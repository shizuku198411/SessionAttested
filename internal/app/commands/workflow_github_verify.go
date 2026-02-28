package commands

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type workflowVerifyTemplateOut struct {
	Path        string `json:"path"`
	ArtifactDir string `json:"artifact_dir"`
	UpstreamRef string `json:"sessionattested_ref,omitempty"`
}

func RunWorkflowGithubVerify(args []string) int {
	resolved, err := applyConfigDefaults("workflow_github_verify", args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	args = resolved

	fs := flag.NewFlagSet("workflow github-verify", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	outPath := fs.String("out", filepath.Join(".github", "workflows", "verify-session-attested.yml"), "workflow output path")
	artifactDir := fs.String("artifact-dir", filepath.Join("attest", "attested_artifacts", "latest"), "artifact directory in repo")
	upstreamRepo := fs.String("sessionattested-repo", "https://github.com/shizuku198411/SessionAttested.git", "SessionAttested git repository to clone")
	upstreamRef := fs.String("sessionattested-ref", "", "SessionAttested git ref to checkout (optional)")
	jsonOut := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	body := renderGithubVerifyWorkflow(*artifactDir, strings.TrimSpace(*upstreamRepo), strings.TrimSpace(*upstreamRef))
	if err := os.MkdirAll(filepath.Dir(*outPath), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "error: mkdir workflow dir:", err)
		return 3
	}
	if err := os.WriteFile(*outPath, []byte(body), 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "error: write workflow:", err)
		return 3
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(workflowVerifyTemplateOut{
			Path:        *outPath,
			ArtifactDir: *artifactDir,
			UpstreamRef: strings.TrimSpace(*upstreamRef),
		})
		return 0
	}
	fmt.Println("wrote:", *outPath)
	fmt.Println("artifact_dir:", *artifactDir)
	fmt.Println("next: commit the workflow and push, or run via workflow_dispatch")
	return 0
}

func renderGithubVerifyWorkflow(defaultArtifactDir, upstreamRepo, upstreamRef string) string {
	refSnippet := ""
	if upstreamRef != "" {
		refSnippet = fmt.Sprintf("          git checkout %q\n", upstreamRef)
	}
	return strings.TrimSpace(fmt.Sprintf(`
name: Verify SessionAttested Evidence

on:
  workflow_dispatch:
    inputs:
      artifact_dir:
        description: "Path to prepared SessionAttested artifacts directory"
        required: true
        default: "%s"
      require_pass:
        description: "Fail workflow if attestation conclusion.pass is false"
        required: true
        default: "true"
  push:
    branches: [ main ]
    paths:
      - "%s/**"
      - ".github/workflows/verify-session-attested.yml"

jobs:
  verify-session-attested:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout target repo
        uses: actions/checkout@v4

      - name: Resolve artifact dir
        id: vars
        shell: bash
        run: |
          set -euo pipefail
          if [[ "${{ github.event_name }}" == "workflow_dispatch" ]]; then
            DIR="${{ github.event.inputs.artifact_dir }}"
            REQUIRE_PASS="${{ github.event.inputs.require_pass }}"
          else
            DIR="%s"
            REQUIRE_PASS="true"
          fi
          echo "dir=$DIR" >> "$GITHUB_OUTPUT"
          echo "require_pass=$REQUIRE_PASS" >> "$GITHUB_OUTPUT"

      - name: Validate required files
        shell: bash
        run: |
          set -euo pipefail
          DIR="${{ steps.vars.outputs.dir }}"

          req() {
            local p="$1"
            [[ -f "$p" ]] || { echo "missing: $p" >&2; exit 1; }
          }

          req "$DIR/attestation/attestation.json"
          req "$DIR/attestation/attestation.sig"
          req "$DIR/attestation/attestation.pub"
          req "$DIR/inputs/policy.yaml"
          if [[ ! -f "$DIR/inputs/commit_binding.json" && ! -f "$DIR/inputs/commit_bindings.jsonl" ]]; then
            echo "missing commit binding file (commit_binding.json or commit_bindings.jsonl)" >&2
            exit 1
          fi

      - name: Setup Go
        uses: actions/setup-go@v5
        with:
          go-version: "1.22"

      - name: Install build dependencies (clang/llvm/libbpf)
        shell: bash
        run: |
          set -euo pipefail
          sudo apt-get update
          sudo apt-get install -y clang llvm libbpf-dev

      - name: Clone and build SessionAttested
        shell: bash
        run: |
          set -euo pipefail
          git clone %q sessionattested-upstream
          cd sessionattested-upstream
%s          go generate ./internal/collector/ebpf
          go build -o attested ./cmd/attested

      - name: Verify attestation (public key only)
        id: verify
        shell: bash
        run: |
          set -euo pipefail
          ROOT="$GITHUB_WORKSPACE"
          DIR="$ROOT/${{ steps.vars.outputs.dir }}"
          REQUIRE_PASS="${{ steps.vars.outputs.require_pass }}"
          VERIFY_TMP="$(mktemp -d "${RUNNER_TEMP:-/tmp}/sessionattested-verify-XXXXXX")"
          cd "$VERIFY_TMP"

          BINDING=""
          if [[ -f "$DIR/inputs/commit_binding.json" ]]; then
            BINDING="$DIR/inputs/commit_binding.json"
          elif [[ -f "$DIR/inputs/commit_bindings.jsonl" ]]; then
            # verify CLI currently accepts single binding file path; skip explicit binding for JSONL here.
            BINDING=""
          fi

          ARGS=(
            --attestation "$DIR/attestation/attestation.json"
            --signature "$DIR/attestation/attestation.sig"
            --public-key "$DIR/attestation/attestation.pub"
            --policy "$DIR/inputs/policy.yaml"
            --json
          )
          if [[ -n "$BINDING" ]]; then
            ARGS+=(--binding "$BINDING")
          fi
          if [[ "$REQUIRE_PASS" == "false" ]]; then
            ARGS+=(--require-pass=false)
          fi

          "$ROOT/sessionattested-upstream/attested" verify "${ARGS[@]}" | tee verify_result.json

      - name: Upload verification result
        uses: actions/upload-artifact@v4
        with:
          name: session-attested-verify-${{ github.run_id }}
          path: ${{ runner.temp }}/**/verify_result.json
          if-no-files-found: error
          retention-days: 30

      - name: Job summary
        shell: bash
        run: |
          set -euo pipefail
          RESULT="$(find "${{ runner.temp }}" -name verify_result.json | head -n1)"
          echo "## SessionAttested Verify Result" >> "$GITHUB_STEP_SUMMARY"
          echo "" >> "$GITHUB_STEP_SUMMARY"
          echo '~~~json' >> "$GITHUB_STEP_SUMMARY"
          cat "$RESULT" >> "$GITHUB_STEP_SUMMARY"
          echo '~~~' >> "$GITHUB_STEP_SUMMARY"
`, defaultArtifactDir, defaultArtifactDir, defaultArtifactDir, upstreamRepo, refSnippet)) + "\n"
}
