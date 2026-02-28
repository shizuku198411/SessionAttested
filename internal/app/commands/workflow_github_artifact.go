package commands

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type workflowTemplateOut struct {
	Path        string `json:"path"`
	ArtifactDir string `json:"artifact_dir"`
}

func RunWorkflowGithubArtifact(args []string) int {
	resolved, err := applyConfigDefaults("workflow_github_artifact", args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	args = resolved

	fs := flag.NewFlagSet("workflow github-artifact", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	outPath := fs.String("out", filepath.Join(".github", "workflows", "publish-attested-artifact.yml"), "workflow output path")
	artifactDir := fs.String("artifact-dir", "attest/attested_artifacts/latest", "artifact directory in repo")
	repo := fs.String("repo", "", "GitHub repo slug (owner/name) for comments in generated file (optional)")
	jsonOut := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	body := renderGithubArtifactWorkflow(*artifactDir, strings.TrimSpace(*repo))
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
		_ = enc.Encode(workflowTemplateOut{Path: *outPath, ArtifactDir: *artifactDir})
		return 0
	}
	fmt.Println("wrote:", *outPath)
	fmt.Println("artifact_dir:", *artifactDir)
	fmt.Println("next: commit the workflow and push")
	return 0
}

func renderGithubArtifactWorkflow(defaultArtifactDir, repo string) string {
	repoComment := ""
	if repo != "" {
		repoComment = "# target repo: " + repo + "\n"
	}
	return strings.TrimSpace(fmt.Sprintf(`
name: Publish SessionAttested Artifacts

on:
  workflow_dispatch:
    inputs:
      artifact_dir:
        description: "Path to prepared SessionAttested artifacts directory"
        required: true
        default: "%s"
  push:
    branches: [ main ]
    paths:
      - "%s/**"
      - ".github/workflows/publish-attested-artifact.yml"

jobs:
  upload-attested-artifact:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Resolve artifact dir
        id: vars
        shell: bash
        run: |
          set -euo pipefail
          %sif [[ "${{ github.event_name }}" == "workflow_dispatch" ]]; then
            DIR="${{ github.event.inputs.artifact_dir }}"
          else
            DIR="%s"
          fi
          echo "dir=$DIR" >> "$GITHUB_OUTPUT"

      - name: Validate required files
        shell: bash
        run: |
          set -euo pipefail
          DIR="${{ steps.vars.outputs.dir }}"

          if [[ ! -d "$DIR" ]]; then
            echo "artifact dir not found: $DIR" >&2
            echo "--- repo files (maxdepth 4) ---"
            find . -maxdepth 4 -type f | sort | sed -n '1,300p'
            exit 1
          fi

          echo "--- artifact files (maxdepth 3) ---"
          find "$DIR" -maxdepth 3 -type f | sort

          req() {
            local p="$1"
            if [[ -f "$p" ]]; then
              echo "OK: $p"
            else
              echo "MISSING: $p" >&2
              exit 1
            fi
          }

          req "$DIR/ATTESTED"
          req "$DIR/ATTESTED_SUMMARY"
          req "$DIR/ATTESTED_POLICY_LAST"
          req "$DIR/attestation/attestation.json"
          req "$DIR/attestation/attestation.sig"
          req "$DIR/attestation/attestation.pub"
          req "$DIR/inputs/policy.yaml"

          if [[ -f "$DIR/inputs/commit_binding.json" ]]; then
            echo "OK: $DIR/inputs/commit_binding.json"
          elif [[ -f "$DIR/inputs/commit_bindings.jsonl" ]]; then
            echo "OK: $DIR/inputs/commit_bindings.jsonl"
          else
            echo "MISSING: commit binding file (commit_binding.json or commit_bindings.jsonl)" >&2
            exit 1
          fi

      - name: Generate manifest (sha256)
        shell: bash
        run: |
          set -euo pipefail
          DIR="${{ steps.vars.outputs.dir }}"
          (
            cd "$DIR"
            find . -type f | sort | while read -r f; do
              sha256sum "$f"
            done
          ) > "$DIR/SHA256SUMS"

      - name: Upload artifact
        uses: actions/upload-artifact@v4
        with:
          name: session-attested-${{ github.run_id }}
          path: |
            ${{ steps.vars.outputs.dir }}/ATTESTED
            ${{ steps.vars.outputs.dir }}/ATTESTED_SUMMARY
            ${{ steps.vars.outputs.dir }}/ATTESTED_POLICY_LAST
            ${{ steps.vars.outputs.dir }}/ATTESTED_WORKSPACE_OBSERVED
            ${{ steps.vars.outputs.dir }}/SHA256SUMS
            ${{ steps.vars.outputs.dir }}/attestation/**
            ${{ steps.vars.outputs.dir }}/inputs/**
            ${{ steps.vars.outputs.dir }}/audit/**
          if-no-files-found: error
          retention-days: 30
`, defaultArtifactDir, defaultArtifactDir, repoComment, defaultArtifactDir)) + "\n"
}
