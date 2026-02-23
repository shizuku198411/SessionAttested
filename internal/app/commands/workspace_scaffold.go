package commands

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

type workspaceScaffoldRequest struct {
	WorkspaceID   string
	WorkspaceHost string
	StateDir      string

	Image         string
	ContainerName string
	Build         bool
	Pull          bool
	BuildContext  string
	Dockerfile    string
	Publish       []string

	MountAttestedBin    bool
	AttestedBinHostPath string
	AttestedBinContPath string

	GitSSHKeyHostPath string
	GitSSHKeyContPath string

	GitUserName  string
	GitUserEmail string
	Repo         string

	Force       bool
	Interactive bool
	PromptInput *bufio.Reader

	UseRelativeWorkspace  bool
	UseRelativeOutputPath bool

	HostUID int
	HostGID int
}

type workspaceScaffoldResult struct {
	CreatedPaths []string
	SkippedPaths []string
}

func generateWorkspaceScaffold(req workspaceScaffoldRequest) (workspaceScaffoldResult, error) {
	var out workspaceScaffoldResult

	if req.WorkspaceHost == "" {
		return out, fmt.Errorf("workspace host is empty")
	}
	attestDir := filepath.Join(req.WorkspaceHost, "attest")
	if err := os.MkdirAll(attestDir, 0o755); err != nil {
		return out, fmt.Errorf("mkdir attest dir: %w", err)
	}

	if req.Interactive {
		promptScaffoldValues(&req)
	}

	gitignorePath := filepath.Join(req.WorkspaceHost, ".gitignore")
	if err := ensureGitignoreBlock(gitignorePath); err != nil {
		return out, err
	}
	out.CreatedPaths = append(out.CreatedPaths, ".gitignore (managed block)")

	cfgPath := filepath.Join(req.WorkspaceHost, "attest", "attested.yaml")
	cfgBody := renderWorkspaceAttestedYAML(req)
	created, err := writeIfMissingOrForced(cfgPath, []byte(cfgBody), req.Force)
	if err != nil {
		return out, fmt.Errorf("write attest/attested.yaml: %w", err)
	}
	if created {
		out.CreatedPaths = append(out.CreatedPaths, "attest/attested.yaml")
	} else {
		out.SkippedPaths = append(out.SkippedPaths, "attest/attested.yaml")
	}

	dfPath := filepath.Join(req.WorkspaceHost, "attest", "Dockerfile")
	created, err = writeIfMissingOrForced(dfPath, []byte(defaultWorkspaceDockerfile), req.Force)
	if err != nil {
		return out, fmt.Errorf("write attest/Dockerfile: %w", err)
	}
	if created {
		out.CreatedPaths = append(out.CreatedPaths, "attest/Dockerfile")
	} else {
		out.SkippedPaths = append(out.SkippedPaths, "attest/Dockerfile")
	}

	policyPath := filepath.Join(req.WorkspaceHost, "attest", "policy.yaml")
	policyBody := renderWorkspacePolicyYAML(req.WorkspaceID)
	created, err = writeIfMissingOrForced(policyPath, []byte(policyBody), req.Force)
	if err != nil {
		return out, fmt.Errorf("write attest/policy.yaml: %w", err)
	}
	if created {
		out.CreatedPaths = append(out.CreatedPaths, "attest/policy.yaml")
	} else {
		out.SkippedPaths = append(out.SkippedPaths, "attest/policy.yaml")
	}

	// If workspace init is executed via sudo, make scaffold files owned by the invoking user
	// so day-to-day editing in the workspace does not require root.
	_ = chownToSudoUserIfPresent(attestDir)
	_ = chownToSudoUserIfPresent(gitignorePath)
	_ = chownToSudoUserIfPresent(cfgPath)
	_ = chownToSudoUserIfPresent(dfPath)
	_ = chownToSudoUserIfPresent(policyPath)

	return out, nil
}

func promptScaffoldValues(req *workspaceScaffoldRequest) {
	if req.PromptInput == nil {
		return
	}
	if strings.TrimSpace(req.GitSSHKeyHostPath) == "" {
		ans := strings.ToLower(strings.TrimSpace(promptLine(req.PromptInput, "mount host git ssh key into container? [y/N]: ")))
		if ans == "y" || ans == "yes" {
			def := detectDefaultSSHKeyPath()
			msg := "host ssh private key path"
			if def != "" {
				msg += " [" + def + "]"
			}
			msg += ": "
			v := promptLine(req.PromptInput, msg)
			if strings.TrimSpace(v) == "" {
				v = def
			}
			req.GitSSHKeyHostPath = strings.TrimSpace(v)
			if strings.TrimSpace(req.GitSSHKeyContPath) == "" {
				req.GitSSHKeyContPath = "/home/dev/.ssh/id_github_attested"
			}
		}
	}
	if req.Repo == "" {
		req.Repo = promptLine(req.PromptInput, "GitHub repo (owner/name) [optional]: ")
	}
	if req.GitUserName == "" {
		req.GitUserName = promptLine(req.PromptInput, "git user.name [optional]: ")
	}
	if req.GitUserEmail == "" {
		req.GitUserEmail = promptLine(req.PromptInput, "git user.email [optional]: ")
	}
}

func promptLine(r *bufio.Reader, msg string) string {
	fmt.Fprint(os.Stdout, msg)
	s, err := r.ReadString('\n')
	if err != nil && strings.TrimSpace(s) == "" {
		return ""
	}
	return strings.TrimSpace(s)
}

func ensureGitignoreBlock(path string) error {
	const start = "# session-attested:begin"
	const end = "# session-attested:end"
	block := strings.Join([]string{
		start,
		".attest_run/state/sessions/*/audit_exec.jsonl",
		".attest_run/state/sessions/*/audit_workspace_write.jsonl",
		".attest_run/state/sessions/*/collector.log",
		".attest_run/keys/attestation_priv.pem",
		".attest_run/state/workspaces/",
		end,
		"",
	}, "\n")

	b, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read .gitignore: %w", err)
	}
	if bytes.Contains(b, []byte(start)) && bytes.Contains(b, []byte(end)) {
		return nil
	}
	if len(b) > 0 && b[len(b)-1] != '\n' {
		b = append(b, '\n')
	}
	b = append(b, []byte(block)...)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		return fmt.Errorf("write .gitignore: %w", err)
	}
	return nil
}

func writeIfMissingOrForced(path string, body []byte, force bool) (bool, error) {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return false, nil
		} else if !os.IsNotExist(err) {
			return false, err
		}
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		return false, err
	}
	return true, nil
}

func writeExecutableIfMissingOrForced(path string, body []byte, force bool) (bool, error) {
	created, err := writeIfMissingOrForced(path, body, force)
	if err != nil {
		return false, err
	}
	if created {
		if err := os.Chmod(path, 0o755); err != nil {
			return false, err
		}
	}
	return created, nil
}

func chownToSudoUserIfPresent(path string) error {
	uidStr := strings.TrimSpace(os.Getenv("SUDO_UID"))
	gidStr := strings.TrimSpace(os.Getenv("SUDO_GID"))
	if uidStr == "" || gidStr == "" {
		return nil
	}
	uid, err := strconv.Atoi(uidStr)
	if err != nil {
		return nil
	}
	gid, err := strconv.Atoi(gidStr)
	if err != nil {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	return os.Chown(path, uid, gid)
}

func renderWorkspaceAttestedYAML(req workspaceScaffoldRequest) string {
	workspaceHost := "."
	repoPath := "."
	stateDir := ".attest_run/state"
	policyPath := "attest/policy.yaml"
	attestOut := ".attest_run/attestations/latest"
	signingKey := ".attest_run/keys/attestation_priv.pem"
	buildContext := "."
	dockerfile := "attest/Dockerfile"
	if !req.UseRelativeWorkspace {
		workspaceHost = req.WorkspaceHost
		repoPath = req.WorkspaceHost
		stateDir = filepath.Join(req.WorkspaceHost, ".attest_run", "state")
		policyPath = filepath.Join(req.WorkspaceHost, "attest", "policy.yaml")
		attestOut = filepath.Join(req.WorkspaceHost, ".attest_run", "attestations", "latest")
		signingKey = filepath.Join(req.WorkspaceHost, ".attest_run", "keys", "attestation_priv.pem")
	}
	if !req.UseRelativeOutputPath {
		stateDir = req.StateDir
	}
	if strings.TrimSpace(req.BuildContext) != "" {
		buildContext = req.BuildContext
	}
	if strings.TrimSpace(req.Dockerfile) != "" && req.Dockerfile != "Dockerfile" {
		// workspace scaffold stores Dockerfile under attest/ by default
		dockerfile = req.Dockerfile
	}
	if req.Dockerfile == "Dockerfile" {
		dockerfile = "attest/Dockerfile"
	}

	image := strings.TrimSpace(req.Image)
	if image == "" {
		image = "attested-" + sanitizeName(req.WorkspaceID) + ":latest"
	}
	name := strings.TrimSpace(req.ContainerName)
	if name == "" {
		name = sanitizeName(req.WorkspaceID)
	}
	repo := strings.TrimSpace(req.Repo)
	if repo == "" {
		repo = "your-org/your-repo"
	}
	gitUserName := strings.TrimSpace(req.GitUserName)
	if gitUserName == "" {
		gitUserName = "Your Name"
	}
	gitUserEmail := strings.TrimSpace(req.GitUserEmail)
	if gitUserEmail == "" {
		gitUserEmail = "you@example.com"
	}
	uid := req.HostUID
	gid := req.HostGID
	if uid <= 0 || gid <= 0 {
		uid, gid = currentShellUIDGID()
	}
	if uid <= 0 {
		uid = 1000
	}
	if gid <= 0 {
		gid = 1000
	}

	var b strings.Builder
	b.WriteString("defaults:\n")
	fmt.Fprintf(&b, "  state_dir: %s\n\n", yamlStr(stateDir))
	b.WriteString("commands:\n")
	fmt.Fprintf(&b, "  workspace_init:\n    workspace_id: %s\n\n", yamlStr(req.WorkspaceID))
	fmt.Fprintf(&b, "  workspace_rm:\n    workspace_id: %s\n\n", yamlStr(req.WorkspaceID))
	b.WriteString("  start:\n")
	fmt.Fprintf(&b, "    name: %s\n", yamlStr(name))
	fmt.Fprintf(&b, "    image: %s\n", yamlStr(image))
	fmt.Fprintf(&b, "    pull: %v\n", req.Pull)
	fmt.Fprintf(&b, "    build: %v\n", req.Build)
	b.WriteString("    reuse_container: true\n")
	fmt.Fprintf(&b, "    build_context: %s\n", yamlStr(buildContext))
	fmt.Fprintf(&b, "    dockerfile: %s\n", yamlStr(dockerfile))
	b.WriteString("    auto_collect: true\n")
	b.WriteString("    auto_collect_sudo: true\n")
	b.WriteString("    auto_collect_wait: 10s\n")
	b.WriteString("    inject_session_env: true\n")
	b.WriteString("    mount_attested_bin: true\n")
	b.WriteString("    attested_bin_container_path: /usr/local/bin/attested\n")
	fmt.Fprintf(&b, "    git_user_name: %s\n", yamlStr(gitUserName))
	fmt.Fprintf(&b, "    git_user_email: %s\n", yamlStr(gitUserEmail))
	if strings.TrimSpace(req.GitSSHKeyHostPath) != "" {
		fmt.Fprintf(&b, "    git_ssh_key_host_path: %s\n", yamlStr(req.GitSSHKeyHostPath))
		fmt.Fprintf(&b, "    git_ssh_key_container_path: %s\n", yamlStr(nonEmpty(req.GitSSHKeyContPath, "/home/dev/.ssh/id_github_attested")))
	} else {
		b.WriteString("    # git_ssh_key_host_path: /absolute/path/to/id_ed25519\n")
		b.WriteString("    # git_ssh_key_container_path: /home/dev/.ssh/id_github_attested\n")
	}
	b.WriteString("    build_arg:\n")
	fmt.Fprintf(&b, "      - %s\n", yamlStr(fmt.Sprintf("DEV_UID=%d", uid)))
	fmt.Fprintf(&b, "      - %s\n", yamlStr(fmt.Sprintf("DEV_GID=%d", gid)))
	if len(req.Publish) > 0 {
		b.WriteString("    publish:\n")
		for _, p := range req.Publish {
			fmt.Fprintf(&b, "      - %s\n", yamlStr(p))
		}
	} else {
		b.WriteString("    publish:\n")
		b.WriteString("      - \"0.0.0.0:2222:22/tcp\"\n")
	}
	fmt.Fprintf(&b, "    workspace_host: %s\n\n", yamlStr(workspaceHost))

	b.WriteString("  collect:\n")
	b.WriteString("    until_stop: true\n")
	b.WriteString("    poll: 300ms\n\n")

	b.WriteString("  stop:\n")
	b.WriteString("    keep_container: true\n")
	b.WriteString("    collector_wait: 20s\n")
	b.WriteString("    # run_attest: true\n")
	b.WriteString("    # run_verify: true\n")
	b.WriteString("    # verify_write_result: true\n\n")

	b.WriteString("  commit:\n")
	fmt.Fprintf(&b, "    repo_path: %s\n", yamlStr(repoPath))
	b.WriteString("    message: \"attested session commit\"\n\n")

	b.WriteString("  attest:\n")
	fmt.Fprintf(&b, "    repo: %s\n", yamlStr(repo))
	fmt.Fprintf(&b, "    policy: %s\n", yamlStr(policyPath))
	fmt.Fprintf(&b, "    out: %s\n", yamlStr(attestOut))
	fmt.Fprintf(&b, "    signing_key: %s\n", yamlStr(signingKey))
	fmt.Fprintf(&b, "    key_id: %s\n", yamlStr(req.WorkspaceID+"-key-1"))
	fmt.Fprintf(&b, "    issuer_name: %s\n", yamlStr(req.WorkspaceID+"-attestor"))
	b.WriteString("    use_binding: true\n\n")

	b.WriteString("  verify:\n")
	fmt.Fprintf(&b, "    policy: %s\n", yamlStr(policyPath))
	b.WriteString("    require_pass: true\n")
	b.WriteString("    write_result: true\n")

	return b.String()
}

func renderWorkspacePolicyYAML(workspaceID string) string {
	if strings.TrimSpace(workspaceID) == "" {
		workspaceID = "workspace"
	}
	return fmt.Sprintf(`policy_id: %q
policy_version: "1.0.0"

forbidden_exec: []

forbidden_writers: []

exceptions: []
`, workspaceID+"-policy")
}

func yamlStr(s string) string {
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}

func nonEmpty(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}

func sanitizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return "workspace"
	}
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9')
		if ok {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "workspace"
	}
	return out
}

func detectDefaultSSHKeyPath() string {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return ""
	}
	candidates := []string{
		filepath.Join(home, ".ssh", "id_ed25519"),
		filepath.Join(home, ".ssh", "id_rsa"),
	}
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return candidates[0]
}

func currentShellUIDGID() (int, int) {
	uid := parseEnvInt("SUDO_UID")
	gid := parseEnvInt("SUDO_GID")
	if uid > 0 && gid > 0 {
		return uid, gid
	}
	return os.Getuid(), os.Getgid()
}

func parseEnvInt(key string) int {
	s := strings.TrimSpace(os.Getenv(key))
	if s == "" {
		return 0
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return 0
	}
	return v
}

func upsertBuildArg(args []string, key, value string) []string {
	prefix := key + "="
	replaced := false
	out := make([]string, 0, len(args)+1)
	for _, a := range args {
		if strings.HasPrefix(a, prefix) {
			out = append(out, prefix+value)
			replaced = true
		} else {
			out = append(out, a)
		}
	}
	if !replaced {
		out = append(out, prefix+value)
	}
	return out
}

const defaultWorkspaceDockerfile = `FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
ARG DEV_UID=1000
ARG DEV_GID=1000

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       openssh-server \
       sudo \
       ca-certificates \
       vim \
       less \
       git \
    && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /var/run/sshd

RUN set -eux; \
    uid_user="$(getent passwd "${DEV_UID}" | cut -d: -f1 || true)"; \
    if ! getent group "${DEV_GID}" >/dev/null; then \
      groupadd -g "${DEV_GID}" dev; \
    fi; \
    if id -u dev >/dev/null 2>&1; then \
      usermod -u "${DEV_UID}" -g "${DEV_GID}" -s /bin/bash dev; \
    elif [ -n "${uid_user}" ]; then \
      if [ "${uid_user}" != "dev" ]; then \
        usermod -l dev -d /home/dev -m "${uid_user}"; \
      fi; \
      usermod -g "${DEV_GID}" -s /bin/bash dev; \
    else \
      useradd -m -u "${DEV_UID}" -g "${DEV_GID}" -s /bin/bash dev; \
    fi; \
    echo 'dev:devpass' | chpasswd; \
    usermod -aG sudo dev

RUN sed -i 's/^#\?PasswordAuthentication .*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PermitRootLogin .*/PermitRootLogin no/' /etc/ssh/sshd_config \
    && printf '\nUsePAM yes\nPubkeyAuthentication yes\n' >> /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
`

func renderScriptStart() string {
	return `#!/usr/bin/env bash
set -euo pipefail

CONFIG="${CONFIG:-./attest/attested.yaml}"
LAST_SESSION_FILE="${LAST_SESSION_FILE:-.attest_run/last_session_id}"
LAST_START_JSON_FILE="${LAST_START_JSON_FILE:-.attest_run/last_start.json}"
ATTESTED_USE_SUDO="${ATTESTED_USE_SUDO:-auto}"

ATT_CMD=(attested)
USED_SUDO=0
if [[ "$ATTESTED_USE_SUDO" != "never" && "${EUID:-$(id -u)}" -ne 0 ]]; then
  ATT_CMD=(sudo -E attested)
  USED_SUDO=1
fi

START_JSON="$("${ATT_CMD[@]}" start --config "$CONFIG" --json "$@")"
mkdir -p "$(dirname "$LAST_SESSION_FILE")"
printf '%s\n' "$START_JSON" > "$LAST_START_JSON_FILE"

SESSION_ID="$(printf '%s' "$START_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin)["session_id"])')"
CONTAINER_ID="$(printf '%s' "$START_JSON" | python3 -c 'import sys,json; print(json.load(sys.stdin)["container_id"])')"
printf '%s\n' "$SESSION_ID" > "$LAST_SESSION_FILE"

if [[ "$USED_SUDO" -eq 1 && -d .attest_run ]]; then
  sudo chown -R "$(id -u):$(id -g)" .attest_run 2>/dev/null || true
fi

echo "session_id: $SESSION_ID"
echo "container_id: $CONTAINER_ID"
echo "saved: $LAST_SESSION_FILE"
`
}

func renderScriptStop() string {
	return `#!/usr/bin/env bash
set -euo pipefail

CONFIG="${CONFIG:-./attest/attested.yaml}"
LAST_SESSION_FILE="${LAST_SESSION_FILE:-.attest_run/last_session_id}"
ATTESTED_USE_SUDO="${ATTESTED_USE_SUDO:-auto}"
SESSION_ID="${1:-}"
if [[ -z "$SESSION_ID" ]]; then
  SESSION_ID="$(tr -d '\r\n' < "$LAST_SESSION_FILE")"
else
  shift
fi

ATT_CMD=(attested)
USED_SUDO=0
if [[ "$ATTESTED_USE_SUDO" != "never" && "${EUID:-$(id -u)}" -ne 0 ]]; then
  ATT_CMD=(sudo -E attested)
  USED_SUDO=1
fi

"${ATT_CMD[@]}" stop --config "$CONFIG" --session "$SESSION_ID" "$@"
if [[ "$USED_SUDO" -eq 1 && -d .attest_run ]]; then
  sudo chown -R "$(id -u):$(id -g)" .attest_run 2>/dev/null || true
fi
echo "session: $SESSION_ID"
echo "summary: .attest_run/state/sessions/$SESSION_ID/audit_summary.json"
`
}

func renderScriptAttest() string {
	return `#!/usr/bin/env bash
set -euo pipefail

CONFIG="${CONFIG:-./attest/attested.yaml}"
LAST_SESSION_FILE="${LAST_SESSION_FILE:-.attest_run/last_session_id}"
SESSION_ID="${1:-}"
if [[ -z "$SESSION_ID" ]]; then
  SESSION_ID="$(tr -d '\r\n' < "$LAST_SESSION_FILE")"
else
  shift
fi

attested attest --config "$CONFIG" --session "$SESSION_ID" "$@"
`
}

func renderScriptVerify() string {
	return `#!/usr/bin/env bash
set -euo pipefail

CONFIG="${CONFIG:-./attest/attested.yaml}"
LAST_SESSION_FILE="${LAST_SESSION_FILE:-.attest_run/last_session_id}"
SESSION_ID="${1:-}"
if [[ -z "$SESSION_ID" ]]; then
  SESSION_ID="$(tr -d '\r\n' < "$LAST_SESSION_FILE")"
else
  shift
fi

BINDING=".attest_run/state/sessions/$SESSION_ID/commit_binding.json"
BINDING_ARGS=()
if [[ -f "$BINDING" ]]; then
  BINDING_ARGS=(--binding "$BINDING")
fi

attested verify \
  --config "$CONFIG" \
  --attestation .attest_run/attestations/latest/attestation.json \
  --signature .attest_run/attestations/latest/attestation.sig \
  --public-key .attest_run/attestations/latest/attestation.pub \
  "${BINDING_ARGS[@]}" \
  "$@"
`
}

func renderScriptExportArtifact() string {
	return `#!/usr/bin/env bash
set -euo pipefail

LAST_SESSION_FILE="${LAST_SESSION_FILE:-.attest_run/last_session_id}"
SESSION_ID="${1:-}"
OUT_DIR="${OUT_DIR:-attested_artifacts/latest}"
if [[ -z "$SESSION_ID" ]]; then
  SESSION_ID="$(tr -d '\r\n' < "$LAST_SESSION_FILE")"
fi

SESSION_DIR=".attest_run/state/sessions/$SESSION_ID"
ATTEST_DIR=".attest_run/attestations/latest"

mkdir -p "$OUT_DIR"/attestation "$OUT_DIR"/inputs "$OUT_DIR"/audit
cp ATTESTED "$OUT_DIR/ATTESTED"
cp ATTESTED_SUMMARY "$OUT_DIR/ATTESTED_SUMMARY"
cp ATTESTED_POLICY_LAST "$OUT_DIR/ATTESTED_POLICY_LAST"
cp "$ATTEST_DIR/attestation.json" "$OUT_DIR/attestation/attestation.json"
cp "$ATTEST_DIR/attestation.sig"  "$OUT_DIR/attestation/attestation.sig"
cp "$ATTEST_DIR/attestation.pub"  "$OUT_DIR/attestation/attestation.pub"
cp .attest_run/policy.yaml "$OUT_DIR/inputs/policy.yaml"
if [[ -f "$SESSION_DIR/commit_bindings.jsonl" ]]; then
  cp "$SESSION_DIR/commit_bindings.jsonl" "$OUT_DIR/inputs/commit_bindings.jsonl"
else
  cp "$SESSION_DIR/commit_binding.json" "$OUT_DIR/inputs/commit_binding.json"
fi
cp "$SESSION_DIR/audit_summary.json" "$OUT_DIR/audit/audit_summary.json"
cp "$SESSION_DIR/event_root.json"    "$OUT_DIR/audit/event_root.json"
cp "$SESSION_DIR/meta.json"          "$OUT_DIR/audit/meta.json"
find "$OUT_DIR" -maxdepth 3 -type f | sort
`
}

func renderScriptWorkspaceInit() string {
	return `#!/usr/bin/env bash
set -euo pipefail

CONFIG="${CONFIG:-./attest/attested.yaml}"
ATTESTED_USE_SUDO="${ATTESTED_USE_SUDO:-auto}"

# workspace init may require sudo depending on state_dir / Docker access
if [[ "$ATTESTED_USE_SUDO" != "never" && "${EUID:-$(id -u)}" -ne 0 ]]; then
  sudo -E attested workspace init --config "$CONFIG" --workspace-host "${PWD}" "$@"
  if [[ -d .attest_run ]]; then
    sudo chown -R "$(id -u):$(id -g)" .attest_run 2>/dev/null || true
  fi
  if [[ -d attest ]]; then
    sudo chown -R "$(id -u):$(id -g)" attest 2>/dev/null || true
  fi
  if [[ -d scripts/attested ]]; then
    sudo chown -R "$(id -u):$(id -g)" scripts/attested 2>/dev/null || true
  fi
  if [[ -f .gitignore ]]; then
    sudo chown "$(id -u):$(id -g)" .gitignore 2>/dev/null || true
  fi
else
  attested workspace init --config "$CONFIG" --workspace-host "${PWD}" "$@"
fi
`
}

func renderScriptWorkspaceRm() string {
	return `#!/usr/bin/env bash
set -euo pipefail

CONFIG="${CONFIG:-./attest/attested.yaml}"
ATTESTED_USE_SUDO="${ATTESTED_USE_SUDO:-auto}"

# workspace rm may require sudo depending on state_dir / Docker access
if [[ "$ATTESTED_USE_SUDO" != "never" && "${EUID:-$(id -u)}" -ne 0 ]]; then
  exec sudo -E attested workspace rm --config "$CONFIG" "$@"
else
  exec attested workspace rm --config "$CONFIG" "$@"
fi
`
}
