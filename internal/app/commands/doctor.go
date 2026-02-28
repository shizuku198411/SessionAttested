package commands

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	dockerapitypes "github.com/docker/docker/api/types"
	dockerapicontainer "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
	"session-attested/internal/crypto"
	"session-attested/internal/docker"
	"session-attested/internal/state"
)

type doctorCheck struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Detail  string `json:"detail,omitempty"`
	Warning bool   `json:"warning,omitempty"`
}

type doctorOut struct {
	ConfigPath string       `json:"config_path,omitempty"`
	RunDir     string       `json:"run_dir"`
	StateDir   string       `json:"state_dir"`
	SessionID  string       `json:"session_id,omitempty"`
	Checks     []doctorCheck`json:"checks"`
}

func RunDoctor(args []string) int {
	resolved, err := applyConfigDefaults("doctor", args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	configPath, profile, _ := extractConfigArgs(args)
	if strings.TrimSpace(configPath) == "" {
		configPath = defaultConfigPath()
	}
	args = resolved

	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	sessionID := fs.String("session", "", "session id (default: .attest_run/last_session_id)")
	runDir := fs.String("run-dir", ".attest_run", "run dir")
	stateDir := fs.String("state-dir", filepath.Join(".attest_run", "state"), "state dir")
	jsonOut := fs.Bool("json", false, "output JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if strings.TrimSpace(*sessionID) == "" {
		if sid, ok := readLastSessionID(); ok {
			*sessionID = sid
		}
	}

	out := doctorOut{
		ConfigPath: configPath,
		RunDir:     *runDir,
		StateDir:   *stateDir,
		SessionID:  strings.TrimSpace(*sessionID),
	}

	add := func(name string, ok bool, detail string, warning bool) {
		out.Checks = append(out.Checks, doctorCheck{Name: name, OK: ok, Detail: detail, Warning: warning})
	}

	// Paths/config
	if configPath == "" {
		add("config", false, "no config found (attest/attested.yaml)", true)
	} else {
		add("config", true, configPath, false)
	}
	attestCfgVals, _ := mergedConfigValues(configPath, profile, "attest")
	startCfgVals, _ := mergedConfigValues(configPath, profile, "start")
	if fi, err := os.Stat(*runDir); err == nil && fi.IsDir() {
		add("run_dir", true, *runDir, false)
	} else {
		add("run_dir", false, *runDir+" not found", true)
	}
	if fi, err := os.Stat(*stateDir); err == nil && fi.IsDir() {
		add("state_dir", true, *stateDir, false)
	} else {
		add("state_dir", false, *stateDir+" not found", true)
	}
	if sid := strings.TrimSpace(*sessionID); sid != "" {
		add("last_session_id", true, sid, false)
	} else {
		add("last_session_id", false, ".attest_run/last_session_id not found", true)
	}

	// Docker diagnostics
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var dockerCLI *client.Client
	cli, err := docker.NewClient()
	if err != nil {
		add("docker_client", false, err.Error(), false)
	} else if err := docker.Ping(ctx, cli); err != nil {
		add("docker_ping", false, err.Error(), false)
	} else {
		dockerCLI = cli
		add("docker_ping", true, "ok", false)
	}

	// sudo -n (non-fatal)
	if os.Geteuid() == 0 {
		add("sudo_noninteractive", true, "running as root", false)
	} else if _, err := exec.LookPath("sudo"); err != nil {
		add("sudo_noninteractive", false, "sudo not found", true)
	} else {
		cmd := exec.Command("sudo", "-n", "true")
		if err := cmd.Run(); err != nil {
			add("sudo_noninteractive", false, "sudo -n unavailable (run `sudo -v` or use sudo)", true)
		} else {
			add("sudo_noninteractive", true, "sudo -n available", false)
		}
	}

	// Kernel LSM hint (best effort)
	if b, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		lsm := strings.TrimSpace(string(b))
		add("kernel_lsm_list", true, lsm, false)
	} else {
		add("kernel_lsm_list", false, err.Error(), true)
	}

	// Selected session files / attestation
	if sid := strings.TrimSpace(*sessionID); sid != "" {
		st := state.StateDir{Root: *stateDir}
		checkPath := func(name, p string, required bool) {
			if _, err := os.Stat(p); err == nil {
				add(name, true, p, false)
			} else {
				add(name, false, p+" missing", !required)
			}
		}
		checkPath("session_meta", st.MetaPath(sid), true)
		checkPath("audit_summary", st.AuditSummaryPath(sid), true)
		checkPath("event_root", st.EventRootPath(sid), true)

		attPath, att, err := resolveAttestationForSession(*runDir, sid)
		if err != nil {
			add("session_attestation", false, err.Error(), true)
		} else {
			add("session_attestation", true, attPath, false)
			// Compare attestation session_id consistency
			if att.Session.SessionID == sid {
				add("attestation_session_match", true, sid, false)
			} else {
				add("attestation_session_match", false, fmt.Sprintf("attestation has %q, expected %q", att.Session.SessionID, sid), false)
			}
			ilr := verifyLocalAuditLogIntegrityIfAvailable(&att)
			if ilr.Checked {
				add("raw_audit_log_integrity", ilr.OK, ilr.Reason, false)
			} else {
				add("raw_audit_log_integrity", false, "not checked (local state unavailable)", true)
			}
			if att.Issuer != nil && strings.TrimSpace(att.Issuer.KeyFingerprint) != "" {
				add("attestation_signing_key_fingerprint", true, att.Issuer.KeyFingerprint, false)
			} else {
				add("attestation_signing_key_fingerprint", false, "missing in attestation issuer", true)
			}
		}
		// latest attestation exists?
		latest := filepath.Join(*runDir, "attestations", "latest", "attestation.json")
		if _, err := os.Stat(latest); err == nil {
			add("latest_attestation", true, latest, false)
		} else {
			add("latest_attestation", false, latest+" missing", true)
		}
		latestPub := filepath.Join(*runDir, "attestations", "latest", "attestation.pub")
		if fp, err := doctorPublicKeyFingerprint(latestPub); err == nil {
			add("latest_attestation_pub_fingerprint", true, fp, false)
		} else {
			add("latest_attestation_pub_fingerprint", false, err.Error(), true)
		}
		// summary parse sanity
		summaryPath := filepath.Join(".", "ATTESTED_SUMMARY")
		if b, err := os.ReadFile(summaryPath); err == nil && len(strings.TrimSpace(string(b))) > 0 {
			var arr []map[string]any
			if err := json.Unmarshal(b, &arr); err != nil {
				add("attested_summary_parse", false, err.Error(), true)
			} else {
				add("attested_summary_parse", true, fmt.Sprintf("%d records", len(arr)), false)
			}
		} else {
			add("attested_summary_parse", false, "ATTESTED_SUMMARY missing", true)
		}
	}

	// Signing key fingerprint from config (attest.signing_key)
	if attestCfgVals != nil {
		if signingKey, ok := anyString(attestCfgVals["signing_key"]); ok && signingKey != "" {
			if fp, err := doctorPrivateKeyFingerprint(signingKey); err == nil {
				add("config_signing_key_fingerprint", true, fp, false)
			} else {
				add("config_signing_key_fingerprint", false, err.Error(), true)
			}
		} else {
			add("config_signing_key_fingerprint", false, "attest.signing_key not configured", true)
		}
	}

	// Optional start/verify key expectation visibility
	if startCfgVals != nil {
		if keyHost, ok := anyString(startCfgVals["git_ssh_key_host_path"]); ok && keyHost != "" {
			if fp, err := doctorPrivateKeyFingerprint(keyHost); err == nil {
				add("git_ssh_key_host_fingerprint", true, fp, true)
			}
		}
	}

	// Workspace config-vs-container diff detection (recreate hint)
	if dockerCLI != nil {
		if startVals, err := mergedConfigValues(configPath, profile, "start"); err == nil && startVals != nil {
			wsVals, _ := mergedConfigValues(configPath, profile, "workspace_init")
			merged := map[string]any{}
			for k, v := range startVals {
				merged[k] = v
			}
			for k, v := range wsVals {
				merged[k] = v
			}
			res := doctorWorkspaceContainerDiff(context.Background(), dockerCLI, *stateDir, merged)
			add("workspace_container_diff", res.OK, res.Detail, res.Warning)
		}
	}

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		enc.SetIndent("", "  ")
		_ = enc.Encode(out)
		return 0
	}

	fmt.Println("SessionAttested doctor")
	if out.ConfigPath != "" {
		fmt.Println("config:", out.ConfigPath)
	}
	fmt.Println("run_dir:", out.RunDir)
	fmt.Println("state_dir:", out.StateDir)
	if out.SessionID != "" {
		fmt.Println("session:", out.SessionID)
	}
	for _, c := range out.Checks {
		status := "OK"
		if !c.OK {
			if c.Warning {
				status = "WARN"
			} else {
				status = "FAIL"
			}
		}
		if c.Detail != "" {
			fmt.Printf("- [%s] %s: %s\n", status, c.Name, c.Detail)
		} else {
			fmt.Printf("- [%s] %s\n", status, c.Name)
		}
	}
	return 0
}

type workspaceDiffCheck struct {
	OK      bool
	Detail  string
	Warning bool
}

func doctorWorkspaceContainerDiff(ctx context.Context, cli *client.Client, stateDir string, cfg map[string]any) workspaceDiffCheck {
	workspaceID, _ := anyString(cfg["workspace_id"])
	if workspaceID == "" {
		return workspaceDiffCheck{OK: false, Detail: "workspace_id not configured (skip diff)", Warning: true}
	}
	st := state.StateDir{Root: stateDir}
	var wm state.WorkspaceMeta
	if err := state.ReadJSON(st.WorkspaceMetaPath(workspaceID), &wm); err != nil {
		return workspaceDiffCheck{OK: false, Detail: "workspace meta not found (skip diff)", Warning: true}
	}
	if strings.TrimSpace(wm.Docker.ContainerID) == "" {
		return workspaceDiffCheck{OK: false, Detail: "workspace meta has no container id", Warning: true}
	}
	ins, err := cli.ContainerInspect(ctx, wm.Docker.ContainerID)
	if err != nil {
		return workspaceDiffCheck{OK: false, Detail: "cannot inspect workspace container: " + err.Error(), Warning: true}
	}

	var mismatches []string
	if want, ok := anyString(cfg["image"]); ok && want != "" && ins.Config != nil {
		if got := strings.TrimSpace(ins.Config.Image); got != "" && got != want {
			mismatches = append(mismatches, fmt.Sprintf("image config=%q container=%q", want, got))
		}
	}
	if want, ok := anyString(cfg["name"]); ok && want != "" {
		if got := strings.TrimPrefix(ins.Name, "/"); got != "" && got != want {
			mismatches = append(mismatches, fmt.Sprintf("name config=%q container=%q", want, got))
		}
	}
	if wantWS, ok := anyString(cfg["workspace_host"]); ok && wantWS != "" {
		if abs, err := filepath.Abs(wantWS); err == nil {
			wantWS = abs
		}
		if gotWS, ok := findWorkspaceMountSource(ins.Mounts); ok && gotWS != wantWS {
			mismatches = append(mismatches, fmt.Sprintf("workspace mount config=%q container=%q", wantWS, gotWS))
		}
	}
	wantPublish := anyStringSlice(cfg["publish"])
	if len(wantPublish) > 0 {
		wantNorm, err := normalizePublishSpecs(wantPublish)
		if err != nil {
			mismatches = append(mismatches, "publish parse error: "+err.Error())
		} else {
			gotNorm := normalizePortBindings(ins.HostConfig)
			if !equalStrings(wantNorm, gotNorm) {
				mismatches = append(mismatches, fmt.Sprintf("publish config=%v container=%v", wantNorm, gotNorm))
			}
		}
	}

	if len(mismatches) == 0 {
		return workspaceDiffCheck{OK: true, Detail: "no config/container diffs detected"}
	}
	return workspaceDiffCheck{OK: false, Detail: "recreate required likely: " + strings.Join(mismatches, "; "), Warning: true}
}

func anyString(v any) (string, bool) {
	s, ok := v.(string)
	if !ok {
		return "", false
	}
	return strings.TrimSpace(s), true
}

func anyStringSlice(v any) []string {
	switch t := v.(type) {
	case []string:
		out := make([]string, 0, len(t))
		for _, s := range t {
			if s = strings.TrimSpace(s); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			if s, ok := x.(string); ok {
				s = strings.TrimSpace(s)
				if s != "" {
					out = append(out, s)
				}
			}
		}
		return out
	default:
		return nil
	}
}

func normalizePublishSpecs(specs []string) ([]string, error) {
	if len(specs) == 0 {
		return nil, nil
	}
	_, pm, err := nat.ParsePortSpecs(specs)
	if err != nil {
		return nil, err
	}
	return normalizePortMap(pm), nil
}

func normalizePortBindings(h *dockerapicontainer.HostConfig) []string {
	if h == nil {
		return nil
	}
	return normalizePortMap(h.PortBindings)
}

func normalizePortMap(pm nat.PortMap) []string {
	var out []string
	for port, bindings := range pm {
		for _, b := range bindings {
			ip := b.HostIP
			if strings.TrimSpace(ip) == "" {
				ip = "0.0.0.0"
			}
			out = append(out, fmt.Sprintf("%s:%s:%s", ip, b.HostPort, string(port)))
		}
	}
	sort.Strings(out)
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func findWorkspaceMountSource(mounts []dockerapitypes.MountPoint) (string, bool) {
	for _, m := range mounts {
		if m.Destination == "/workspace" && m.Source != "" {
			return m.Source, true
		}
	}
	return "", false
}

func doctorPrivateKeyFingerprint(path string) (string, error) {
	priv, err := crypto.LoadEd25519PrivateKey(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	fp, err := crypto.Ed25519PublicKeyFingerprint(crypto.PublicFromPrivate(priv))
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return fp, nil
}

func doctorPublicKeyFingerprint(path string) (string, error) {
	pub, err := crypto.LoadEd25519PublicKey(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	fp, err := crypto.Ed25519PublicKeyFingerprint(pub)
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return fp, nil
}
