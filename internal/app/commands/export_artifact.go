package commands

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"session-attested/internal/state"
)

type exportArtifactOut struct {
	SessionID    string   `json:"session_id"`
	OutDir       string   `json:"out_dir"`
	Attestation  string   `json:"attestation"`
	FilesCopied  []string `json:"files_copied"`
	FilesSkipped []string `json:"files_skipped,omitempty"`
}

func RunExportArtifact(args []string) int {
	resolved, err := applyConfigDefaults("export_artifact", args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	args = resolved

	fs := flag.NewFlagSet("export artifact", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	sessionID := fs.String("session", "", "session id (default: .attest_run/last_session_id)")
	stateDir := fs.String("state-dir", filepath.Join(".attest_run", "state"), "state dir")
	runDir := fs.String("run-dir", ".attest_run", "run dir")
	outDir := fs.String("out", filepath.Join("attest", "attested_artifacts", "latest"), "artifact export output dir")
	policyPath := fs.String("policy", "", "policy source path (default: attest/policy.yaml or ATTESTED_POLICY_LAST)")
	includeRawLogs := fs.Bool("include-raw-logs", false, "include raw audit jsonl logs")
	jsonOut := fs.Bool("json", false, "output JSON")

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if strings.TrimSpace(*sessionID) == "" {
		if sid, ok := readLastSessionID(); ok {
			*sessionID = sid
		}
	}
	if strings.TrimSpace(*sessionID) == "" {
		fmt.Fprintln(os.Stderr, "error: --session is required")
		return 2
	}

	attPath, _, attErr := resolveAttestationForSession(*runDir, *sessionID)
	if attErr != nil || strings.TrimSpace(attPath) == "" {
		fmt.Fprintln(os.Stderr, "error: resolve attestation for session:", attErr)
		return 4
	}

	attDir := filepath.Dir(attPath)
	sigPath := filepath.Join(attDir, "attestation.sig")
	pubPath := filepath.Join(attDir, "attestation.pub")

	st := state.StateDir{Root: *stateDir}
	sessionDir := st.SessionDir(*sessionID)
	commitBindingJSONL := st.CommitBindingsPath(*sessionID)
	commitBindingJSON := st.CommitBindingPath(*sessionID)

	if err := os.MkdirAll(filepath.Join(*outDir, "attestation"), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "error: mkdir attestation dir:", err)
		return 3
	}
	if err := os.MkdirAll(filepath.Join(*outDir, "inputs"), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "error: mkdir inputs dir:", err)
		return 3
	}
	if err := os.MkdirAll(filepath.Join(*outDir, "audit"), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "error: mkdir audit dir:", err)
		return 3
	}

	var copied []string
	var skipped []string
	copyReq := func(src, dst string) error {
		if err := copyFile(src, dst); err != nil {
			return err
		}
		copied = append(copied, dst)
		return nil
	}
	copyOpt := func(src, dst string) {
		if strings.TrimSpace(src) == "" {
			return
		}
		if _, err := os.Stat(src); err != nil {
			skipped = append(skipped, src)
			return
		}
		if err := copyReq(src, dst); err != nil {
			skipped = append(skipped, src+" ("+err.Error()+")")
		}
	}

	// Top-level ATTESTED artifacts (verify outputs)
	copyOpt(filepath.Join(".", "ATTESTED"), filepath.Join(*outDir, "ATTESTED"))
	copyOpt(filepath.Join(".", "ATTESTED_SUMMARY"), filepath.Join(*outDir, "ATTESTED_SUMMARY"))
	copyOpt(filepath.Join(".", "ATTESTED_POLICY_LAST"), filepath.Join(*outDir, "ATTESTED_POLICY_LAST"))
	copyOpt(filepath.Join(".", "ATTESTED_WORKSPACE_OBSERVED"), filepath.Join(*outDir, "ATTESTED_WORKSPACE_OBSERVED"))

	// Attestation bundle (session-specific preferred by resolver)
	if err := copyReq(attPath, filepath.Join(*outDir, "attestation", "attestation.json")); err != nil {
		fmt.Fprintln(os.Stderr, "error: copy attestation.json:", err)
		return 3
	}
	if err := copyReq(sigPath, filepath.Join(*outDir, "attestation", "attestation.sig")); err != nil {
		fmt.Fprintln(os.Stderr, "error: copy attestation.sig:", err)
		return 3
	}
	if err := copyReq(pubPath, filepath.Join(*outDir, "attestation", "attestation.pub")); err != nil {
		fmt.Fprintln(os.Stderr, "error: copy attestation.pub:", err)
		return 3
	}

	// Policy input (prefer explicit/attest/policy.yaml, fallback to ATTESTED_POLICY_LAST).
	pol := strings.TrimSpace(*policyPath)
	if pol == "" {
		if _, err := os.Stat(filepath.Join("attest", "policy.yaml")); err == nil {
			pol = filepath.Join("attest", "policy.yaml")
		} else if _, err := os.Stat("ATTESTED_POLICY_LAST"); err == nil {
			pol = "ATTESTED_POLICY_LAST"
		}
	}
	if pol != "" {
		if err := copyReq(pol, filepath.Join(*outDir, "inputs", "policy.yaml")); err != nil {
			fmt.Fprintln(os.Stderr, "error: copy policy:", err)
			return 3
		}
	} else {
		fmt.Fprintln(os.Stderr, "error: policy source not found (use --policy or create attest/policy.yaml / ATTESTED_POLICY_LAST)")
		return 2
	}

	// Commit binding(s)
	if _, err := os.Stat(commitBindingJSONL); err == nil {
		if err := copyReq(commitBindingJSONL, filepath.Join(*outDir, "inputs", "commit_bindings.jsonl")); err != nil {
			fmt.Fprintln(os.Stderr, "error: copy commit_bindings.jsonl:", err)
			return 3
		}
	} else if _, err := os.Stat(commitBindingJSON); err == nil {
		if err := copyReq(commitBindingJSON, filepath.Join(*outDir, "inputs", "commit_binding.json")); err != nil {
			fmt.Fprintln(os.Stderr, "error: copy commit_binding.json:", err)
			return 3
		}
	} else {
		fmt.Fprintln(os.Stderr, "error: commit binding not found for session")
		return 4
	}

	// Session audit summaries (recommended)
	copyOpt(filepath.Join(sessionDir, "audit_summary.json"), filepath.Join(*outDir, "audit", "audit_summary.json"))
	copyOpt(filepath.Join(sessionDir, "event_root.json"), filepath.Join(*outDir, "audit", "event_root.json"))
	copyOpt(filepath.Join(sessionDir, "meta.json"), filepath.Join(*outDir, "audit", "meta.json"))
	copyOpt(filepath.Join(*runDir, "reports", "sessions", *sessionID, "session_correlation.json"),
		filepath.Join(*outDir, "audit", "session_correlation.json"))

	if *includeRawLogs {
		copyOpt(filepath.Join(sessionDir, "audit_exec.jsonl"), filepath.Join(*outDir, "audit", "audit_exec.jsonl"))
		copyOpt(filepath.Join(sessionDir, "audit_workspace_write.jsonl"), filepath.Join(*outDir, "audit", "audit_workspace_write.jsonl"))
	}

	chownPathToSudoOwnerBestEffort(*outDir)

	if *jsonOut {
		out := exportArtifactOut{
			SessionID:    *sessionID,
			OutDir:       *outDir,
			Attestation:  attPath,
			FilesCopied:  copied,
			FilesSkipped: skipped,
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(out)
		return 0
	}

	fmt.Println("exported artifact bundle:", *outDir)
	fmt.Println("session:", *sessionID)
	for _, p := range copied {
		fmt.Println("  copied:", p)
	}
	for _, p := range skipped {
		fmt.Println("  skipped:", p)
	}
	if _, err := os.Stat(filepath.Join(".github", "workflows", "publish-attested-artifact.yml")); err != nil {
		fmt.Println("next: generate publish workflow template: attested workflow github-artifact")
	}
	if _, err := os.Stat(filepath.Join(".github", "workflows", "verify-session-attested.yml")); err != nil {
		fmt.Println("next: generate verify workflow template: attested workflow github-verify")
	}
	return 0
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return nil
}
