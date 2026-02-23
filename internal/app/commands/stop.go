package commands

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"context"
	"session-attested/internal/docker"
	"session-attested/internal/state"
)

type stopOut struct {
	SessionID        string `json:"session_id"`
	StoppedContainer bool   `json:"stopped_container"`
	AuditSummaryPath string `json:"audit_summary_path"`
	EventRootPath    string `json:"event_root_path"`
	AttestRan        bool   `json:"attest_ran,omitempty"`
	VerifyRan        bool   `json:"verify_ran,omitempty"`
}

func RunStop(args []string) int {
	configPath, profile, _ := extractConfigArgs(args)
	resolved, err := applyConfigDefaults("stop", args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	args = resolved

	fs := flag.NewFlagSet("stop", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	sessionID := fs.String("session", "", "session id")
	stateDir := fs.String("state-dir", state.DefaultStateDir().Root, "state dir")
	keepContainer := fs.Bool("keep-container", false, "stop container but keep it (do not remove)")
	jsonOut := fs.Bool("json", false, "output JSON")
	collectorWait := fs.Duration("collector-wait", 15*time.Second, "max wait for collector finalize")
	runAttest := fs.Bool("run-attest", false, "run attested attest after finalize")
	runVerify := fs.Bool("run-verify", false, "run attested verify after attest/finalize")
	verifyWriteResult := fs.Bool("verify-write-result", false, "when --run-verify, also write ATTESTED/ATTESTED_SUMMARY")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *sessionID == "" {
		if sid, ok := readLastSessionID(); ok {
			*sessionID = sid
		}
	}
	if *sessionID == "" {
		fmt.Fprintln(os.Stderr, "error: --session is required")
		return 2
	}

	st := state.StateDir{Root: *stateDir}

	// Ensure meta exists
	var meta state.SessionMeta
	if err := state.ReadJSON(st.MetaPath(*sessionID), &meta); err != nil {
		fmt.Fprintln(os.Stderr, "error: session not found (meta missing):", err)
		return 4
	}

	// --- before StopAndRemove ---
	if meta.Docker.ContainerID != "" {
		cli, err := docker.NewClient()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: docker client:", err)
			return 3
		}

		id, err := docker.InspectIdentity(context.Background(), cli, meta.Docker.ContainerID)
		if err == nil {
			want := meta.SessionID
			got := ""
			if id.Labels != nil {
				got = id.Labels["attested.session_id"]
			}
			if got != "" && got != want && !meta.Docker.Reused {
				fmt.Fprintln(os.Stderr, "error: container label attested.session_id mismatch")
				fmt.Fprintln(os.Stderr, "  want:", want)
				fmt.Fprintln(os.Stderr, "  got :", got)
				return 5
			}
		}
	}

	stopped := false
	attestRan := false
	verifyRan := false
	auditPath := st.AuditSummaryPath(*sessionID)
	rootPath := st.EventRootPath(*sessionID)
	if !bothFilesExist(auditPath, rootPath) {
		pidPath := st.CollectorPIDPath(*sessionID)
		stopPath := st.CollectorStopPath(*sessionID)
		if _, err := os.Stat(pidPath); err == nil {
			if err := os.WriteFile(stopPath, []byte("stop\n"), 0o644); err != nil {
				fmt.Fprintln(os.Stderr, "error: signal collector stop:", err)
				return 5
			}
			deadline := time.Now().Add(*collectorWait)
			for !bothFilesExist(auditPath, rootPath) && time.Now().Before(deadline) {
				time.Sleep(200 * time.Millisecond)
			}
		}
	}
	if !bothFilesExist(auditPath, rootPath) {
		fmt.Fprintln(os.Stderr, "error: audit files are missing; collector finalize not completed")
		return 5
	}

	if !*keepContainer && meta.Docker.ContainerID != "" {
		cli, err := docker.NewClient()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: docker client:", err)
			return 3
		}
		// best-effort
		_ = docker.StopAndRemove(context.Background(), cli, meta.Docker.ContainerID)
		stopped = true
	}
	if *keepContainer && meta.Docker.ContainerID != "" {
		cli, err := docker.NewClient()
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: docker client:", err)
			return 3
		}
		_ = docker.Stop(context.Background(), cli, meta.Docker.ContainerID)
		stopped = true
	}

	if *runVerify {
		*runAttest = true
	}
	if *runAttest {
		attArgs := []string{"--session", *sessionID, "--state-dir", *stateDir}
		if strings.TrimSpace(configPath) != "" {
			attArgs = append(attArgs, "--config", configPath)
		}
		if strings.TrimSpace(profile) != "" {
			attArgs = append(attArgs, "--profile", profile)
		}
		if code := RunAttest(attArgs); code != 0 && code != 6 {
			return code
		}
		attestRan = true
	}
	if *runVerify {
		outDir, _, err := configStringValue(configPath, profile, "attest", "out")
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: resolve attest.out from config:", err)
			return 2
		}
		if strings.TrimSpace(outDir) == "" {
			fmt.Fprintln(os.Stderr, "error: stop --run-verify requires commands.attest.out in --config")
			return 2
		}
		verifyArgs := []string{
			"--attestation", filepath.Join(outDir, "attestation.json"),
			"--signature", filepath.Join(outDir, "attestation.sig"),
			"--public-key", filepath.Join(outDir, "attestation.pub"),
			"--binding", st.CommitBindingPath(*sessionID),
		}
		if *verifyWriteResult {
			verifyArgs = append(verifyArgs, "--write-result")
		}
		if strings.TrimSpace(configPath) != "" {
			verifyArgs = append(verifyArgs, "--config", configPath)
		}
		if strings.TrimSpace(profile) != "" {
			verifyArgs = append(verifyArgs, "--profile", profile)
		}
		code := RunVerify(verifyArgs)
		verifyRan = true
		if code != 0 {
			return code
		}
	}

	// When executed via sudo, restore ownership of local run artifacts for the shell user.
	chownPathToSudoOwnerBestEffort(filepath.Dir(st.Root))
	chownPathToSudoOwnerBestEffort("ATTESTED")
	chownPathToSudoOwnerBestEffort("ATTESTED_SUMMARY")
	chownPathToSudoOwnerBestEffort("ATTESTED_POLICY_LAST")
	chownPathToSudoOwnerBestEffort("ATTESTED_WORKSPACE_OBSERVED")

	return emitStop(*jsonOut, stopOut{
		SessionID:        *sessionID,
		StoppedContainer: stopped,
		AuditSummaryPath: auditPath,
		EventRootPath:    rootPath,
		AttestRan:        attestRan,
		VerifyRan:        verifyRan,
	}, 0)
}

func emitStop(jsonOut bool, out stopOut, exitCode int) int {
	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(out)
		return exitCode
	}
	fmt.Println("finalized")
	fmt.Println("stopped_container:", out.StoppedContainer)
	fmt.Println("audit_summary:", out.AuditSummaryPath)
	fmt.Println("event_root:", out.EventRootPath)
	if out.AttestRan {
		fmt.Println("attest_ran: true")
	}
	if out.VerifyRan {
		fmt.Println("verify_ran: true")
	}
	return exitCode
}

func bothFilesExist(auditPath, rootPath string) bool {
	if _, err := os.Stat(auditPath); err != nil {
		return false
	}
	if _, err := os.Stat(rootPath); err != nil {
		return false
	}
	return true
}
