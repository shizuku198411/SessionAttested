package commands

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"session-attested/internal/collector"
	"session-attested/internal/collector/ebpf"
	"session-attested/internal/docker"
	"session-attested/internal/state"
)

func RunCollect(args []string) int {
	resolved, err := applyConfigDefaults("collect", args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	args = resolved

	fs := flag.NewFlagSet("collect", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	sessionID := fs.String("session", "", "session id")
	stateDir := fs.String("state-dir", state.DefaultStateDir().Root, "state dir")
	duration := fs.Duration("duration", 30*time.Second, "collection duration, e.g. 30s")
	untilStop := fs.Bool("until-stop", false, "run until stop signal file is created")
	poll := fs.Duration("poll", 300*time.Millisecond, "poll interval for until-stop mode")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *sessionID == "" {
		fmt.Fprintln(os.Stderr, "error: --session is required")
		return 2
	}
	if *untilStop && *duration > 0 {
		*duration = 0
	}

	st := state.StateDir{Root: *stateDir}
	var meta state.SessionMeta
	if err := state.ReadJSON(st.MetaPath(*sessionID), &meta); err != nil {
		fmt.Fprintln(os.Stderr, "error: read meta:", err)
		return 4
	}
	if meta.Docker.ContainerID == "" {
		fmt.Fprintln(os.Stderr, "error: container_id missing in meta")
		return 4
	}
	rollbackOnSetupFailure := true
	defer func() {
		if rollbackOnSetupFailure {
			rollbackContainerBestEffort(meta.Docker.ContainerID, "collect setup failed")
		}
	}()

	cli, err := docker.NewClient()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: docker client:", err)
		return 3
	}
	pid, err := docker.ContainerInitPID(context.Background(), cli, meta.Docker.ContainerID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: inspect container pid:", err)
		return 3
	}

	c := ebpf.New(st)
	if err := c.Start(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, "error: start ebpf collector:", err)
		return 3
	}
	defer c.Close()

	// register session (initPID required for mapping)
	if err := c.RegisterSession(context.Background(), collector.SessionRegistration{
		SessionID:         *sessionID,
		ContainerID:       meta.Docker.ContainerID,
		ContainerInitPID:  pid,
		WorkspaceHostPath: meta.Workspace.HostPath,
	}); err != nil {
		fmt.Fprintln(os.Stderr, "error: register session:", err)
		return 3
	}
	rollbackOnSetupFailure = false

	stopPath := st.CollectorStopPath(*sessionID)
	pidPath := st.CollectorPIDPath(*sessionID)
	_ = os.Remove(stopPath)

	if *untilStop {
		if err := os.WriteFile(pidPath, []byte(fmt.Sprintf("%d\n", os.Getpid())), 0o644); err != nil {
			fmt.Fprintln(os.Stderr, "error: write collector pid:", err)
			return 3
		}
		defer os.Remove(pidPath)

		for {
			if _, err := os.Stat(stopPath); err == nil {
				break
			}
			time.Sleep(*poll)
		}
	} else {
		time.Sleep(*duration)
	}

	// finalize and write audit files
	res, err := c.FinalizeSession(context.Background(), *sessionID)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: finalize:", err)
		return 5
	}

	// write summary/root into state-dir (stop と同じ)
	if err := state.WriteJSON(st.AuditSummaryPath(*sessionID), res.Summary, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "error: write audit_summary:", err)
		return 3
	}
	evRoot := state.EventRootFile{
		EventRootAlg:   res.EventRootAlg,
		EventRoot:      res.EventRootHex,
		EventCount:     res.EventCount,
		CollectorLogID: res.CollectorLogID,
		Window:         state.AuditWindowFrom(res.WindowStartRFC3339, res.WindowEndRFC3339),
	}
	if err := state.WriteJSON(st.EventRootPath(*sessionID), evRoot, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "error: write event_root:", err)
		return 3
	}

	fmt.Println("collected and finalized")
	fmt.Println("audit_summary:", st.AuditSummaryPath(*sessionID))
	fmt.Println("event_root:", st.EventRootPath(*sessionID))
	if *untilStop {
		fmt.Println("mode: until-stop")
	}
	return 0
}
