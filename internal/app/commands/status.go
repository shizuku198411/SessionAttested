package commands

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"session-attested/internal/state"
)

type statusOut struct {
	SessionID        string `json:"session_id"`
	Exists           bool   `json:"exists"`
	Finalized        bool   `json:"finalized"`
	MetaPath         string `json:"meta_path"`
	AuditSummaryPath string `json:"audit_summary_path"`
	EventRootPath    string `json:"event_root_path"`
	WorkspaceHost    string `json:"workspace_host,omitempty"`
}

func RunStatus(args []string) int {
	resolved, err := applyConfigDefaults("status", args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	args = resolved

	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	sessionID := fs.String("session", "", "session id")
	stateDir := fs.String("state-dir", state.DefaultStateDir().Root, "state dir")
	jsonOut := fs.Bool("json", false, "output JSON")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *sessionID == "" {
		fmt.Fprintln(os.Stderr, "error: --session is required")
		return 2
	}

	st := state.StateDir{Root: *stateDir}

	metaPath := st.MetaPath(*sessionID)
	auditPath := st.AuditSummaryPath(*sessionID)
	rootPath := st.EventRootPath(*sessionID)

	out := statusOut{
		SessionID:        *sessionID,
		MetaPath:         metaPath,
		AuditSummaryPath: auditPath,
		EventRootPath:    rootPath,
	}

	var meta state.SessionMeta
	if err := state.ReadJSON(metaPath, &meta); err != nil {
		out.Exists = false
		if *jsonOut {
			enc := json.NewEncoder(os.Stdout)
			enc.SetEscapeHTML(false)
			_ = enc.Encode(out)
			return 4
		}
		fmt.Println("not found")
		return 4
	}

	out.Exists = true
	out.WorkspaceHost = meta.Workspace.HostPath

	_, err1 := os.Stat(auditPath)
	_, err2 := os.Stat(rootPath)
	out.Finalized = (err1 == nil && err2 == nil)

	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(out)
		return 0
	}

	fmt.Printf("session_id: %s\n", *sessionID)
	fmt.Printf("workspace_host: %s\n", out.WorkspaceHost)
	fmt.Printf("finalized: %v\n", out.Finalized)
	fmt.Printf("meta: %s\n", metaPath)
	fmt.Printf("audit_summary: %s\n", auditPath)
	fmt.Printf("event_root: %s\n", rootPath)
	return 0
}
