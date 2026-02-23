package state

import "path/filepath"

type StateDir struct{ Root string }

func DefaultStateDir() StateDir { return StateDir{Root: "/var/lib/session-attested"} }

func (s StateDir) SessionDir(sessionID string) string {
	return filepath.Join(s.Root, "sessions", sessionID)
}
func (s StateDir) MetaPath(sessionID string) string {
	return filepath.Join(s.SessionDir(sessionID), "meta.json")
}
func (s StateDir) AuditSummaryPath(sessionID string) string {
	return filepath.Join(s.SessionDir(sessionID), "audit_summary.json")
}
func (s StateDir) EventRootPath(sessionID string) string {
	return filepath.Join(s.SessionDir(sessionID), "event_root.json")
}

func (s StateDir) CollectorStopPath(sessionID string) string {
	return filepath.Join(s.SessionDir(sessionID), "collector.stop")
}

func (s StateDir) CollectorPIDPath(sessionID string) string {
	return filepath.Join(s.SessionDir(sessionID), "collector.pid")
}

func (s StateDir) CommitBindingPath(sessionID string) string {
	return filepath.Join(s.SessionDir(sessionID), "commit_binding.json")
}

func (s StateDir) CommitBindingsPath(sessionID string) string {
	return filepath.Join(s.SessionDir(sessionID), "commit_bindings.jsonl")
}

func (s StateDir) WorkspaceMetaDir() string {
	return filepath.Join(s.Root, "workspaces")
}

func (s StateDir) WorkspaceMetaPath(workspaceID string) string {
	return filepath.Join(s.WorkspaceMetaDir(), workspaceID+".json")
}
