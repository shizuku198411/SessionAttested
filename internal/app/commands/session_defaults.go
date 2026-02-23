package commands

import (
	"os"
	"path/filepath"
	"strings"
)

func defaultLastSessionIDPath() string {
	return filepath.Join(".attest_run", "last_session_id")
}

func readLastSessionID() (string, bool) {
	b, err := os.ReadFile(defaultLastSessionIDPath())
	if err != nil {
		return "", false
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", false
	}
	return s, true
}

func writeLastSessionID(sessionID string) error {
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return nil
	}
	p := defaultLastSessionIDPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(sessionID+"\n"), 0o644)
}
