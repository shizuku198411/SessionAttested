package state

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

func NewSessionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	// 32 hex chars
	return hex.EncodeToString(b[:]), nil
}

func NewMeta(sessionID, workspaceHostPath string) (*SessionMeta, error) {
	if sessionID == "" {
		return nil, fmt.Errorf("sessionID empty")
	}
	m := &SessionMeta{
		SessionID: sessionID,
		StartedAt: time.Now().UTC().Format(time.RFC3339),
	}
	m.Workspace.HostPath = workspaceHostPath
	m.Workspace.ContainerPath = "/workspace"
	// Docker fields are optional until Docker integration
	return m, nil
}
