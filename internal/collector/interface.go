package collector

import (
	"context"
	"session-attested/internal/model"
)

type SessionRegistration struct {
	SessionID         string
	WorkspaceHostPath string
	ContainerID       string
	ContainerInitPID  int
	CgroupHint        string
}

type FinalizeResult struct {
	Summary            *model.AuditSummary
	EventRootAlg       string
	EventRootHex       string
	EventCount         uint64
	WindowStartRFC3339 string
	WindowEndRFC3339   string
	CollectorLogID     string
}

type ContainerResolveRequest struct {
	ContainerID string
	Labels      map[string]string
}

type Collector interface {
	RegisterSession(ctx context.Context, reg SessionRegistration) error
	FinalizeSession(ctx context.Context, sessionID string) (*FinalizeResult, error)
	Status(ctx context.Context, sessionID string) (string, error)
	ResolveSession(ctx context.Context, req ContainerResolveRequest) (string /*sessionID*/, bool /*ok*/, error)
}
