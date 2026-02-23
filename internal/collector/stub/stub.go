package stub

import (
	"context"
	"time"

	"session-attested/internal/collector"
	"session-attested/internal/model"
)

type StubCollector struct{}

func New() *StubCollector { return &StubCollector{} }

func (s *StubCollector) RegisterSession(ctx context.Context, reg collector.SessionRegistration) error {
	_ = ctx
	_ = reg
	return nil
}

func (s *StubCollector) FinalizeSession(ctx context.Context, sessionID string) (*collector.FinalizeResult, error) {
	_ = ctx
	now := time.Now().UTC()

	summary := &model.AuditSummary{
		Window: model.AuditWindow{
			StartRFC3339: now.Add(-1 * time.Minute).Format(time.RFC3339),
			EndRFC3339:   now.Format(time.RFC3339),
		},
		ExecObserved: model.ExecObserved{
			Count:         0,
			ForbiddenSeen: 0,
		},
		WorkspaceWritesObserved: model.WorkspaceWritesObserved{
			Count: 0,
		},
		WriterIdentities: []model.ExecutableIdentity{},
	}

	return &collector.FinalizeResult{
		Summary:            summary,
		EventRootAlg:       "hash_chain_sha256",
		EventRootHex:       "0000000000000000000000000000000000000000000000000000000000000000",
		EventCount:         0,
		WindowStartRFC3339: summary.Window.StartRFC3339,
		WindowEndRFC3339:   summary.Window.EndRFC3339,
		CollectorLogID:     "stub:" + sessionID,
	}, nil
}

func (s *StubCollector) Status(ctx context.Context, sessionID string) (string, error) {
	_ = ctx
	_ = sessionID
	return "unknown", nil
}

func (s *StubCollector) ResolveSession(ctx context.Context, req collector.ContainerResolveRequest) (string, bool, error) {
	_ = ctx
	// PoC: rely on label
	if req.Labels == nil {
		return "", false, nil
	}
	if sid, ok := req.Labels["attested.session_id"]; ok && sid != "" {
		return sid, true, nil
	}
	return "", false, nil
}
