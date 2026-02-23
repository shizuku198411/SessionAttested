package state

import "session-attested/internal/model"

type EventRootFile struct {
	EventRootAlg   string            `json:"event_root_alg"`
	EventRoot      string            `json:"event_root"`
	EventCount     uint64            `json:"event_count"`
	Window         model.AuditWindow `json:"window"`
	CollectorLogID string            `json:"collector_log_id,omitempty"`
}
