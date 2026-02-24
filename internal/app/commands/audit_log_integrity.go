package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"session-attested/internal/model"
	"session-attested/internal/spec"
	"session-attested/internal/state"
)

type auditLogIntegrityResult struct {
	Checked bool
	OK      bool
	Reason  string
}

func verifyLocalAuditLogIntegrityIfAvailable(att *model.Attestation) auditLogIntegrityResult {
	if att == nil || strings.TrimSpace(att.Session.SessionID) == "" {
		return auditLogIntegrityResult{}
	}
	return verifyAuditLogIntegrityForStateRoot(att, filepath.Join(".attest_run", "state"))
}

func verifyAuditLogIntegrityForStateRoot(att *model.Attestation, stateRoot string) auditLogIntegrityResult {
	if att == nil {
		return auditLogIntegrityResult{}
	}
	sid := strings.TrimSpace(att.Session.SessionID)
	if sid == "" {
		return auditLogIntegrityResult{}
	}
	st := state.StateDir{Root: stateRoot}
	sessionDir := st.SessionDir(sid)
	if _, err := os.Stat(sessionDir); err != nil {
		return auditLogIntegrityResult{} // no local state -> skip
	}

	erPath := st.EventRootPath(sid)
	var erf state.EventRootFile
	if err := state.ReadJSON(erPath, &erf); err != nil {
		return auditLogIntegrityResult{} // missing/invalid event_root in local verify context -> skip
	}

	rootHex, count, err := recomputeEventRootFromAuditLogs(sessionDir, sid)
	if err != nil {
		return auditLogIntegrityResult{
			Checked: true,
			OK:      false,
			Reason:  "AUDIT_LOG_INTEGRITY_MISMATCH: " + err.Error(),
		}
	}

	if erf.EventRootAlg != "" && erf.EventRootAlg != "hash_chain_sha256" {
		return auditLogIntegrityResult{
			Checked: true,
			OK:      false,
			Reason:  "AUDIT_LOG_INTEGRITY_MISMATCH: unsupported event_root_alg in event_root.json",
		}
	}
	if att.Integrity.EventRootAlg != "" && att.Integrity.EventRootAlg != "hash_chain_sha256" {
		return auditLogIntegrityResult{
			Checked: true,
			OK:      false,
			Reason:  "AUDIT_LOG_INTEGRITY_MISMATCH: unsupported event_root_alg in attestation",
		}
	}
	if strings.TrimSpace(erf.EventRoot) != "" && normalizeEventRootValue(erf.EventRoot) != normalizeEventRootValue(rootHex) {
		return auditLogIntegrityResult{
			Checked: true,
			OK:      false,
			Reason:  "AUDIT_LOG_INTEGRITY_MISMATCH: event_root.json root mismatch",
		}
	}
	if strings.TrimSpace(att.Integrity.EventRoot) != "" && normalizeEventRootValue(att.Integrity.EventRoot) != normalizeEventRootValue(rootHex) {
		return auditLogIntegrityResult{
			Checked: true,
			OK:      false,
			Reason:  "AUDIT_LOG_INTEGRITY_MISMATCH: attestation integrity root mismatch",
		}
	}
	if erf.EventCount != 0 && erf.EventCount != count {
		return auditLogIntegrityResult{
			Checked: true,
			OK:      false,
			Reason:  "AUDIT_LOG_INTEGRITY_MISMATCH: event_root.json count mismatch",
		}
	}
	if att.Integrity.EventCount != 0 && att.Integrity.EventCount != count {
		return auditLogIntegrityResult{
			Checked: true,
			OK:      false,
			Reason:  "AUDIT_LOG_INTEGRITY_MISMATCH: attestation integrity count mismatch",
		}
	}

	return auditLogIntegrityResult{Checked: true, OK: true}
}

type seqCanonicalEvent struct {
	Seq   uint64
	Canon []byte
}

func recomputeEventRootFromAuditLogs(sessionDir, sessionID string) (string, uint64, error) {
	var events []seqCanonicalEvent

	for _, name := range []string{"audit_exec.jsonl", "audit_workspace_write.jsonl"} {
		path := filepath.Join(sessionDir, name)
		b, err := os.ReadFile(path)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", 0, fmt.Errorf("read %s: %w", name, err)
		}
		lines := strings.Split(string(b), "\n")
		for i, ln := range lines {
			ln = strings.TrimSpace(ln)
			if ln == "" {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal([]byte(ln), &m); err != nil {
				return "", 0, fmt.Errorf("%s line %d invalid json", name, i+1)
			}
			seq, ok := anyToUint64(m["seq"])
			if !ok {
				return "", 0, fmt.Errorf("%s line %d missing seq", name, i+1)
			}
			canon, err := spec.CanonicalizeJSONBytes([]byte(ln))
			if err != nil {
				return "", 0, fmt.Errorf("%s line %d canonicalize: %w", name, i+1, err)
			}
			events = append(events, seqCanonicalEvent{Seq: seq, Canon: canon})
		}
	}

	sort.SliceStable(events, func(i, j int) bool { return events[i].Seq < events[j].Seq })
	canonEvents := make([][]byte, 0, len(events))
	for _, ev := range events {
		canonEvents = append(canonEvents, ev.Canon)
	}
	hc := spec.HashChainRoot([]byte("session-attested:"+sessionID), canonEvents)
	return spec.Hex32(hc.Root), hc.Count, nil
}

func anyToUint64(v any) (uint64, bool) {
	switch x := v.(type) {
	case float64:
		if x < 0 {
			return 0, false
		}
		return uint64(x), true
	case float32:
		if x < 0 {
			return 0, false
		}
		return uint64(x), true
	case int:
		if x < 0 {
			return 0, false
		}
		return uint64(x), true
	case int64:
		if x < 0 {
			return 0, false
		}
		return uint64(x), true
	case uint64:
		return x, true
	case uint32:
		return uint64(x), true
	case json.Number:
		n, err := x.Int64()
		if err != nil || n < 0 {
			return 0, false
		}
		return uint64(n), true
	default:
		return 0, false
	}
}

func normalizeEventRootValue(s string) string {
	s = strings.TrimSpace(strings.ToLower(s))
	s = strings.TrimPrefix(s, "sha256:")
	return s
}
