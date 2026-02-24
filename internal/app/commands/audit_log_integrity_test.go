package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"session-attested/internal/model"
	"session-attested/internal/spec"
	"session-attested/internal/state"
)

func TestVerifyAuditLogIntegrityForStateRoot_OK(t *testing.T) {
	tmp := t.TempDir()
	att := writeTestAuditLogsAndAttestation(t, tmp, "sess-ok")

	got := verifyAuditLogIntegrityForStateRoot(att, filepath.Join(tmp, ".attest_run", "state"))
	if !got.Checked {
		t.Fatalf("expected Checked=true")
	}
	if !got.OK {
		t.Fatalf("expected OK=true, got reason=%s", got.Reason)
	}
}

func TestVerifyAuditLogIntegrityForStateRoot_DetectsTamper(t *testing.T) {
	tmp := t.TempDir()
	att := writeTestAuditLogsAndAttestation(t, tmp, "sess-ng")

	// Tamper raw write log after event_root/attestation were built.
	writePath := filepath.Join(tmp, ".attest_run", "state", "sessions", "sess-ng", "audit_workspace_write.jsonl")
	if err := os.WriteFile(writePath, []byte(`{"schema":"audit-workspace-write/0.1","seq":2,"ts_ns":2,"pid":11,"ppid":10,"uid":1000,"comm":"tampered","filename":"/workspace/src/main.txt","op":"open_write","flags":0}`+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := verifyAuditLogIntegrityForStateRoot(att, filepath.Join(tmp, ".attest_run", "state"))
	if !got.Checked {
		t.Fatalf("expected Checked=true")
	}
	if got.OK {
		t.Fatalf("expected tamper detection failure")
	}
	if !strings.HasPrefix(got.Reason, "AUDIT_LOG_INTEGRITY_MISMATCH") {
		t.Fatalf("unexpected reason: %s", got.Reason)
	}
}

func writeTestAuditLogsAndAttestation(t *testing.T, root, sid string) *model.Attestation {
	t.Helper()
	sessionDir := filepath.Join(root, ".attest_run", "state", "sessions", sid)
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		t.Fatal(err)
	}

	execLine := `{"schema":"audit-exec/0.1","seq":1,"ts_ns":1,"pid":10,"ppid":1,"uid":1000,"comm":"sh","filename":"/bin/sh"}`
	writeLine := `{"schema":"audit-workspace-write/0.1","seq":2,"ts_ns":2,"pid":11,"ppid":10,"uid":1000,"comm":"bash","filename":"/workspace/src/main.txt","op":"open_write","flags":0}`
	if err := os.WriteFile(filepath.Join(sessionDir, "audit_exec.jsonl"), []byte(execLine+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sessionDir, "audit_workspace_write.jsonl"), []byte(writeLine+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	rootHex, count, err := recomputeEventRootFromAuditLogs(sessionDir, sid)
	if err != nil {
		t.Fatal(err)
	}
	er := state.EventRootFile{
		EventRootAlg: "hash_chain_sha256",
		EventRoot:    rootHex,
		EventCount:   count,
	}
	if err := writeJSON(filepath.Join(sessionDir, "event_root.json"), er); err != nil {
		t.Fatal(err)
	}

	att := &model.Attestation{
		Session: model.Session{SessionID: sid},
		Integrity: model.Integrity{
			EventRootAlg: "hash_chain_sha256",
			EventRoot:    rootHex,
			EventCount:   count,
		},
	}
	return att
}

func writeJSON(path string, v any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	return os.WriteFile(path, b, 0o644)
}

func TestRecomputeEventRootFromAuditLogs_OrderBySeq(t *testing.T) {
	tmp := t.TempDir()
	sid := "sess-order"
	sessionDir := filepath.Join(tmp, "sessions", sid)
	if err := os.MkdirAll(sessionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// Intentionally write seq=2 before seq=1 across files; recompute must sort by seq.
	writeLine := `{"schema":"audit-workspace-write/0.1","seq":2,"ts_ns":2,"pid":11,"ppid":10,"uid":1000,"comm":"bash","filename":"/workspace/x","op":"open_write","flags":0}`
	execLine := `{"schema":"audit-exec/0.1","seq":1,"ts_ns":1,"pid":10,"ppid":1,"uid":1000,"comm":"sh","filename":"/bin/sh"}`
	if err := os.WriteFile(filepath.Join(sessionDir, "audit_workspace_write.jsonl"), []byte(writeLine+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sessionDir, "audit_exec.jsonl"), []byte(execLine+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	gotRoot, gotCount, err := recomputeEventRootFromAuditLogs(sessionDir, sid)
	if err != nil {
		t.Fatal(err)
	}

	c1, err := spec.CanonicalizeJSONBytes([]byte(execLine))
	if err != nil {
		t.Fatal(err)
	}
	c2, err := spec.CanonicalizeJSONBytes([]byte(writeLine))
	if err != nil {
		t.Fatal(err)
	}
	hc := spec.HashChainRoot([]byte("session-attested:"+sid), [][]byte{c1, c2})
	wantRoot := spec.Hex32(hc.Root)
	if gotRoot != wantRoot || gotCount != 2 {
		t.Fatalf("mismatch got=(%s,%d) want=(%s,%d)", gotRoot, gotCount, wantRoot, 2)
	}
}
