package policy

import "testing"

func TestCanonicalizeYAML_SameMeaningSameHash(t *testing.T) {
	y1 := []byte(`
policy_id: "poc-default"
policy_version: "1.0.0"
forbidden_exec:
  - sha256: "sha256:aaaaaaaa"
    comment: "codex"
allowed_writers:
  - sha256: "sha256:bbbbbbbb"
    comment: "writer-1"
forbidden_writers: []
exceptions: []
`)

	// reorder keys; and change comments; should not affect ruleset_hash.
	y2 := []byte(`
allowed_writers:
  - comment: "different comment"
    sha256: "sha256:bbbbbbbb"
forbidden_writers: []
policy_version: "1.0.0"
policy_id: "poc-default"
forbidden_exec:
  - comment: "codex"
    sha256: "sha256:aaaaaaaa"
exceptions: []
`)

	c1, err := CanonicalizeYAML(y1)
	if err != nil {
		t.Fatal(err)
	}
	c2, err := CanonicalizeYAML(y2)
	if err != nil {
		t.Fatal(err)
	}

	h1 := RulesetHash(c1)
	h2 := RulesetHash(c2)

	if h1 != h2 {
		t.Fatalf("ruleset_hash mismatch: %s vs %s\nc1=%s\nc2=%s", h1, h2, c1, c2)
	}
}

func TestParsePolicy_Minimal(t *testing.T) {
	raw := []byte(`
policy_id: "poc-default"
policy_version: "1.0.0"
forbidden_exec: []
forbidden_writers: []
allowed_writers: []
exceptions: []
`)
	p, err := ParsePolicy(raw)
	if err != nil {
		t.Fatal(err)
	}
	if p.PolicyID != "poc-default" {
		t.Fatalf("policy_id mismatch: %s", p.PolicyID)
	}
	if p.PolicyVersion != "1.0.0" {
		t.Fatalf("policy_version mismatch: %s", p.PolicyVersion)
	}
	if p.ForbiddenExec == nil || p.ForbiddenWriters == nil || p.AllowedWriters == nil {
		t.Fatalf("lists must be non-nil")
	}
}

func TestCanonicalizeYAML_ListOrderIgnored(t *testing.T) {
	y1 := []byte(`
policy_id: "poc-default"
policy_version: "1.0.0"
forbidden_exec:
  - sha256: "sha256:bbbb"
  - sha256: "sha256:aaaa"
allowed_writers: []
forbidden_writers: []
`)

	y2 := []byte(`
policy_id: "poc-default"
policy_version: "1.0.0"
forbidden_exec:
  - sha256: "sha256:aaaa"
  - sha256: "sha256:bbbb"
allowed_writers: []
forbidden_writers: []
`)

	c1, _ := CanonicalizeYAML(y1)
	c2, _ := CanonicalizeYAML(y2)
	if RulesetHash(c1) != RulesetHash(c2) {
		t.Fatalf("expected same hash when only list order differs")
	}
}
