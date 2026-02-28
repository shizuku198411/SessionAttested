package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"session-attested/internal/spec"
)

// CanonicalizeYAML returns canonical bytes for ruleset_hash.
//
// Strategy (PoC):
// - Parse YAML into Policy (typed)
// - Drop comment fields (non-semantic)
// - Drop exceptions for PoC (reserved field; currently non-semantic)
// - Build a normalized map and encode to canonical JSON bytes
func CanonicalizeYAML(raw []byte) ([]byte, error) {
	p, err := ParsePolicy(raw)
	if err != nil {
		return nil, fmt.Errorf("parse policy: %w", err)
	}

	// Normalize rules: keep only sha256 fields; comments are non-semantic.
	forbidden := normalizeRules(p.ForbiddenExec)
	forbiddenLineage := normalizeRules(p.ForbiddenExecLineageWrites)
	forbiddenWriters := normalizeRules(p.ForbiddenWriters)
	allowed := normalizeRules(p.AllowedWriters) // legacy compatibility

	// Build a normalized object.
	obj := map[string]any{
		"policy_id":         p.PolicyID,
		"policy_version":    p.PolicyVersion,
		"forbidden_exec":    forbidden,
		"forbidden_writers": forbiddenWriters,
		"allowed_writers":   allowed,
		// "exceptions": omitted in PoC canonicalization
	}
	if len(forbiddenLineage) > 0 {
		obj["forbidden_exec_lineage_writes"] = forbiddenLineage
	}

	// Canonical JSON bytes (stable key order etc.)
	return spec.CanonicalJSON(obj)
}

func normalizeRules(rules []Rule) []map[string]any {
	out := make([]map[string]any, 0, len(rules))
	for _, r := range rules {
		if r.SHA256 == "" {
			continue
		}
		out = append(out, map[string]any{
			"sha256": r.SHA256,
		})
	}

	// Sort for determinism if list order changes in YAML.
	// If you want list order to be semantic, remove this sort.
	sort.Slice(out, func(i, j int) bool {
		return out[i]["sha256"].(string) < out[j]["sha256"].(string)
	})
	return out
}

func RulesetHash(canonical []byte) string {
	h := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(h[:])
}

func BuildSet(rules []Rule) map[string]struct{} {
	set := make(map[string]struct{}, len(rules))
	for _, r := range rules {
		if r.SHA256 == "" {
			continue
		}
		set[r.SHA256] = struct{}{}
	}
	return set
}
