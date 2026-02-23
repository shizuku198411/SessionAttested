package attest

import (
	"fmt"
	"strings"

	"session-attested/internal/model"
	"session-attested/internal/policy"
)

type EvaluationResult struct {
	Pass                 bool
	Reasons              []model.ConclusionReason
	ForbiddenExecSeen    uint64
	ForbiddenWriterSeen  uint64
	UnapprovedWriterSeen uint64
}

func Evaluate(p *policy.Policy, summary *model.AuditSummary) EvaluationResult {
	forbiddenSet := policy.BuildSet(p.ForbiddenExec)
	forbiddenWriterSet := policy.BuildSet(p.ForbiddenWriters)
	allowedSet := policy.BuildSet(p.AllowedWriters) // legacy whitelist mode
	legacyWhitelistMode := len(allowedSet) > 0

	var forbiddenWriterSeen uint64
	var unapprovedWriterSeen uint64
	var forbiddenExecSeen uint64
	var forbiddenWriters []model.ExecutableIdentity
	var unapprovedWriters []model.ExecutableIdentity
	var forbiddenExecs []model.ExecutableIdentity

	for _, w := range summary.WriterIdentities {
		if _, ok := forbiddenWriterSet[w.SHA256]; ok {
			forbiddenWriterSeen++
			forbiddenWriters = appendIdentitySample(forbiddenWriters, w)
		}
		if legacyWhitelistMode {
			if _, ok := allowedSet[w.SHA256]; !ok {
				unapprovedWriterSeen++
				unapprovedWriters = appendIdentitySample(unapprovedWriters, w)
			}
		}
	}

	if len(summary.ExecutedIdentities) > 0 {
		for _, e := range summary.ExecutedIdentities {
			if _, ok := forbiddenSet[e.SHA256]; ok {
				forbiddenExecSeen++
				forbiddenExecs = appendIdentitySample(forbiddenExecs, e)
			}
		}
	} else {
		// Backward-compatible fallback for older summaries.
		forbiddenExecSeen = summary.ExecObserved.ForbiddenSeen
	}

	pass := true
	var reasons []model.ConclusionReason

	if forbiddenExecSeen > 0 {
		pass = false
		reasons = append(reasons, model.ConclusionReason{
			Code:   "FORBIDDEN_EXEC_SEEN",
			Detail: formatIdentityReasonDetail(forbiddenExecSeen, forbiddenExecs),
		})
	}
	if forbiddenWriterSeen > 0 {
		pass = false
		reasons = append(reasons, model.ConclusionReason{
			Code:   "FORBIDDEN_WRITER_SEEN",
			Detail: formatIdentityReasonDetail(forbiddenWriterSeen, forbiddenWriters),
		})
	}
	if legacyWhitelistMode && unapprovedWriterSeen > 0 {
		pass = false
		reasons = append(reasons, model.ConclusionReason{
			Code:   "UNAPPROVED_WRITER_SEEN",
			Detail: formatIdentityReasonDetail(unapprovedWriterSeen, unapprovedWriters),
		})
	}
	if pass {
		reasons = append(reasons, model.ConclusionReason{Code: "OK"})
	}

	// Update counters in summary-like manner (caller may reflect these into attestation fields)
	return EvaluationResult{
		Pass:                 pass,
		Reasons:              reasons,
		ForbiddenExecSeen:    forbiddenExecSeen,
		ForbiddenWriterSeen:  forbiddenWriterSeen,
		UnapprovedWriterSeen: unapprovedWriterSeen,
	}
}

func appendIdentitySample(dst []model.ExecutableIdentity, x model.ExecutableIdentity) []model.ExecutableIdentity {
	const maxSamples = 5
	if len(dst) >= maxSamples {
		return dst
	}
	return append(dst, x)
}

func formatIdentityReasonDetail(total uint64, ids []model.ExecutableIdentity) string {
	if total == 0 {
		return ""
	}
	if len(ids) == 0 {
		return fmt.Sprintf("count=%d", total)
	}
	parts := make([]string, 0, len(ids))
	for _, id := range ids {
		s := id.SHA256
		if len(s) > 16 {
			s = s[:16]
		}
		if id.PathHint != "" {
			parts = append(parts, fmt.Sprintf("%s(%s)", s, id.PathHint))
		} else {
			parts = append(parts, s)
		}
	}
	return fmt.Sprintf("count=%d samples=[%s]", total, strings.Join(parts, ", "))
}
