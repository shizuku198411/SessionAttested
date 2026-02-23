package attest

import (
	"session-attested/internal/model"
	"session-attested/internal/policy"
	"session-attested/internal/state"
	"time"
)

type BuildInput struct {
	Repo      string
	CommitSHA string
	Ref       string

	SessionID         string
	WorkspaceHostPath string

	Meta      *state.SessionMeta
	Summary   *model.AuditSummary
	EventRoot *state.EventRootFile
	Binding   *state.CommitBinding
	Bindings  []state.CommitBinding

	PolicyPath        string
	Policy            *policy.Policy
	PolicyRulesetHash string

	CollectorName    string
	CollectorVersion string
	NodeID           string
}

func BuildAttestation(in BuildInput, eval EvaluationResult, issuerName, keyID string) (*model.Attestation, error) {
	a := &model.Attestation{
		SchemaVersion:   "1.0",
		AttestationType: "non_agent_direct_write",
		Subject: model.Subject{
			Repo:      in.Repo,
			CommitSHA: in.CommitSHA,
			Ref:       in.Ref,
		},
		Session: model.Session{
			SessionID: in.SessionID,
			Workspace: model.Workspace{
				HostPath:      in.Meta.Workspace.HostPath,
				ContainerPath: in.Meta.Workspace.ContainerPath,
			},
		},
		Environment: model.Environment{
			Mode: "docker_poc",
			Collector: model.CollectorInfo{
				Name:    in.CollectorName,
				Version: in.CollectorVersion,
				NodeID:  in.NodeID,
			},
			DeveloperContainer: model.DevContainer{
				Runtime:     "docker",
				ContainerID: in.Meta.Docker.ContainerID,
				Image: model.ContainerImage{
					Name:   in.Meta.Docker.Image,
					Digest: in.Meta.Docker.ImageDigest,
				},
			},
		},
		Policy: model.PolicyRef{
			PolicyID:         in.Policy.PolicyID,
			PolicyVersion:    in.Policy.PolicyVersion,
			RulesetHash:      in.PolicyRulesetHash,
			ForbiddenExec:    toExecutableFingerprints(in.Policy.ForbiddenExec),
			ForbiddenWriters: toExecutableFingerprints(in.Policy.ForbiddenWriters),
			AllowedWriters:   toExecutableFingerprints(in.Policy.AllowedWriters), // legacy snapshot if present
		},
		AuditSummary: *in.Summary,
		Integrity: model.Integrity{
			EventRoot:      in.EventRoot.EventRoot,
			EventRootAlg:   in.EventRoot.EventRootAlg,
			EventCount:     in.EventRoot.EventCount,
			CollectorLogID: in.EventRoot.CollectorLogID,
		},
		Conclusion: model.Conclusion{
			Pass:    eval.Pass,
			Reasons: eval.Reasons,
		},
		IssuedAtRFC3339: time.Now().UTC().Format(time.RFC3339),
	}

	// reflect counters into audit summary fields (optional but useful)
	a.AuditSummary.ExecObserved.ForbiddenSeen = eval.ForbiddenExecSeen
	a.AuditSummary.WorkspaceWritesObserved.ForbiddenWriterSeen = eval.ForbiddenWriterSeen
	a.AuditSummary.WorkspaceWritesObserved.UnapprovedWriterSeen = eval.UnapprovedWriterSeen
	if in.Binding != nil {
		a.Session.CommitBinding = &model.SessionCommitRef{
			CommitSHA:      in.Binding.CommitSHA,
			ParentSHA:      in.Binding.ParentSHA,
			RepoPath:       in.Binding.RepoPath,
			CreatedRFC3339: in.Binding.CreatedRFC3339,
		}
	}
	if len(in.Bindings) > 0 {
		a.Session.CommitBindings = make([]model.SessionCommitRef, 0, len(in.Bindings))
		for _, b := range in.Bindings {
			a.Session.CommitBindings = append(a.Session.CommitBindings, model.SessionCommitRef{
				CommitSHA:      b.CommitSHA,
				ParentSHA:      b.ParentSHA,
				RepoPath:       b.RepoPath,
				CreatedRFC3339: b.CreatedRFC3339,
			})
		}
	}

	if issuerName != "" || keyID != "" {
		a.Issuer = &model.Issuer{
			Name:   issuerName,
			KeyID:  keyID,
			Method: "ed25519",
		}
	}
	return a, nil
}

func toExecutableFingerprints(rules []policy.Rule) []model.ExecutableFingerprint {
	out := make([]model.ExecutableFingerprint, 0, len(rules))
	for _, r := range rules {
		if r.SHA256 == "" {
			continue
		}
		out = append(out, model.ExecutableFingerprint{
			SHA256:  r.SHA256,
			Comment: r.Comment,
		})
	}
	return out
}
