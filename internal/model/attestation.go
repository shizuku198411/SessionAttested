package model

type Attestation struct {
	SchemaVersion   string       `json:"schema_version"`
	AttestationType string       `json:"attestation_type"`
	Subject         Subject      `json:"subject"`
	Session         Session      `json:"session"`
	Environment     Environment  `json:"environment"`
	Policy          PolicyRef    `json:"policy"`
	AuditSummary    AuditSummary `json:"audit_summary"`
	Integrity       Integrity    `json:"integrity"`
	Conclusion      Conclusion   `json:"conclusion"`
	IssuedAtRFC3339 string       `json:"issued_at"`
	Issuer          *Issuer      `json:"issuer,omitempty"`
}

type Subject struct {
	Repo      string `json:"repo"`
	CommitSHA string `json:"commit_sha"`
	Ref       string `json:"ref"`
}

type Session struct {
	SessionID      string             `json:"session_id"`
	Workspace      Workspace          `json:"workspace"`
	CommitBinding  *SessionCommitRef  `json:"commit_binding,omitempty"`
	CommitBindings []SessionCommitRef `json:"commit_bindings,omitempty"`
}

type SessionCommitRef struct {
	CommitSHA      string `json:"commit_sha"`
	ParentSHA      string `json:"parent_sha,omitempty"`
	RepoPath       string `json:"repo_path,omitempty"`
	CreatedRFC3339 string `json:"created_rfc3339,omitempty"`
}

type Workspace struct {
	HostPath      string `json:"host_path"`
	ContainerPath string `json:"container_path"`
}

type Environment struct {
	Mode               string        `json:"mode"`
	Collector          CollectorInfo `json:"collector"`
	DeveloperContainer DevContainer  `json:"developer_container"`
}

type CollectorInfo struct {
	Name    string      `json:"name"`
	Version string      `json:"version"`
	NodeID  string      `json:"node_id"`
	Kernel  *KernelInfo `json:"kernel,omitempty"`
}

type KernelInfo struct {
	Release string `json:"release,omitempty"`
	BuildID string `json:"build_id,omitempty"`
}

type DevContainer struct {
	Runtime     string         `json:"runtime"`
	ContainerID string         `json:"container_id"`
	Image       ContainerImage `json:"image"`
}

type ContainerImage struct {
	Name   string `json:"name"`
	Digest string `json:"digest,omitempty"`
}

type PolicyRef struct {
	PolicyID         string                  `json:"policy_id"`
	PolicyVersion    string                  `json:"policy_version"`
	RulesetHash      string                  `json:"ruleset_hash"`
	ForbiddenExec    []ExecutableFingerprint `json:"forbidden_exec"`
	ForbiddenWriters []ExecutableFingerprint `json:"forbidden_writers,omitempty"`
	AllowedWriters   []ExecutableFingerprint `json:"allowed_writers,omitempty"` // legacy whitelist snapshot
}

type ExecutableFingerprint struct {
	SHA256  string `json:"sha256"`
	Comment string `json:"comment,omitempty"`
}

type AuditSummary struct {
	Window                  AuditWindow             `json:"window"`
	ExecObserved            ExecObserved            `json:"exec_observed"`
	ExecutedIdentities      []ExecutableIdentity    `json:"executed_identities,omitempty"`
	WorkspaceWritesObserved WorkspaceWritesObserved `json:"workspace_writes_observed"`
	WorkspaceFiles          []WorkspaceWriteFile    `json:"workspace_files,omitempty"`
	WriterIdentities        []ExecutableIdentity    `json:"writer_identities"`
	Notes                   string                  `json:"notes,omitempty"`
}

type AuditWindow struct {
	StartRFC3339 string `json:"start_rfc3339"`
	EndRFC3339   string `json:"end_rfc3339"`
}

type ExecObserved struct {
	Count                   uint64   `json:"count"`
	ForbiddenSeen           uint64   `json:"forbidden_seen,omitempty"`
	IdentityUnresolved      uint64   `json:"identity_unresolved,omitempty"`
	IdentityUnresolvedHints []string `json:"identity_unresolved_hints,omitempty"`
}

type WorkspaceWritesObserved struct {
	Count                         uint64            `json:"count"`
	ByOp                          map[string]uint64 `json:"by_op,omitempty"`
	ForbiddenWriterSeen           uint64            `json:"forbidden_writer_seen,omitempty"`
	UnapprovedWriterSeen          uint64            `json:"unapproved_writer_seen,omitempty"`
	WriterIdentityUnresolved      uint64            `json:"writer_identity_unresolved,omitempty"`
	WriterIdentityUnresolvedHints []string          `json:"writer_identity_unresolved_hints,omitempty"`
}

type WorkspaceWriteFile struct {
	Path                     string               `json:"path"`
	WriteCount               uint64               `json:"write_count"`
	ByOp                     map[string]uint64    `json:"by_op,omitempty"`
	Writers                  []ExecutableIdentity `json:"writers,omitempty"`
	Comms                    []string             `json:"comms,omitempty"`
	WriterIdentityUnresolved uint64               `json:"writer_identity_unresolved,omitempty"`
}

type ExecutableIdentity struct {
	SHA256   string `json:"sha256"`
	Inode    uint64 `json:"inode"`
	Dev      uint64 `json:"dev"`
	PathHint string `json:"path_hint,omitempty"`
}

type Integrity struct {
	EventRoot      string `json:"event_root"`
	EventRootAlg   string `json:"event_root_alg"`
	EventCount     uint64 `json:"event_count"`
	CollectorLogID string `json:"collector_log_id,omitempty"`
}

type Conclusion struct {
	Pass    bool               `json:"pass"`
	Reasons []ConclusionReason `json:"reasons"`
}

type ConclusionReason struct {
	Code   string `json:"code"`
	Detail string `json:"detail,omitempty"`
}

type Issuer struct {
	Name   string `json:"name,omitempty"`
	KeyID  string `json:"key_id,omitempty"`
	Method string `json:"method,omitempty"`
}
