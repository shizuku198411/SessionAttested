package state

type SessionMeta struct {
	SessionID string `json:"session_id"`
	StartedAt string `json:"started_at"`
	Workspace struct {
		HostPath      string `json:"host_path"`
		ContainerPath string `json:"container_path"`
	} `json:"workspace"`
	Docker struct {
		ContainerID string `json:"container_id"`
		Image       string `json:"image"`
		ImageDigest string `json:"image_digest,omitempty"`
		Reused      bool   `json:"reused,omitempty"`
	} `json:"docker"`
	Policy struct {
		Path        string `json:"path,omitempty"`
		RulesetHash string `json:"ruleset_hash,omitempty"`
	} `json:"policy"`
}
