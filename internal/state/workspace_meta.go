package state

type WorkspaceMeta struct {
	WorkspaceID string `json:"workspace_id"`
	CreatedAt   string `json:"created_at"`
	Workspace   struct {
		HostPath      string `json:"host_path"`
		ContainerPath string `json:"container_path"`
	} `json:"workspace"`
	Docker struct {
		ContainerID   string `json:"container_id"`
		ContainerName string `json:"container_name,omitempty"`
		Image         string `json:"image"`
		ImageDigest   string `json:"image_digest,omitempty"`
	} `json:"docker"`
}
