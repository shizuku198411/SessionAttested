package docker

import (
	"context"

	//"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

type ContainerIdentity struct {
	ID     string
	Labels map[string]string
}

func InspectIdentity(ctx context.Context, cli *client.Client, containerID string) (*ContainerIdentity, error) {
	ins, err := cli.ContainerInspect(ctx, containerID)
	if err != nil {
		return nil, err
	}
	labels := map[string]string{}
	if ins.Config != nil && ins.Config.Labels != nil {
		for k, v := range ins.Config.Labels {
			labels[k] = v
		}
	}
	return &ContainerIdentity{
		ID:     ins.ID,
		Labels: labels,
	}, nil
}

// Exists returns true if container exists.
func Exists(ctx context.Context, cli *client.Client, containerID string) (bool, error) {
	_, err := cli.ContainerInspect(ctx, containerID)
	if err == nil {
		return true, nil
	}
	// docker returns error for not found; keep it simple for PoC
	return false, nil
}
