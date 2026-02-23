package docker

import (
	"context"
	"fmt"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

func StopAndRemove(ctx context.Context, cli *client.Client, containerID string) error {
	if containerID == "" {
		return fmt.Errorf("containerID is empty")
	}

	// v27: StopOptions.Timeout is *int (seconds)
	sec := int((10 * time.Second).Seconds())
	_ = cli.ContainerStop(ctx, containerID, container.StopOptions{Timeout: &sec})

	return cli.ContainerRemove(ctx, containerID, container.RemoveOptions{
		Force:         true,
		RemoveVolumes: true,
	})
}

func Stop(ctx context.Context, cli *client.Client, containerID string) error {
	if containerID == "" {
		return fmt.Errorf("containerID is empty")
	}
	sec := int((10 * time.Second).Seconds())
	return cli.ContainerStop(ctx, containerID, container.StopOptions{Timeout: &sec})
}
