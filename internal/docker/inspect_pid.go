package docker

import (
	"context"
	"fmt"

	"github.com/docker/docker/client"
)

func ContainerInitPID(ctx context.Context, cli *client.Client, containerID string) (int, error) {
	ins, err := cli.ContainerInspect(ctx, containerID)
	if err != nil {
		return 0, err
	}
	if ins.State == nil {
		return 0, fmt.Errorf("container state is nil")
	}
	// State.Pid is the init pid on the host
	if ins.State.Pid <= 0 {
		return 0, fmt.Errorf("invalid container pid: %d", ins.State.Pid)
	}
	return ins.State.Pid, nil
}
