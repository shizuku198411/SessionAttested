package commands

import (
	"context"
	"fmt"
	"os"

	"session-attested/internal/docker"
)

func rollbackContainerBestEffort(containerID, reason string) {
	if containerID == "" {
		return
	}
	cli, err := docker.NewClient()
	if err != nil {
		fmt.Fprintf(os.Stderr, "warn: rollback skipped (docker client): %v\n", err)
		return
	}
	if err := docker.StopAndRemove(context.Background(), cli, containerID); err != nil {
		fmt.Fprintf(os.Stderr, "warn: rollback failed (%s): %v\n", reason, err)
		return
	}
	fmt.Fprintf(os.Stderr, "rollback: removed container %s (%s)\n", containerID, reason)
}
