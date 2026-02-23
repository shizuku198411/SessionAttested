package docker

import (
	"context"

	"github.com/docker/docker/client"
)

func NewClient() (*client.Client, error) {
	return client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
}

func Ping(ctx context.Context, cli *client.Client) error {
	_, err := cli.Ping(ctx)
	return err
}
