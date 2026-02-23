package docker

import (
	"context"
	"fmt"
	"io"
	"os"
	"reflect"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	"github.com/docker/go-connections/nat"
)

type RunOptions struct {
	Image string
	Name  string

	WorkspaceHostPath      string
	WorkspaceContainerPath string // usually "/workspace"

	Env        []string // "K=V"
	Cmd        []string
	WorkingDir string
	Publish    []string // repeatable, e.g. "127.0.0.1:2222:22/tcp"

	Pull bool

	TTY   bool
	Stdin bool

	// CgroupParent is optional. Example: "/attested/<session_id>"
	CgroupParent string

	// Labels are always recommended (fallback binding).
	Labels map[string]string

	ExtraMounts []mount.Mount
}

type RunResult struct {
	ContainerID   string
	ContainerName string
	ImageName     string
	ImageDigest   string // "sha256:..." if found
}

func CreateDevContainer(ctx context.Context, cli *client.Client, opts RunOptions) (*RunResult, error) {
	if opts.Image == "" {
		return nil, fmt.Errorf("image is required")
	}
	if opts.WorkspaceHostPath == "" {
		return nil, fmt.Errorf("workspace host path is required")
	}
	if opts.WorkspaceContainerPath == "" {
		opts.WorkspaceContainerPath = "/workspace"
	}
	if !opts.TTY {
		opts.TTY = true
	}
	if opts.Labels == nil {
		opts.Labels = map[string]string{}
	}

	digest, err := EnsureImage(ctx, cli, opts.Image, opts.Pull)
	if err != nil {
		return nil, fmt.Errorf("ensure image: %w", err)
	}

	cfg := &container.Config{
		Image:      opts.Image,
		Env:        opts.Env,
		Cmd:        opts.Cmd,
		WorkingDir: opts.WorkingDir,
		Tty:        opts.TTY,
		OpenStdin:  opts.Stdin,
		Labels:     opts.Labels,
	}

	hostCfg := &container.HostConfig{
		Mounts: []mount.Mount{
			{
				Type:   mount.TypeBind,
				Source: opts.WorkspaceHostPath,
				Target: opts.WorkspaceContainerPath,
			},
		},
	}
	if len(opts.ExtraMounts) > 0 {
		hostCfg.Mounts = append(hostCfg.Mounts, opts.ExtraMounts...)
	}
	if len(opts.Publish) > 0 {
		exposed, bindings, err := nat.ParsePortSpecs(opts.Publish)
		if err != nil {
			return nil, fmt.Errorf("parse publish specs: %w", err)
		}
		cfg.ExposedPorts = exposed
		hostCfg.PortBindings = bindings
	}
	if opts.CgroupParent != "" {
		ok := setStringField(hostCfg, "CgroupParent", opts.CgroupParent)
		if !ok {
			return nil, fmt.Errorf("cgroup parent requested but HostConfig.CgroupParent not available in this SDK build")
		}
	}

	resp, err := cli.ContainerCreate(ctx, cfg, hostCfg, nil, nil, opts.Name)
	if err != nil {
		return nil, fmt.Errorf("container create: %w", err)
	}
	name := opts.Name
	if name == "" {
		name = resp.ID
	}
	return &RunResult{
		ContainerID:   resp.ID,
		ContainerName: name,
		ImageName:     opts.Image,
		ImageDigest:   digest,
	}, nil
}

func EnsureImage(ctx context.Context, cli *client.Client, ref string, pull bool) (string /*digest*/, error) {
	if pull {
		rc, err := cli.ImagePull(ctx, ref, image.PullOptions{})
		if err != nil {
			return "", err
		}
		_, _ = io.Copy(io.Discard, rc)
		_ = rc.Close()
	}

	args := filters.NewArgs()
	args.Add("reference", ref)

	imgs, err := cli.ImageList(ctx, image.ListOptions{Filters: args})
	if err != nil {
		return "", err
	}

	for _, img := range imgs {
		for _, rd := range img.RepoDigests {
			if strings.Contains(rd, "@sha256:") {
				parts := strings.SplitN(rd, "@", 2)
				if len(parts) == 2 {
					return parts[1], nil // "sha256:..."
				}
			}
		}
	}
	return "", nil
}

func ImageExists(ctx context.Context, cli *client.Client, ref string) (bool, error) {
	_, _, err := cli.ImageInspectWithRaw(ctx, ref)
	if err == nil {
		return true, nil
	}
	if client.IsErrNotFound(err) || strings.Contains(strings.ToLower(err.Error()), "no such image") {
		return false, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

// setStringField sets a string field by name using reflection.
// It returns true if the field existed and was set, false otherwise.
func setStringField(ptr any, fieldName, value string) bool {
	v := reflect.ValueOf(ptr)
	if v.Kind() != reflect.Pointer {
		return false
	}
	e := v.Elem()
	if e.Kind() != reflect.Struct {
		return false
	}
	f := e.FieldByName(fieldName)
	if !f.IsValid() || !f.CanSet() {
		return false
	}
	if f.Kind() != reflect.String {
		return false
	}
	f.SetString(value)
	return true
}

func RunDevContainer(ctx context.Context, cli *client.Client, opts RunOptions) (*RunResult, error) {
	res, err := CreateDevContainer(ctx, cli, opts)
	if err != nil {
		return nil, err
	}
	if err := cli.ContainerStart(ctx, res.ContainerID, container.StartOptions{}); err != nil {
		return nil, fmt.Errorf("container start: %w", err)
	}
	return res, nil
}

func StartExistingContainer(ctx context.Context, cli *client.Client, containerRef string) (*RunResult, error) {
	if strings.TrimSpace(containerRef) == "" {
		return nil, fmt.Errorf("container ref is required")
	}
	ins, err := cli.ContainerInspect(ctx, containerRef)
	if err != nil {
		return nil, fmt.Errorf("container inspect: %w", err)
	}
	if err := cli.ContainerStart(ctx, ins.ID, container.StartOptions{}); err != nil {
		return nil, fmt.Errorf("container start: %w", err)
	}
	name := strings.TrimPrefix(ins.Name, "/")
	if name == "" {
		name = ins.ID
	}
	imageName := ""
	if ins.Config != nil {
		imageName = ins.Config.Image
	}
	return &RunResult{
		ContainerID:   ins.ID,
		ContainerName: name,
		ImageName:     imageName,
	}, nil
}
