package docker

import (
	"archive/tar"
	"bytes"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

type BuildOptions struct {
	Tag        string
	ContextDir string
	Dockerfile string
	Pull       bool
	BuildArgs  []string // repeatable: KEY=VALUE
}

func BuildImage(ctx context.Context, cli *client.Client, opts BuildOptions) (string, error) {
	if opts.Tag == "" {
		return "", fmt.Errorf("build tag is required")
	}
	if opts.ContextDir == "" {
		return "", fmt.Errorf("build context dir is required")
	}
	if opts.Dockerfile == "" {
		opts.Dockerfile = "Dockerfile"
	}

	ctxTar, err := makeBuildContextTar(opts.ContextDir)
	if err != nil {
		return "", fmt.Errorf("build context tar: %w", err)
	}

	buildArgs, err := toBuildArgsMap(opts.BuildArgs)
	if err != nil {
		return "", err
	}

	rc, err := cli.ImageBuild(ctx, bytes.NewReader(ctxTar), types.ImageBuildOptions{
		Tags:       []string{opts.Tag},
		Dockerfile: opts.Dockerfile,
		Remove:     true,
		PullParent: opts.Pull,
		BuildArgs:  buildArgs,
	})
	if err != nil {
		return "", fmt.Errorf("image build: %w", err)
	}
	defer rc.Body.Close()
	_, _ = io.Copy(io.Discard, rc.Body)

	digest, err := EnsureImage(ctx, cli, opts.Tag, false)
	if err != nil {
		return "", err
	}
	return digest, nil
}

func toBuildArgsMap(args []string) (map[string]*string, error) {
	if len(args) == 0 {
		return nil, nil
	}
	out := make(map[string]*string, len(args))
	for _, a := range args {
		k, v, ok := strings.Cut(a, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("invalid build arg %q (expected KEY=VALUE)", a)
		}
		val := v
		out[k] = &val
	}
	return out, nil
}

func makeBuildContextTar(root string) ([]byte, error) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	defer tw.Close()

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return nil
		}

		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		rel = strings.TrimPrefix(rel, "./")

		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = rel
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(tw, f)
		_ = f.Close()
		return copyErr
	})
	if err != nil {
		return nil, err
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
