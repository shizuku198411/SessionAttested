package docker

import (
	"context"
	"fmt"
	"io"
	"strings"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

func ExecShell(ctx context.Context, cli *client.Client, containerID, shellCmd string) error {
	return execShellWithUser(ctx, cli, containerID, "", shellCmd)
}

func ExecShellAsUser(ctx context.Context, cli *client.Client, containerID, user, shellCmd string) error {
	return execShellWithUser(ctx, cli, containerID, user, shellCmd)
}

func execShellWithUser(ctx context.Context, cli *client.Client, containerID, user, shellCmd string) error {
	if containerID == "" {
		return fmt.Errorf("containerID is empty")
	}
	opts := container.ExecOptions{
		AttachStdout: true,
		AttachStderr: true,
		Cmd:          []string{"/bin/sh", "-lc", shellCmd},
	}
	if strings.TrimSpace(user) != "" {
		opts.User = user
	}
	execResp, err := cli.ContainerExecCreate(ctx, containerID, opts)
	if err != nil {
		return fmt.Errorf("container exec create: %w", err)
	}
	attach, err := cli.ContainerExecAttach(ctx, execResp.ID, container.ExecAttachOptions{})
	if err != nil {
		return fmt.Errorf("container exec attach: %w", err)
	}
	defer attach.Close()
	_, _ = io.Copy(io.Discard, attach.Reader)

	ins, err := cli.ContainerExecInspect(ctx, execResp.ID)
	if err != nil {
		return fmt.Errorf("container exec inspect: %w", err)
	}
	if ins.ExitCode != 0 {
		return fmt.Errorf("container exec exit code: %d", ins.ExitCode)
	}
	return nil
}

func InjectSessionEnv(ctx context.Context, cli *client.Client, containerID, sessionID, stateDir, workspaceContainer, workspaceHost string) error {
	if sessionID == "" {
		return fmt.Errorf("sessionID is empty")
	}
	if stateDir == "" {
		return fmt.Errorf("stateDir is empty")
	}
	if workspaceContainer == "" {
		return fmt.Errorf("workspaceContainer is empty")
	}
	// sessionID is hex-generated in this project; safe to embed directly.
	cmd := fmt.Sprintf(`
set -eu
mkdir -p /etc/profile.d
cat >/etc/profile.d/attested-session.sh <<'EOF'
export ATTESTED_SESSION_ID=%s
export ATTESTED_STATE_DIR=%s
export ATTESTED_WORKSPACE_CONTAINER_PATH=%s
export ATTESTED_WORKSPACE_HOST_PATH=%s
EOF
chmod 0644 /etc/profile.d/attested-session.sh
if [ -f /etc/environment ]; then
  grep -v '^ATTESTED_SESSION_ID=' /etc/environment | grep -v '^ATTESTED_STATE_DIR=' | grep -v '^ATTESTED_WORKSPACE_CONTAINER_PATH=' | grep -v '^ATTESTED_WORKSPACE_HOST_PATH=' > /tmp/.attested_env.$$ || true
  mv /tmp/.attested_env.$$ /etc/environment
fi
printf 'ATTESTED_SESSION_ID=%s\n' >> /etc/environment
printf 'ATTESTED_STATE_DIR=%s\n' >> /etc/environment
printf 'ATTESTED_WORKSPACE_CONTAINER_PATH=%s\n' >> /etc/environment
printf 'ATTESTED_WORKSPACE_HOST_PATH=%s\n' >> /etc/environment
	`, sessionID, stateDir, workspaceContainer, workspaceHost, sessionID, stateDir, workspaceContainer, workspaceHost)
	return ExecShell(ctx, cli, containerID, cmd)
}

type DevGitSetupOptions struct {
	UserName            string
	UserEmail           string
	GitHubSSHKeyPath    string
	GitHubSSHConfigPath string
	DevUser             string
	DevHome             string
}

func ConfigureDevGit(ctx context.Context, cli *client.Client, containerID string, opts DevGitSetupOptions) error {
	devUser := strings.TrimSpace(opts.DevUser)
	if devUser == "" {
		devUser = "dev"
	}
	devHome := strings.TrimSpace(opts.DevHome)
	if devHome == "" {
		devHome = "/home/" + devUser
	}

	if strings.TrimSpace(opts.UserName) != "" || strings.TrimSpace(opts.UserEmail) != "" {
		var lines []string
		lines = append(lines, "set -eu")
		lines = append(lines, "export HOME="+shSingleQuote(devHome))
		if strings.TrimSpace(opts.UserName) != "" {
			lines = append(lines, "git config --global user.name "+shSingleQuote(opts.UserName))
		}
		if strings.TrimSpace(opts.UserEmail) != "" {
			lines = append(lines, "git config --global user.email "+shSingleQuote(opts.UserEmail))
		}
		if err := ExecShellAsUser(ctx, cli, containerID, devUser, strings.Join(lines, "\n")); err != nil {
			return fmt.Errorf("configure git user for %s: %w", devUser, err)
		}
	}

	if strings.TrimSpace(opts.GitHubSSHKeyPath) != "" {
		cfgPath := strings.TrimSpace(opts.GitHubSSHConfigPath)
		if cfgPath == "" {
			cfgPath = devHome + "/.ssh/config"
		}
		cfgDir := cfgPath
		if i := strings.LastIndex(cfgDir, "/"); i >= 0 {
			cfgDir = cfgDir[:i]
		}
		keyPath := strings.TrimSpace(opts.GitHubSSHKeyPath)
		cmd := fmt.Sprintf(`
set -eu
mkdir -p %s
cat >%s <<'EOF'
Host github.com
  HostName github.com
  User git
  IdentityFile %s
  IdentitiesOnly yes
  StrictHostKeyChecking accept-new
EOF
chmod 0700 %s
chmod 0600 %s
if getent passwd %s >/dev/null 2>&1; then
  grp="$(id -gn %s 2>/dev/null || true)"
  if [ -n "$grp" ]; then
    chown %s:"$grp" %s
    chown %s:"$grp" %s
  else
    chown %s %s
    chown %s %s
  fi
fi
`,
			shSingleQuote(cfgDir),
			shSingleQuote(cfgPath),
			keyPath,
			shSingleQuote(cfgDir),
			shSingleQuote(cfgPath),
			shSingleQuote(devUser),
			shSingleQuote(devUser),
			shSingleQuote(devUser),
			shSingleQuote(cfgDir),
			shSingleQuote(devUser),
			shSingleQuote(cfgPath),
			shSingleQuote(devUser),
			shSingleQuote(cfgDir),
			shSingleQuote(devUser),
			shSingleQuote(cfgPath),
		)
		if err := ExecShell(ctx, cli, containerID, cmd); err != nil {
			return fmt.Errorf("configure github ssh for %s: %w", devUser, err)
		}
	}

	return nil
}

func shSingleQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'"'"'`) + "'"
}
