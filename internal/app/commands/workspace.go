package commands

import (
	"bufio"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"session-attested/internal/docker"
	"session-attested/internal/state"
)

type workspaceInitOut struct {
	WorkspaceID   string `json:"workspace_id"`
	WorkspaceMeta string `json:"workspace_meta"`
	WorkspaceHost string `json:"workspace_host"`
	ContainerID   string `json:"container_id"`
	ContainerName string `json:"container_name,omitempty"`
	Created       bool   `json:"created"`
}

type workspaceRmOut struct {
	WorkspaceID      string `json:"workspace_id"`
	WorkspaceMeta    string `json:"workspace_meta"`
	RemovedContainer bool   `json:"removed_container"`
	RemovedMeta      bool   `json:"removed_meta"`
}

func RunWorkspaceInit(args []string) int {
	resolved, err := applyConfigDefaultsMulti([]string{"start", "workspace_init"}, args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	args = resolved
	presentFlags := parsePresentFlags(args)

	fs := flag.NewFlagSet("workspace init", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	stateDir := fs.String("state-dir", state.DefaultStateDir().Root, "state dir")
	workspaceID := fs.String("workspace-id", "", "workspace id (default: --name or basename of --workspace-host)")
	workspaceHost := fs.String("workspace-host", "", "workspace host path (required)")
	jsonOut := fs.Bool("json", false, "output JSON")

	image := fs.String("image", "", "docker image (required)")
	name := fs.String("name", "", "docker container name (required for reusable workspace)")
	pull := fs.Bool("pull", false, "pull image before create")
	build := fs.Bool("build", false, "build image before create")
	_ = fs.Bool("reuse-container", false, "ignored in workspace init")
	buildContext := fs.String("build-context", "", "docker build context dir (default: --workspace-host)")
	dockerfile := fs.String("dockerfile", "Dockerfile", "dockerfile path in build context")
	_ = fs.Bool("auto-collect", false, "ignored in workspace init")
	_ = fs.Bool("auto-collect-sudo", true, "ignored in workspace init")
	_ = fs.String("auto-collect-wait", "", "ignored in workspace init")
	_ = fs.String("auto-collect-log", "", "ignored in workspace init")
	_ = fs.Bool("inject-session-env", true, "ignored in workspace init")
	cgroupParent := fs.String("cgroup-parent", "", "docker cgroup parent (optional)")
	mountAttestedBin := fs.Bool("mount-attested-bin", false, "bind-mount host attested binary into container")
	attestedBinHostPath := fs.String("attested-bin-host-path", "", "host path to attested binary (default: current executable)")
	attestedBinContainerPath := fs.String("attested-bin-container-path", "/usr/local/bin/attested", "container path for mounted attested binary")
	gitUserName := fs.String("git-user-name", "", "git user.name to write into generated attest/attested.yaml (optional)")
	gitUserEmail := fs.String("git-user-email", "", "git user.email to write into generated attest/attested.yaml (optional)")
	repo := fs.String("repo", "", "GitHub repo slug (owner/name) to write into generated attest/attested.yaml (optional)")
	scaffold := fs.Bool("scaffold", true, "generate workspace scaffolding (.gitignore, attest/attested.yaml, attest/Dockerfile, attest/policy.yaml)")
	scaffoldForce := fs.Bool("scaffold-force", false, "overwrite existing scaffold files")
	scaffoldInteractive := fs.Bool("scaffold-interactive", true, "prompt for scaffold values (workspace fields + repo/git user) if not provided")
	gitSSHKeyHostPath := fs.String("git-ssh-key-host-path", "", "host path to SSH private key for github.com (mounted read-only into container)")
	gitSSHKeyContainerPath := fs.String("git-ssh-key-container-path", "/home/dev/.ssh/id_github_attested", "container path for mounted SSH private key")
	var envs stringSlice
	var publish stringSlice
	var buildArgs stringSlice
	fs.Var(&envs, "env", "env var (repeatable), e.g. --env K=V")
	fs.Var(&publish, "publish", "port publish (repeatable), e.g. --publish 127.0.0.1:2222:22/tcp")
	fs.Var(&buildArgs, "build-arg", "docker build arg (repeatable), e.g. --build-arg DEV_UID=1000")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *scaffoldInteractive {
		in := bufio.NewReader(os.Stdin)
		if strings.TrimSpace(*workspaceID) == "" {
			*workspaceID = promptLine(in, "workspace name (workspace-id): ")
		}
		if strings.TrimSpace(*workspaceHost) == "" {
			cwd, _ := os.Getwd()
			v := promptLine(in, fmt.Sprintf("workspace path (workspace-host) [%s]: ", cwd))
			if strings.TrimSpace(v) == "" {
				*workspaceHost = cwd
			} else {
				*workspaceHost = v
			}
		}
		if strings.TrimSpace(*image) == "" {
			v := promptLine(in, "docker image [ubuntu:latest]: ")
			if strings.TrimSpace(v) == "" {
				*image = "ubuntu:latest"
			} else {
				*image = v
			}
		}
		if !presentFlags["build"] && !presentFlags["pull"] {
			choice := strings.ToLower(strings.TrimSpace(promptLine(in, "is the image need build or pull? [pull|build] (default: pull): ")))
			switch choice {
			case "build":
				*build = true
				*pull = false
			case "pull", "":
				*pull = true
				*build = false
			default:
				fmt.Fprintf(os.Stderr, "warn: unknown choice %q; defaulting to pull\n", choice)
				*pull = true
				*build = false
			}
		}
		if strings.TrimSpace(*gitSSHKeyHostPath) == "" {
			ans := strings.ToLower(strings.TrimSpace(promptLine(in, "mount host git ssh key into container? [y/N]: ")))
			if ans == "y" || ans == "yes" {
				defKey := detectDefaultSSHKeyPath()
				msg := "host ssh private key path"
				if defKey != "" {
					msg += " [" + defKey + "]"
				}
				msg += ": "
				v := promptLine(in, msg)
				if strings.TrimSpace(v) == "" {
					v = defKey
				}
				*gitSSHKeyHostPath = strings.TrimSpace(v)
				if strings.TrimSpace(*gitSSHKeyContainerPath) == "" {
					*gitSSHKeyContainerPath = "/home/dev/.ssh/id_github_attested"
				}
			}
		}
	}

	if strings.TrimSpace(*workspaceHost) == "" {
		cwd, _ := os.Getwd()
		if cwd != "" {
			*workspaceHost = cwd
		}
	}
	if strings.TrimSpace(*image) == "" {
		*image = "ubuntu:latest"
	}

	wid := strings.TrimSpace(*workspaceID)
	if wid == "" {
		if strings.TrimSpace(*workspaceHost) != "" {
			wid = filepath.Base(filepath.Clean(*workspaceHost))
		}
	}
	if wid == "" || wid == "." || wid == "/" {
		fmt.Fprintln(os.Stderr, "error: could not determine workspace id")
		return 2
	}
	*workspaceID = wid

	if strings.TrimSpace(*name) == "" {
		*name = sanitizeName(wid) + "-dev"
	}
	if strings.TrimSpace(*workspaceHost) == "" {
		fmt.Fprintln(os.Stderr, "error: --workspace-host is required")
		return 2
	}
	if strings.TrimSpace(*image) == "" {
		fmt.Fprintln(os.Stderr, "error: --image is required")
		return 2
	}
	if strings.TrimSpace(*name) == "" {
		fmt.Fprintln(os.Stderr, "error: --name is required (workspace reuse requires a stable container name)")
		return 2
	}

	// For workspace init, default state dir to workspace-local .attest_run/state unless
	// explicitly provided via CLI/config. This avoids /var defaults for first-time users.
	if !presentFlags["state-dir"] {
		*stateDir = filepath.Join(*workspaceHost, ".attest_run", "state")
	}
	if !presentFlags["mount-attested-bin"] {
		// First-time workspace init should mount the host attested binary by default so
		// the user can run `attested` inside the dev container immediately.
		*mountAttestedBin = true
	}
	if len(publish) == 0 {
		// First-time interactive workspace init should produce an SSH-reachable dev container
		// without requiring the user to know/passa --publish explicitly.
		publish = append(publish, "0.0.0.0:2222:22/tcp")
	}
	hostUID, hostGID := currentShellUIDGID()
	buildArgList := []string(buildArgs)
	buildArgList = upsertBuildArg(buildArgList, "DEV_UID", fmt.Sprintf("%d", hostUID))
	buildArgList = upsertBuildArg(buildArgList, "DEV_GID", fmt.Sprintf("%d", hostGID))
	buildArgs = stringSlice(buildArgList)

	st := state.StateDir{Root: *stateDir}
	if err := os.MkdirAll(st.WorkspaceMetaDir(), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "error: mkdir workspace meta dir:", err)
		return 3
	}
	if err := os.MkdirAll(*workspaceHost, 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "error: mkdir workspace:", err)
		return 3
	}

	var scaffoldOut *workspaceScaffoldResult
	if *scaffold {
		req := workspaceScaffoldRequest{
			WorkspaceID:           wid,
			WorkspaceHost:         *workspaceHost,
			StateDir:              *stateDir,
			Image:                 *image,
			ContainerName:         *name,
			Build:                 *build,
			Pull:                  *pull,
			BuildContext:          *buildContext,
			Dockerfile:            *dockerfile,
			Publish:               []string(publish),
			MountAttestedBin:      *mountAttestedBin,
			AttestedBinHostPath:   *attestedBinHostPath,
			AttestedBinContPath:   *attestedBinContainerPath,
			GitSSHKeyHostPath:     *gitSSHKeyHostPath,
			GitSSHKeyContPath:     *gitSSHKeyContainerPath,
			GitUserName:           strings.TrimSpace(*gitUserName),
			GitUserEmail:          strings.TrimSpace(*gitUserEmail),
			Repo:                  strings.TrimSpace(*repo),
			HostUID:               hostUID,
			HostGID:               hostGID,
			Force:                 *scaffoldForce,
			Interactive:           *scaffoldInteractive,
			PromptInput:           bufio.NewReader(os.Stdin),
			UseRelativeWorkspace:  true,
			UseRelativeOutputPath: true,
		}
		out, err := generateWorkspaceScaffold(req)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: generate workspace scaffold:", err)
			return 3
		}
		scaffoldOut = &out

		// If build is requested and the default Dockerfile path is used, prefer the scaffolded
		// template under attest/ so the first workspace init works without extra flags.
		if *build && strings.TrimSpace(*dockerfile) == "Dockerfile" {
			rootDF := filepath.Join(*workspaceHost, "Dockerfile")
			attestDF := filepath.Join(*workspaceHost, "attest", "Dockerfile")
			if _, errRoot := os.Stat(rootDF); os.IsNotExist(errRoot) {
				if _, errAttest := os.Stat(attestDF); errAttest == nil {
					*dockerfile = filepath.Join("attest", "Dockerfile")
				}
			}
		}
	}

	cli, err := docker.NewClient()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: docker client:", err)
		return 3
	}
	if err := docker.Ping(context.Background(), cli); err != nil {
		fmt.Fprintln(os.Stderr, "error: docker daemon not reachable:", err)
		return 3
	}

	extraMounts, err := buildExtraContainerMounts(*mountAttestedBin, *attestedBinHostPath, *attestedBinContainerPath, *gitSSHKeyHostPath, *gitSSHKeyContainerPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}

	created := false
	var runRes *docker.RunResult
	existsCtr, err := docker.Exists(context.Background(), cli, *name)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: inspect container:", err)
		return 3
	}
	if existsCtr {
		runRes, err = docker.StartExistingContainer(context.Background(), cli, *name)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: start existing container:", err)
			return 3
		}
		_ = docker.Stop(context.Background(), cli, runRes.ContainerID)
	} else {
		existsImg, err := docker.ImageExists(context.Background(), cli, *image)
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: inspect image:", err)
			return 3
		}
		if !existsImg && *build {
			ctxDir := *buildContext
			if ctxDir == "" {
				ctxDir = *workspaceHost
			}
			if _, err := os.Stat(filepath.Join(ctxDir, *dockerfile)); err != nil {
				fmt.Fprintln(os.Stderr, "error: dockerfile not found:", err)
				return 2
			}
			if _, err := docker.BuildImage(context.Background(), cli, docker.BuildOptions{
				Tag:        *image,
				ContextDir: ctxDir,
				Dockerfile: *dockerfile,
				Pull:       *pull,
				BuildArgs:  []string(buildArgs),
			}); err != nil {
				fmt.Fprintln(os.Stderr, "error: docker build:", err)
				return 3
			}
		}
		if !existsImg && !*build && *pull {
			if _, err := docker.EnsureImage(context.Background(), cli, *image, true); err != nil {
				fmt.Fprintln(os.Stderr, "error: docker pull:", err)
				return 3
			}
		}
		if !existsImg && !*build && !*pull {
			fmt.Fprintln(os.Stderr, "error: image not found locally; set --pull or --build")
			return 2
		}

		runRes, err = docker.CreateDevContainer(context.Background(), cli, docker.RunOptions{
			Image:                  *image,
			Name:                   *name,
			WorkspaceHostPath:      *workspaceHost,
			WorkspaceContainerPath: "/workspace",
			Env:                    []string(envs),
			Publish:                []string(publish),
			Pull:                   false,
			CgroupParent:           *cgroupParent,
			TTY:                    true,
			Stdin:                  false,
			Labels: map[string]string{
				"attested.workspace_id": wid,
				"attested.managed":      "true",
			},
			ExtraMounts: extraMounts,
		})
		if err != nil {
			fmt.Fprintln(os.Stderr, "error: docker create:", err)
			return 3
		}
		created = true
	}

	var wm state.WorkspaceMeta
	wm.WorkspaceID = wid
	wm.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	wm.Workspace.HostPath = *workspaceHost
	wm.Workspace.ContainerPath = "/workspace"
	wm.Docker.ContainerID = runRes.ContainerID
	wm.Docker.ContainerName = runRes.ContainerName
	wm.Docker.Image = runRes.ImageName
	wm.Docker.ImageDigest = runRes.ImageDigest
	metaPath := st.WorkspaceMetaPath(wid)
	if err := state.WriteJSON(metaPath, wm, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "error: write workspace meta:", err)
		return 3
	}

	out := workspaceInitOut{
		WorkspaceID:   wid,
		WorkspaceMeta: metaPath,
		WorkspaceHost: *workspaceHost,
		ContainerID:   runRes.ContainerID,
		ContainerName: runRes.ContainerName,
		Created:       created,
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(out)
		return 0
	}
	fmt.Printf("workspace_id: %s\n", out.WorkspaceID)
	fmt.Printf("workspace_meta: %s\n", out.WorkspaceMeta)
	fmt.Printf("workspace_host: %s\n", out.WorkspaceHost)
	fmt.Printf("container_id: %s\n", out.ContainerID)
	fmt.Printf("container_name: %s\n", out.ContainerName)
	fmt.Printf("created: %v\n", out.Created)
	fmt.Println("state: container is created/registered and left stopped")
	if scaffoldOut != nil {
		fmt.Println("scaffold:")
		for _, p := range scaffoldOut.CreatedPaths {
			fmt.Printf("  created: %s\n", p)
		}
		for _, p := range scaffoldOut.SkippedPaths {
			fmt.Printf("  skipped(existing): %s\n", p)
		}
	}
	return 0
}

func RunWorkspaceRm(args []string) int {
	resolved, err := applyConfigDefaults("workspace_rm", args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	args = resolved
	presentFlags := parsePresentFlags(args)

	fs := flag.NewFlagSet("workspace rm", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	stateDir := fs.String("state-dir", state.DefaultStateDir().Root, "state dir")
	workspaceID := fs.String("workspace-id", "", "workspace id")
	jsonOut := fs.Bool("json", false, "output JSON")
	removeWorkspaceHost := fs.Bool("remove-workspace-host", false, "also remove workspace host directory (dangerous; best effort)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if !presentFlags["state-dir"] {
		*stateDir = filepath.Join(".attest_run", "state")
	}
	if strings.TrimSpace(*workspaceID) == "" {
		fmt.Fprintln(os.Stderr, "error: --workspace-id is required")
		return 2
	}
	st := state.StateDir{Root: *stateDir}
	metaPath := st.WorkspaceMetaPath(*workspaceID)

	var wm state.WorkspaceMeta
	if err := state.ReadJSON(metaPath, &wm); err != nil {
		fmt.Fprintln(os.Stderr, "error: workspace meta not found:", err)
		return 4
	}

	removedContainer := false
	if strings.TrimSpace(wm.Docker.ContainerID) != "" {
		cli, err := docker.NewClient()
		if err == nil {
			_ = docker.StopAndRemove(context.Background(), cli, wm.Docker.ContainerID)
			removedContainer = true
		}
	}

	removedMeta := false
	if err := os.Remove(metaPath); err == nil {
		removedMeta = true
	}
	if *removeWorkspaceHost && strings.TrimSpace(wm.Workspace.HostPath) != "" {
		_ = os.RemoveAll(wm.Workspace.HostPath)
	}

	out := workspaceRmOut{
		WorkspaceID:      *workspaceID,
		WorkspaceMeta:    metaPath,
		RemovedContainer: removedContainer,
		RemovedMeta:      removedMeta,
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(out)
		return 0
	}
	fmt.Printf("workspace_id: %s\n", out.WorkspaceID)
	fmt.Printf("removed_container: %v\n", out.RemovedContainer)
	fmt.Printf("removed_meta: %v\n", out.RemovedMeta)
	if *removeWorkspaceHost {
		fmt.Printf("removed_workspace_host: best-effort (%s)\n", wm.Workspace.HostPath)
	}
	return 0
}
