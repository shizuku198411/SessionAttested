package commands

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"session-attested/internal/state"
)

type commitOut struct {
	SessionID          string `json:"session_id"`
	RepoPath           string `json:"repo_path"`
	CommitSHA          string `json:"commit_sha"`
	ParentSHA          string `json:"parent_sha,omitempty"`
	CommitBindingPath  string `json:"commit_binding_path"`
	CommitBindingsPath string `json:"commit_bindings_path,omitempty"`
}

var commitSHARe = regexp.MustCompile(`^[0-9a-f]{40}$`)

func RunCommit(args []string) int {
	resolved, err := applyConfigDefaults("commit", args)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 2
	}
	args = resolved

	fs := flag.NewFlagSet("commit", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	sessionID := fs.String("session", "", "session id")
	stateDir := fs.String("state-dir", state.DefaultStateDir().Root, "state dir")
	repoPath := fs.String("repo-path", "", "git repository path (default: workspace host path from session meta)")
	message := fs.String("message", "", "commit message")
	allowEmpty := fs.Bool("allow-empty", false, "allow empty commit")
	jsonOut := fs.Bool("json", false, "output JSON")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *sessionID == "" {
		if sid := strings.TrimSpace(os.Getenv("ATTESTED_SESSION_ID")); sid != "" {
			*sessionID = sid
		}
	}
	if *sessionID == "" {
		if sid, ok := readLastSessionID(); ok {
			*sessionID = sid
		}
	}
	if *stateDir == state.DefaultStateDir().Root {
		if s := strings.TrimSpace(os.Getenv("ATTESTED_STATE_DIR")); s != "" {
			*stateDir = s
		}
	}
	if *sessionID == "" && *message == "" {
		fmt.Fprintln(os.Stderr, "error: --session (or ATTESTED_SESSION_ID) and --message are required")
		return 2
	}
	if *sessionID == "" {
		fmt.Fprintln(os.Stderr, "error: --session is required (or set ATTESTED_SESSION_ID)")
		return 2
	}
	if *message == "" {
		fmt.Fprintln(os.Stderr, "error: --message is required")
		return 2
	}

	st := state.StateDir{Root: *stateDir}
	var meta state.SessionMeta
	if err := state.ReadJSON(st.MetaPath(*sessionID), &meta); err != nil {
		fmt.Fprintln(os.Stderr, "error: read meta:", err)
		return 4
	}

	repo := *repoPath
	if repo == "" {
		repo = meta.Workspace.HostPath
	}
	if fixed, ok := resolveRepoPathForRuntime(repo, &meta); ok {
		repo = fixed
	}
	if err := ensureGitRepo(repo); err != nil {
		// Fallback: current working dir inside dev container
		if cwd, cwdErr := os.Getwd(); cwdErr == nil && cwd != "" && cwd != repo {
			if err2 := ensureGitRepo(cwd); err2 == nil {
				repo = cwd
			} else {
				fmt.Fprintln(os.Stderr, "error:", err)
				return 2
			}
		} else {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 2
		}
	}

	parent, err := gitOutput(repo, "rev-parse", "HEAD")
	if err != nil {
		parent = ""
	}

	gitOut := io.Writer(os.Stdout)
	gitErr := io.Writer(os.Stderr)
	if *jsonOut {
		// Keep stdout clean for machine-readable JSON output.
		gitOut = os.Stderr
	}

	commitArgs := []string{"commit", "-m", *message}
	if *allowEmpty {
		commitArgs = append(commitArgs, "--allow-empty")
	}
	if err := runGit(repo, gitOut, gitErr, commitArgs...); err != nil {
		fmt.Fprintln(os.Stderr, "error: git commit:", err)
		return 3
	}

	sha, err := gitOutput(repo, "rev-parse", "HEAD")
	if err != nil {
		fmt.Fprintln(os.Stderr, "error: resolve commit sha:", err)
		return 3
	}
	if !commitSHARe.MatchString(sha) {
		fmt.Fprintln(os.Stderr, "error: invalid commit sha:", sha)
		return 3
	}

	binding := state.CommitBinding{
		SessionID:      *sessionID,
		CommitSHA:      sha,
		ParentSHA:      parent,
		RepoPath:       repo,
		CreatedRFC3339: time.Now().UTC().Format(time.RFC3339),
	}
	bindingPath := st.CommitBindingPath(*sessionID)
	if err := state.WriteJSON(bindingPath, &binding, 0o644); err != nil {
		fmt.Fprintln(os.Stderr, "error: write commit binding:", err)
		return 3
	}
	bindingsPath := st.CommitBindingsPath(*sessionID)
	if err := state.AppendCommitBindingJSONL(bindingsPath, binding); err != nil {
		fmt.Fprintln(os.Stderr, "error: append commit binding history:", err)
		return 3
	}

	out := commitOut{
		SessionID:          *sessionID,
		RepoPath:           repo,
		CommitSHA:          sha,
		ParentSHA:          parent,
		CommitBindingPath:  bindingPath,
		CommitBindingsPath: bindingsPath,
	}
	if *jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(out)
		return 0
	}

	fmt.Println("committed")
	fmt.Println("repo_path:", out.RepoPath)
	fmt.Println("commit_sha:", out.CommitSHA)
	if out.ParentSHA != "" {
		fmt.Println("parent_sha:", out.ParentSHA)
	}
	fmt.Println("binding:", out.CommitBindingPath)
	fmt.Println("bindings:", out.CommitBindingsPath)
	return 0
}

func ensureGitRepo(repo string) error {
	out, err := gitOutput(repo, "rev-parse", "--is-inside-work-tree")
	if err != nil {
		return fmt.Errorf("not a git repository: %s", repo)
	}
	if strings.TrimSpace(out) != "true" {
		return fmt.Errorf("not inside git work tree: %s", repo)
	}
	return nil
}

func runGit(repo string, stdout, stderr io.Writer, args ...string) error {
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

func gitOutput(repo string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", repo}, args...)...)
	b, err := cmd.Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(b)), nil
}

func resolveRepoPathForRuntime(repo string, meta *state.SessionMeta) (string, bool) {
	if strings.TrimSpace(repo) == "" {
		return "", false
	}
	hostWS := strings.TrimSpace(os.Getenv("ATTESTED_WORKSPACE_HOST_PATH"))
	containerWS := strings.TrimSpace(os.Getenv("ATTESTED_WORKSPACE_CONTAINER_PATH"))
	if hostWS == "" || containerWS == "" {
		return "", false
	}

	cleanRepo := filepath.Clean(repo)
	cleanHost := filepath.Clean(hostWS)
	if cleanRepo == cleanHost {
		return containerWS, true
	}
	rel, err := filepath.Rel(cleanHost, cleanRepo)
	if err != nil {
		return "", false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	if rel == "." {
		return containerWS, true
	}
	return filepath.ToSlash(filepath.Join(containerWS, rel)), true
}
