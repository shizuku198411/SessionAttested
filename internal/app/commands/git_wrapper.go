package commands

import (
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
)

func RunGitWrapper(args []string) int {
	if len(args) > 0 && args[0] == "commit" {
		// Delegate to attested commit (creates commit binding), while accepting git-like flags.
		return RunCommit(normalizeGitCommitArgs(args[1:]))
	}

	fs := flag.NewFlagSet("git", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	repoPath := fs.String("repo-path", ".", "git repository path (default: current directory)")

	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "error: git subcommand is required (add/status/push/branch)")
		return 2
	}

	sub := rest[0]
	if !isAllowedGitSubcommand(sub) {
		fmt.Fprintln(os.Stderr, "error: unsupported git subcommand for wrapper:", sub)
		fmt.Fprintln(os.Stderr, "allowed: add, status, push, branch, init, commit")
		return 2
	}

	cmd := exec.Command("git", append([]string{"-C", *repoPath}, rest...)...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return ee.ExitCode()
		}
		fmt.Fprintln(os.Stderr, "error: git wrapper:", err)
		return 3
	}
	return 0
}

func normalizeGitCommitArgs(args []string) []string {
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-m":
			out = append(out, "--message")
		case strings.HasPrefix(a, "-m="):
			out = append(out, "--message="+strings.TrimPrefix(a, "-m="))
		default:
			out = append(out, a)
		}
	}
	return out
}

func isAllowedGitSubcommand(s string) bool {
	switch s {
	case "add", "status", "push", "branch", "init":
		return true
	default:
		return false
	}
}
