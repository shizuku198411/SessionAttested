package main

import (
	"fmt"
	"os"

	"session-attested/internal/app/commands"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "policy":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		switch os.Args[2] {
		case "hash":
			code := commands.RunPolicyHash(os.Args[3:])
			os.Exit(code)
		case "candidates":
			code := commands.RunPolicyCandidates(os.Args[3:])
			os.Exit(code)
		default:
			usage()
			os.Exit(2)
		}

	case "verify":
		code := commands.RunVerify(os.Args[2:])
		os.Exit(code)

	case "workspace":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		switch os.Args[2] {
		case "init":
			code := commands.RunWorkspaceInit(os.Args[3:])
			os.Exit(code)
		case "rm":
			code := commands.RunWorkspaceRm(os.Args[3:])
			os.Exit(code)
		default:
			usage()
			os.Exit(2)
		}

	case "attest":
		code := commands.RunAttest(os.Args[2:])
		os.Exit(code)

	case "start":
		code := commands.RunStart(os.Args[2:])
		os.Exit(code)

	case "stop":
		code := commands.RunStop(os.Args[2:])
		os.Exit(code)

	case "status":
		code := commands.RunStatus(os.Args[2:])
		os.Exit(code)

	case "collect":
		code := commands.RunCollect(os.Args[2:])
		os.Exit(code)

	case "commit":
		code := commands.RunCommit(os.Args[2:])
		os.Exit(code)

	case "git":
		code := commands.RunGitWrapper(os.Args[2:])
		os.Exit(code)

	default:
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `attested (PoC)

Usage:
  attested policy hash --policy <path> [--config <yaml>] [--profile <name>] [--json]
  attested policy candidates --session <id> [--state-dir <dir>] [--out <path>] [--include-git] [--include-attested] [--include-exec] [--json]
  attested workspace init --workspace-id <id> --workspace-host <dir> --name <container> --image <image> [--build|--pull] [--scaffold[=true|false]] [--scaffold-force] [--scaffold-interactive] [--repo <owner/name>] [start-compatible options...] [--state-dir <dir>] [--config <yaml>] [--profile <name>] [--json]
  attested workspace rm --workspace-id <id> [--remove-workspace-host] [--state-dir <dir>] [--json]
  attested verify --attestation <path> --signature <path> [--public-key <path>] [--policy <path>] [--binding <path>] [--require-pass] [--write-result] [--result-file <path>] [--config <yaml>] [--profile <name>] [--json]
  attested attest --session <id> --repo <owner/name> [--commit <40hex>] --policy <path> --out <dir> --signing-key <pem> [--use-binding] [--key-id <id>] [--issuer-name <name>] [--state-dir <dir>] [--config <yaml>] [--profile <name>] [--json]
  attested start --image <image> [--name <name>] [--reuse-container] [--pull] [--build] [--build-context <dir>] [--dockerfile <path>] [--build-arg K=V ...] [--auto-collect] [--auto-collect-sudo] [--auto-collect-wait 5s] [--auto-collect-log <path>] [--inject-session-env] [--mount-attested-bin] [--attested-bin-host-path <path>] [--attested-bin-container-path <path>] [--git-user-name <name>] [--git-user-email <email>] [--git-ssh-key-host-path <path>] [--git-ssh-key-container-path <path>] [--env K=V ...] [--publish HOST:CONT[/tcp|udp] ...] [--cgroup-parent <path>] [--state-dir <dir>] [--workspace-host <dir>] [--config <yaml>] [--profile <name>] [--json]
  attested stop --session <id> [--keep-container] [--run-attest] [--run-verify] [--verify-write-result] [--state-dir <dir>] [--collector-wait 15s] [--config <yaml>] [--profile <name>] [--json]
  attested status --session <id> [--state-dir <dir>] [--config <yaml>] [--profile <name>] [--json]
  attested collect --session <id> [--state-dir <dir>] [--duration 30s | --until-stop] [--poll 300ms] [--config <yaml>] [--profile <name>]
  attested commit --session <id> --message <msg> [--repo-path <path>] [--allow-empty] [--state-dir <dir>] [--config <yaml>] [--profile <name>] [--json]
  attested git [--repo-path <path>] <add|status|push|branch> [args...]
  attested git commit --session <id> --message <msg> [--repo-path <path>] [--allow-empty] [--state-dir <dir>] [--config <yaml>] [--profile <name>] [--json]
  
Exit codes:
  0 success
  2 invalid args / input
  7 signature / verification failure
`)
}
