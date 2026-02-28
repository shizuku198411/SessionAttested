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

	case "key":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		switch os.Args[2] {
		case "fingerprint":
			code := commands.RunKeyFingerprint(os.Args[3:])
			os.Exit(code)
		default:
			usage()
			os.Exit(2)
		}

	case "verify":
		code := commands.RunVerify(os.Args[2:])
		os.Exit(code)

	case "doctor":
		code := commands.RunDoctor(os.Args[2:])
		os.Exit(code)

	case "export":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		switch os.Args[2] {
		case "artifact":
			code := commands.RunExportArtifact(os.Args[3:])
			os.Exit(code)
		default:
			usage()
			os.Exit(2)
		}

	case "webui":
		code := commands.RunWebUI(os.Args[2:])
		os.Exit(code)

	case "workflow":
		if len(os.Args) < 3 {
			usage()
			os.Exit(2)
		}
		switch os.Args[2] {
		case "github-artifact":
			code := commands.RunWorkflowGithubArtifact(os.Args[3:])
			os.Exit(code)
		case "github-verify":
			code := commands.RunWorkflowGithubVerify(os.Args[3:])
			os.Exit(code)
		default:
			usage()
			os.Exit(2)
		}

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
  attested key fingerprint (--public-key <path> | --private-key <path>) [--json]
  attested doctor [--session <id>] [--run-dir .attest_run] [--state-dir .attest_run/state] [--config <yaml>] [--profile <name>] [--json]
  attested export artifact [--session <id>] [--run-dir .attest_run] [--state-dir .attest_run/state] [--out attest/attested_artifacts/latest] [--policy <path>] [--include-raw-logs] [--config <yaml>] [--profile <name>] [--json]
  attested workflow github-artifact [--out .github/workflows/publish-attested-artifact.yml] [--artifact-dir attest/attested_artifacts/latest] [--repo <owner/name>] [--config <yaml>] [--profile <name>] [--json]
  attested workflow github-verify [--out .github/workflows/verify-session-attested.yml] [--artifact-dir attest/attested_artifacts/latest] [--sessionattested-repo <git-url>] [--sessionattested-ref <ref>] [--config <yaml>] [--profile <name>] [--json]
  attested workspace init --workspace-id <id> --workspace-host <dir> --name <container> --image <image> [--build|--pull] [--scaffold[=true|false]] [--scaffold-force] [--scaffold-interactive] [--repo <owner/name>] [start-compatible options...] [--state-dir <dir>] [--config <yaml>] [--profile <name>] [--json]
  attested workspace rm --workspace-id <id> [--remove-workspace-host] [--state-dir <dir>] [--json]
  attested webui [--addr 127.0.0.1:8443] [--session <id>] [--run-dir .attest_run] [--state-dir .attest_run/state] [--tls-cert <path>] [--tls-key <path>]
  attested verify --attestation <path> --signature <path> [--public-key <path>] [--expected-key-fingerprint <sha256:...>] [--policy <path>] [--binding <path>] [--require-pass] [--write-result] [--result-file <path>] [--config <yaml>] [--profile <name>] [--json]
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
