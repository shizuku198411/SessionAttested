# PoC Quickstart (Build & Usage)

[English](./POC_QUICKSTART.md) | [日本語](docs/jp/POC_QUICKSTART.md)


This is the shortest practical path to try SessionAttested as a PoC.

## 1. Prerequisites

- Linux host with eBPF support
- Docker
- `sudo` access (collector)
- Go (to build `attested`)
- OpenSSL (for attestation key generation)

## 2. Build `attested`

```bash
cd /path/to/session-attested
go build -o attested ./cmd/attested
```

Optional install:

```bash
sudo install -m 0755 ./attested /usr/local/bin/attested
```

## 3. Prepare a PoC workspace

```bash
mkdir -p ~/work/sessionattested-sandbox
cd ~/work/sessionattested-sandbox
git init
git branch -M main
```

(Optional) add remote:

```bash
git remote add origin <your-repo-url>
```

## 4. Initialize workspace (recommended)

The easiest path is to let `workspace init` generate the scaffold interactively.

```bash
attested workspace init
```

What it prepares (by default):

- workspace registration (`.attest_run/state/workspaces/...`)
- `attest/attested.yaml` (config template)
- `attest/Dockerfile` (dev-container template)
- `attest/policy.yaml` (policy template)
- `.gitignore` (managed block for local audit artifacts)
- dev container (created and left stopped)

Notes:

- Interactive prompts fill items such as workspace id/path, image, build/pull, GitHub repo, git user, and optional SSH key mount.
- Most users do not need to prepare `attested.yaml` manually.

## 5. Manual config/Dockerfile preparation (optional)

If you prefer manual setup instead of `workspace init`, prepare at least:

- `Dockerfile`
- `attest/attested.yaml`

Example bootstrap (copy from repository examples):

```bash
mkdir -p attest
cp /path/to/session-attested/example/attested.config.yaml ./attest/attested.yaml
cp /path/to/session-attested/example/docker/ubuntu-24.04-ssh/Dockerfile ./Dockerfile
```

Update `attest/attested.yaml` for your environment, especially:

- `commands.start.workspace_host`
- `commands.start.image`
- `commands.start.build`
- `commands.start.dockerfile`
- `commands.start.publish` (SSH port mapping)
- `commands.start.auto_collect`
- `commands.attest.policy`
- `commands.attest.out`
- `commands.attest.signing_key`
- `commands.verify.policy`

## 6. Start a session (container start + auto collector)

```bash
attested start --json
```

Save:

- `session_id`
- `container_id`

If `auto_collect: true`, collector starts in background.

Notes:

- `./attest/attested.yaml` is auto-detected if present (so `--config` is usually unnecessary)
- `.attest_run/last_session_id` is updated automatically on successful `start`
- By default, `stop` can preserve the container (`keep_container: true`), so you can repeat sessions without rebuilding the environment

## 7. Work inside the dev container

Example (SSH):

```bash
ssh dev@127.0.0.1 -p 2222
```

Inside the container:

```bash
cd /workspace
attested git status
attested git add -A
attested git commit -m "poc: first commit"
```

`ATTESTED_SESSION_ID` is usually injected, so `--session` is not required for `attested git commit`.

## 8. Git operations can be done on host or inside container

You can choose either operation style depending on your policy:

- auditee pushes from inside the dev container
- auditor runs `attest` / `verify` first and pushes only after pass (from host or container)

Typical examples:

- inside container: `attested git add/commit/push`
- on host: normal `git` or `attested git ...` (same workspace)

## 9. Stop session + attest + verify

```bash
attested stop --run-attest --run-verify --verify-write-result
```

Generated/updated outputs typically include:

- `.attest_run/state/sessions/<SESSION_ID>/...`
- `.attest_run/attestations/latest/attestation.json`
- `ATTESTED`
- `ATTESTED_SUMMARY`
- `ATTESTED_POLICY_LAST`
- `ATTESTED_WORKSPACE_OBSERVED`

## 10. Repeat sessions on the same container (normal workflow)

`start` / `stop` are intended to be used repeatedly as **work-unit boundaries**.

- `start`: starts (or reuses) the registered dev container and begins a new audited session
- `stop`: finalizes the session and typically stops the container, but does not delete it

This means your dev environment (installed tools, caches, editor server state, etc.) can remain available across sessions.

## 11. First Files to Check

- `ATTESTED_SUMMARY`
  - `verify_ok`, `attestation_pass`, `reason`
- `.attest_run/state/sessions/<SESSION_ID>/audit_summary.json`
  - `executed_identities`, `writer_identities`
- `.attest_run/attestations/latest/attestation.json`
  - `conclusion.reasons`
- `ATTESTED_WORKSPACE_OBSERVED`
  - cumulative observed exec/writer identities across workspace sessions (including unresolved counters/hints)

## 12. Review Results in WebUI (Optional but Recommended)

SessionAttested includes a local HTTPS WebUI to inspect session results and cumulative observed identities.

```bash
attested webui
```

Or bind to another address/port:

```bash
attested webui --addr 0.0.0.0:9443
```

What to check first:

- `Attestation / Verification` card (`PASS` / `FAIL`, reason code)
- `Audit Summary` card (counts / unresolved)
- `Executed Identities (Session)` / `Writer Identities (Session)` (policy-hit highlights)
- `See other sessions` (session-by-session pass/fail comparison)

Notes:

- TLS is self-signed (browser warning expected)
- Selecting another session in the UI updates the displayed summary/result using `ATTESTED_SUMMARY`

## 13. Generate a Candidate Policy

```bash
attested policy candidates
```

Output:

- `.attest_run/policy.<SESSION_ID>.candidate.yaml`

Review and rename it to your active policy file.

## 14. Common PoC Pitfalls

### Collector does not start / finalize

- confirm `sudo` access
- inspect `collector.log`
- confirm kernel/LSM hook availability (tracepoint fallback exists)

### `verify` fails

- inspect `ATTESTED_SUMMARY.reason`
- inspect `attestation.json.conclusion.reasons`
- check `forbidden_exec` / `forbidden_writers`
- if `policy_match=false`, confirm you used the intended policy
- if the reason is `AUDIT_LOG_INTEGRITY_MISMATCH`:
  - confirm you are using the latest `attested` binary
  - check whether local session logs under `.attest_run/state/sessions/<SESSION_ID>/` were edited/replaced after collection
  - compare `event_root.json` with the selected session `attestation.json` (`integrity.event_root`, `integrity.event_count`)

### Writer identity looks different from raw `comm`

- `audit_workspace_write.jsonl.comm` and `writer_identities` are related but not always identical
- prefer `forbidden_exec` as the primary verdict (see `POLICY_GUIDE.md`)

### I changed `publish`/mount settings but nothing changed

- Docker port publishes and bind mounts are fixed at container creation time
- if you changed `attest/attested.yaml` (`publish`, SSH key mount, mounted `attested` binary, etc.), recreate the workspace container:
  - `attested workspace rm`
  - `attested workspace init`
