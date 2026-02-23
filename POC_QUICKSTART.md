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

## 4. Prepare PoC config and Dockerfile

Minimum files:

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

## 5. Start a session (container + auto collector)

```bash
attested start --config ./attest/attested.yaml --json
```

Save:

- `session_id`
- `container_id`

If `auto_collect: true`, collector starts in background.

## 6. Work inside the dev container

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

## 7. Stop session + attest + verify

```bash
attested stop \
  --config ./attest/attested.yaml \
  --session <SESSION_ID> \
  --run-attest \
  --run-verify \
  --verify-write-result
```

Generated/updated outputs typically include:

- `.attest_run/state/sessions/<SESSION_ID>/...`
- `.attest_run/attestations/latest/attestation.json`
- `ATTESTED`
- `ATTESTED_SUMMARY`
- `ATTESTED_POLICY_LAST`

## 8. First Files to Check

- `ATTESTED_SUMMARY`
  - `verify_ok`, `attestation_pass`, `reason`
- `.attest_run/state/sessions/<SESSION_ID>/audit_summary.json`
  - `executed_identities`, `writer_identities`
- `.attest_run/attestations/latest/attestation.json`
  - `conclusion.reasons`

## 9. Generate a Candidate Policy

```bash
attested policy candidates \
  --session <SESSION_ID> \
  --state-dir ./.attest_run/state
```

Output:

- `.attest_run/policy.<SESSION_ID>.candidate.yaml`

Review and rename it to your active policy file.

## 10. Common PoC Pitfalls

### Collector does not start / finalize

- confirm `sudo` access
- inspect `collector.log`
- confirm kernel/LSM hook availability (tracepoint fallback exists)

### `verify` fails

- inspect `ATTESTED_SUMMARY.reason`
- inspect `attestation.json.conclusion.reasons`
- check `forbidden_exec` / `forbidden_writers`
- if `policy_match=false`, confirm you used the intended policy

### Writer identity looks different from raw `comm`

- `audit_workspace_write.jsonl.comm` and `writer_identities` are related but not always identical
- prefer `forbidden_exec` as the primary verdict (see `POLICY_GUIDE.md`)
