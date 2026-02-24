# Attestation Flow (PoC)

[English](./ATTESTATION_FLOW.md) | [日本語](docs/jp/ATTESTATION_FLOW.md)


This document explains the end-to-end attestation flow in SessionAttested using current commands, from the perspective of two actors:

- **Auditor** : controls the host / collector / signing / verification policy
- **Auditee** : performs development work in the dev container

## 1. Roles

### Auditor

- prepares and manages the host machine
- starts the session and container
- runs / manages the eBPF collector
- finalizes the session and generates attestations
- verifies and publishes results

### Auditee

- connects to the dev container (e.g., via SSH)
- edits files in `/workspace`
- performs Git operations (`attested git ...`)
- produces commits linked to the audited session

## 2. Typical PoC Flow

### Step 1. Start session (auditor)

```bash
attested start --json
```

What happens:

- starts the dev container
- writes session metadata (`meta.json`)
- (optionally) starts collector in background (`auto_collect: true`)
- injects `ATTESTED_SESSION_ID` / `ATTESTED_STATE_DIR` into the container
- allows repeated `start` / `stop` cycles while reusing the same dev-container environment (when configured)

Outputs:

- `session_id`
- `container_id`

### Step 2. Development work in dev container (auditee)

Typical operations:

```bash
cd /workspace
attested git status
attested git add -A
attested git commit -m "poc: work"
```

What is recorded:

- `exec` events (CLI tools, IDE/extension binaries, shells, helpers)
- `workspace write` events under `/workspace`
- commit binding (`commit_binding.json`, `commit_bindings.jsonl`)

### Step 3. Stop session and finalize (auditor)

```bash
attested stop \
  --run-attest \
  --run-verify \
  --verify-write-result
```

What happens:

- stops the container (or stops+removes it depending on config/policy)
- signals collector to stop and finalize
- writes audit aggregates (`audit_summary.json`, `event_root.json`)
- builds and signs `attestation.json`
- runs `verify`
- updates `ATTESTED`, `ATTESTED_SUMMARY`, `ATTESTED_POLICY_LAST`, `ATTESTED_WORKSPACE_OBSERVED`

### Step 4. Review recorded results in WebUI (auditor, optional)

```bash
attested webui
```

What happens:

- starts a local HTTPS server (self-signed certificate)
- reads recorded outputs in the workspace (`ATTESTED*`, `.attest_run/state/...`, `attestation.json`)
- provides a visual review UI for:
  - session PASS/FAIL status
  - audit summary counts
  - executed/writer identities
  - workspace cumulative observed identities
  - commit links / session list

Notes:

- the UI is a viewer for recorded results; it does not replace `attest` / `verify`
- current implementations typically keep `attestation.json` as `latest`; when browsing older sessions, the UI uses `ATTESTED_SUMMARY` for per-session verification status

## 3. Optional: Policy candidate generation (auditor)

```bash
attested policy candidates \
  --session <SESSION_ID>
```

Output:

- `.attest_run/policy.<SESSION_ID>.candidate.yaml`

Use this to bootstrap policy design from observed identities.

## 5. Optional: Manual attest/verify (auditor)

If not using `stop --run-attest --run-verify`, run manually:

```bash
attested attest
attested verify --write-result
```

## 6. Outputs by Stage (Summary)

- Session start:
  - `meta.json`
- During work:
  - `audit_exec.jsonl`
  - `audit_workspace_write.jsonl`
  - `commit_binding.json`
  - `commit_bindings.jsonl`
- Finalize:
  - `audit_summary.json`
  - `event_root.json`
- Attest / verify:
  - `attestation.json`, `.sig`, `.pub`
  - `ATTESTED`
  - `ATTESTED_SUMMARY`
  - `ATTESTED_POLICY_LAST`
  - `ATTESTED_WORKSPACE_OBSERVED`
- WebUI review:
  - no new audit evidence is generated
  - recorded outputs are rendered for visual inspection (`attested webui`)

## 7. Operational Interpretation (PoC)

Recommended policy weighting at the PoC stage:

- `forbidden_exec`: primary verdict (prohibited tool execution)
- `forbidden_writers`: supplementary verdict (writer attribution evidence)

Reason:

- write syscalls may be delegated to helper processes (e.g., `bash`, `node`) depending on tool internals
- prohibited tool binaries are usually detected more reliably in `exec` observations
