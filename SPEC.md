# SPEC: SessionAttested

[English](./SPEC.md) | [日本語](docs/jp/SPEC.md)


This document defines the PoC specification for `attested` (SessionAttested). The PoC targets development containers on Docker, binds host-side audit observations (LSM/eBPF) to commits, and outputs them as signed attestations.

The core of this specification is not “AI agent detection only,” but a general attestation foundation that verifies process execution and workspace writes in a development session based on policy (prohibited executables / writer policies). AI-agent prohibition is treated as a representative policy application.

For the Japanese original currently maintained in this repository, see [`docs/jp/SPEC.md`](docs/jp/SPEC.md).

## 1. Goals and Claims

### 1.1 Goal

For hiring tests, portfolios, and audit-oriented use cases, present process execution and workspace writes during a development session in a form that can be verified using environmental/process-level evidence.

Preventing/verifying code implementation delegated entirely to an AI agent (where the agent directly rewrites files) is one concrete use case of this framework.

### 1.2 Claims Signed by the PoC

- For a session `session_id` executed on a host under the auditor’s control:
  - write operations under the target workspace `/workspace` (host bind mount) originated only from allowed executables (writer policy model)
  - execution/writes by prohibited executables (`forbidden_exec`; including AI-agent-related tools) were not observed (within the scope of the policy definition)
- The set of audit events supporting the above claims is aggregated by `event_root`, enabling tamper detection
- The attestation document is signed with a signing key controlled by the auditor

### 1.3 Non-Goals

- Proving in general that a user “did not use a category of tools at all” (e.g., manually importing artifacts generated in another environment)
- Copy/paste detection or prompt-history tracking
- Full integrity guarantees for self-hosted environments (the PoC assumes a managed host)

## 2. Threat Model (PoC)

### 2.1 Attacks in Scope

- A prohibited executable (including AI-agent tools) directly rewrites the workspace
- A non-approved process writes to the workspace
- Audit logs are tampered with or swapped after collection

### 2.2 Attacks Out of Scope (PoC)

- A human consults an external LLM and manually implements the result (including copy/paste)
- The auditor performs malicious actions with host administrator privileges
- Kernel tampering, disabling LSM/eBPF (within the auditor-side infrastructure security boundary)

## 3. Architecture (PoC / Docker)

### 3.1 Components

- Dev Container: Docker container where the user performs development work
- Host Audit Collector: host-side process that collects events via LSM/eBPF
- Attestor: CLI/service that evaluates policy against audit summaries, generates, and signs attestations

### 3.2 Fixed Workspace Path

- Host side: `/var/lib/attested-workspaces/<session_id>/`
- In container: bind-mounted to `/workspace`
- Audit scope is limited to write-related operations under `/workspace`

## 4. Audit Events

### 4.1 Event Types

The PoC requires the following two event classes.

- `exec`: process execution events
- `workspace_write`: write-related operations under `/workspace` (e.g., `open_write` / create / rename / unlink)

Event format follows `schemas/audit-event.schema.json`.

### 4.2 LSM Hooks

- `exec`: `bprm_check_security`
- `workspace_write`:
  - minimum: `file_open` (detect write flags)
  - optional additions: `inode_create`, `inode_unlink`, `inode_rename`

### 4.3 Executable Identification

- `process.exe` in an event must contain at least `(inode, dev)`
- `sha256` may be computed and filled in by the userspace collector from `/proc/<pid>/exe`, event path, etc.
- `path_hint` is for display/debugging and is not the primary verification root (hash identity is primary)

### 4.4 Container Identification

- Events include `cgroup_id`
- Userspace resolves `cgroup_id -> container_id`
- For PoC stability, embedding session info at container launch (e.g., `--cgroup-parent /attested/<session_id>`) is recommended

## 5. Session (`session_id`)

### 5.1 Session Start / Stop

- `attested start` issues a `session_id`, prepares the workspace, registers the session with the collector, and starts the dev container
- `attested stop` stops the dev container and instructs the collector to finalize aggregation

### 5.2 Commit Binding

- Minimal PoC implementation can be expressed as `attested attest --session <session_id> --commit <sha>`
- Future/extended behavior strengthens this with `attested commit` (safe-git equivalent / commit binding management)

## 6. Policy

Policy is defined in `policy/policy.yaml`.

- `forbidden_exec`: prohibited executables (including AI-agent tools), listed by sha256
- `forbidden_writers`: executables prohibited from writing to `/workspace`, listed by sha256
- `allowed_writers`: legacy whitelist mode (backward compatibility; deprecated)
- `ruleset_hash`: sha256 of the canonical policy representation (`sha256:<hex>`)

PoC evaluation rules:

- fail if at least one forbidden executable is observed in `exec`
- fail if a `workspace_write` writer is included in `forbidden_writers`

### 6.1 Operational Interpretation (PoC stage)

At the PoC stage, the following operational interpretation is recommended.

- `forbidden_exec`: primary verdict (detection of prohibited tool execution)
- `forbidden_writers`: supplementary verdict (stronger evidence for write attribution)

Reasoning:

- Real tools/extensions may delegate writes internally to child processes such as `bash`, `node`, or `python`
- Therefore, the direct writer observed in `workspace_write` may not match the top-level orchestrator/agent name
- In contrast, `exec` is generally effective for detecting the presence of prohibited executables

## 7. Integrity Aggregation (`event_root`)

The PoC adopts hash-chain-based `event_root` aggregation (SHA-256).

### 7.1 Canonical JSON

JSON normalization rules used for signatures and hash calculations:

- UTF-8
- keys sorted in lexicographic order
- no whitespace (compact form)
- no trailing newline
- numeric representation must follow JSON standard (no unnecessary leading zeros, etc.)

### 7.2 Hash Chain

- `seed = "session-attested:" + session_id` (UTF-8)
- `h0 = sha256(seed)`
- for each event `e_i`:
  - `x_i = sha256(canonical_json(e_i))`
  - `h_{i+1} = sha256(h_i || x_i)` (`||` = byte concatenation)
- `event_root = h_n` (hex)
- `event_count = n`
- event ordering must be ascending by `seq`

## 8. Attestation (`attestation.json`)

- Machine-readable format follows `schemas/attestation.schema.json`
- Required information includes:
  - subject (repo/commit)
  - session (`session_id`, workspace)
  - environment (collector info, container info)
  - policy (`policy_id` / `policy_version`, `ruleset_hash`)
  - audit summary (observed counts, writer set, forbidden detections)
  - event root summary (`root`, `seed`, `event_count`)
  - conclusion (pass/fail + reason codes)
  - `issued_at`

## 9. Signature (PoC)

Ed25519 is recommended in the PoC.

- Signed payload: canonical JSON byte sequence of `attestation.json`
- Outputs:
  - `attestation.json`
  - `attestation.sig` (signature bytes, e.g., base64)
  - `attestation.pub` (verification public key; may be bundled in PoC)

## Appendix A: Failure Reason Codes

- `OK`
- `FORBIDDEN_EXEC_SEEN`
- `FORBIDDEN_WRITER_SEEN`
- `UNAPPROVED_WRITER_SEEN`
- `AUDIT_GAP_DETECTED`
- `INTEGRITY_MISMATCH`
- `POLICY_MISMATCH`
