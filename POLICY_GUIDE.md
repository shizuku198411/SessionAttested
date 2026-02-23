# Policy Guide

[English](./POLICY_GUIDE.md) | [日本語](docs/jp/POLICY_GUIDE.md)


This document explains how to design, review, and operate SessionAttested policies.

PoC recommendation:

- Use `forbidden_exec` as the primary verdict
- Use `forbidden_writers` as supplementary evidence

## 1. Purpose of Policy

Policies evaluate identities collected in `audit_summary.json` and determine whether a session should pass or fail verification.

PoC style: blocklist-centric policies.

## 2. Core Fields (PoC)

```yaml
policy_id: "sandbox-policy"
policy_version: "1.0.0"

forbidden_exec: []
forbidden_writers: []

exceptions: []
```

### 2.1 `forbidden_exec`

- evaluated against `executed_identities`
- primary mechanism for AI agent / prohibited tool detection

Typical use:

- codex / claude-like agent binaries
- disallowed code generators / fetchers / organization-specific tools

### 2.2 `forbidden_writers`

- evaluated against `writer_identities`
- supplementary evidence for workspace write attribution

Typical use:

- stable writer identities that directly write to `/workspace`
- same hashes as `forbidden_exec` for stronger evidence

### 2.3 `exceptions`

Reserved for future conditional allow rules / operational exceptions.

## 3. Why `forbidden_exec` Should Be Primary (PoC)

Write syscalls may be delegated to helper processes such as `bash`, `node`, or `python`, depending on tool internals.

Therefore:

- write actor names may vary
- prohibited tool execution is usually more stable in `exec` observations

## 4. Recommended Policy Workflow

### 4.1 Run a session and collect audit results

- `attested start`
- perform development work
- `attested stop --run-attest --run-verify --verify-write-result`

### 4.2 Generate candidate policy

```bash
attested policy candidates \
  --session <SESSION_ID> \
  --state-dir <RUN_DIR>/state
```

Output:

- `<RUN_DIR>/policy.<SESSION_ID>.candidate.yaml`

### 4.3 Review and promote

- review candidate entries
- remove noise / non-target identities
- set a proper `policy_id`
- rename/copy to the active policy file

## 5. Review Checklist

- `audit_summary.json.executed_identities`
- `audit_summary.json.writer_identities`
- unresolved counters (`identity_unresolved`, writer unresolved if present)

If unresolved counts are high, improve observation quality before tightening policy.

## 6. What to Add First

Good initial `forbidden_exec` candidates:

- explicit AI agent binaries
- unique extension binaries / CLIs you truly want to ban
- high-risk tools with clear policy rationale

Avoid banning too early:

- `/bin/bash`
- general `python` / `node`
- common editor platform binaries

These can create high false-positive rates.

## 7. Update Triggers

Revisit policy after:

- tool/extension updates
- base image changes
- sudden increase in unresolved identities
- false positives / misses found in operation

## 8. Reading Failures (`attest` / `verify`)

Check:

1. `attestation.json.conclusion.reasons`
2. `ATTESTED_SUMMARY.reason`
3. `audit_summary.json` identities
4. raw logs (`audit_exec.jsonl`, `audit_workspace_write.jsonl`) if needed

Typical reason codes:

- `FORBIDDEN_EXEC_SEEN`
- `FORBIDDEN_WRITER_SEEN`
- `UNAPPROVED_WRITER_SEEN` (legacy whitelist compatibility)

## 9. Compatibility Note

- `allowed_writers` remains readable for backward compatibility
- New policies should use `forbidden_writers`

## 10. Minimal Practical Rule Set (PoC)

A safe starting point:

- `forbidden_exec`: only the agent/tool binaries you prohibit
- `forbidden_writers`: empty (or same agent binaries only)
- review `reason.detail` before changing policy
