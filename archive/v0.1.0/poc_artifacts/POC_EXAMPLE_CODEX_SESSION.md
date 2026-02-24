# PoC Example: Codex Write Session (Fail Case)

[English](./POC_EXAMPLE_CODEX_SESSION.md) | [日本語](../docs/jp/archive/POC_EXAMPLE_CODEX_SESSION.md)


This document summarizes a concrete SessionAttested PoC run in which Codex performed workspace writes and the attestation correctly failed policy verification.

- Session ID: `28e005395ea6b8720012b3b091d826e4`
- Goal: confirm `attestation pass=false` when Codex is listed in `forbidden_exec` / `forbidden_writers`
- Result: expected `fail`

## 1. Scenario Summary

Audited environment:

- dev container (`/workspace`)
- VS Code Remote SSH
- Codex extension installed and used

Observed actions in the session (example):

- create `src/create_by_codex.txt`
- edit/append `src/edited_by_codex.txt`
- run `attested git add/commit`

## 2. Referenced Artifacts (masked export)

This document references a masked PoC artifact export:

- [`./v0.1.0/poc_artifacts/session_28e005395ea6b8720012b3b091d826e4/`](./v0.1.0/poc_artifacts/session_28e005395ea6b8720012b3b091d826e4/)

Key files:

- `.../.attest_run/state/sessions/<SESSION_ID>/audit_exec.jsonl`
- `.../.attest_run/state/sessions/<SESSION_ID>/audit_workspace_write.jsonl`
- `.../.attest_run/state/sessions/<SESSION_ID>/audit_summary.json`
- `.../.attest_run/attestations/latest/attestation.json`
- `.../ATTESTED_SUMMARY`

## 3. Exec Detection (Codex observed)

Representative `audit_exec.jsonl` records include Codex binaries under the VS Code extension path, e.g.:

```json
{"comm":"node","filename":"/home/dev/.vscode-server/extensions/openai.chatgpt-.../bin/linux-aarch64/codex"}
```

```json
{"comm":"codex","filename":"/home/dev/.vscode-server/extensions/openai.chatgpt-.../bin/linux-aarch64/codex"}
```

Codex helper executions (`git`, `lsb_release`, `getconf`, etc.) are also visible under temporary Codex execution paths.

## 4. Workspace Write Detection (Codex writes)

Representative `audit_workspace_write.jsonl` records:

```json
{"comm":"codex","filename":"/workspace/src/create_by_codex.txt","op":"open_write"}
```

```json
{"comm":"codex","filename":"/workspace/src/edited_by_codex.txt","op":"open_write"}
```

This session directly observed `comm="codex"` for writes. In other sessions/tools, writes may appear as delegated helpers (e.g., `bash`, `node`).

## 5. Aggregated Identity Summary (`audit_summary.json`)

Highlights:

- `exec_observed.count`: large session-wide exec activity observed
- `workspace_writes_observed.count`: workspace writes observed
- `executed_identities`: includes VS Code and Codex-related executables
- `writer_identities`: includes Codex executable identity

Important identity (example):

- Codex binary hash (path hint under VS Code extension directory)

## 6. Attestation Result (`attestation.json`)

`conclusion.pass` is `false` with reasons such as:

- `FORBIDDEN_EXEC_SEEN`
- `FORBIDDEN_WRITER_SEEN`

Reason details include sample SHA/path hints (e.g., the Codex executable identity).

## 7. Verify Result (`ATTESTED_SUMMARY`)

Representative result:

- `verify_ok: false`
- `attestation_pass: false`
- `policy_checked: true`
- `policy_match: true`
- `reason: FORBIDDEN_EXEC_SEEN: ...codex...`

Interpretation:

- verification process completed normally
- policy verdict failed as intended due to prohibited tool observation

## 8. Why This PoC Example Is Useful

This example demonstrates that SessionAttested can:

- observe executable launches and workspace writes in a dev container
- fingerprint and aggregate VS Code/Codex-related executables
- apply policy-based fail judgments tied to a commit/session
- produce verifiable outputs (`attestation`, `ATTESTED_SUMMARY`) suitable for review/audit
