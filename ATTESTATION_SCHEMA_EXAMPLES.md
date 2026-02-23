# Attestation Schema Examples

[English](./ATTESTATION_SCHEMA_EXAMPLES.md) | [日本語](docs/jp/ATTESTATION_SCHEMA_EXAMPLES.md)


This document provides practical examples and field explanations for the main SessionAttested outputs.

Covered artifacts:

- `audit_summary.json`
- `event_root.json`
- `commit_binding.json` / `commit_bindings.jsonl`
- `attestation.json`
- `ATTESTED`
- `ATTESTED_SUMMARY`
- `ATTESTED_POLICY_LAST`
- `ATTESTED_WORKSPACE_OBSERVED`

Examples are simplified excerpts.

## 1. `audit_summary.json`

Aggregated session audit summary (counts, identities, unresolved counters).

```json
{
  "window": {"start_rfc3339": "2026-02-22T09:51:43Z", "end_rfc3339": "2026-02-22T09:56:44Z"},
  "exec_observed": {"count": 1438, "identity_unresolved": 19},
  "workspace_writes_observed": {"count": 9, "by_op": {"open_write": 9}},
  "executed_identities": [{"sha256": "sha256:...", "path_hint": "/home/dev/.vscode-server/.../codex"}],
  "writer_identities": [{"sha256": "sha256:...", "path_hint": "/home/dev/.vscode-server/.../codex"}]
}
```

Use it for:

- policy evaluation inputs
- session overview without scanning all raw logs
- unresolved identity monitoring

## 2. `event_root.json`

Hash-chain aggregate for the event set.

```json
{
  "schema": "event-root/0.1",
  "session_id": "28e005395ea6b8720012b3b091d826e4",
  "event_count": 1447,
  "root": "sha256:4a2f3c...",
  "seed": "session-attested:28e005395ea6b8720012b3b091d826e4"
}
```

## 3. `commit_binding.json` (latest commit)

Single-record binding for the most recent session commit.

```json
{
  "schema": "commit-binding/0.1",
  "session_id": "28e005395ea6b8720012b3b091d826e4",
  "repo": "shizuku198411/sandbox",
  "commit_sha": "3a1e62a00e3640b6e65cf1620c85a2dc23beef76",
  "timestamp": "2026-02-22T09:56:20Z"
}
```

## 4. `commit_bindings.jsonl` (multiple commits)

Append-only history for sessions with multiple `attested git commit` operations.

```json
{"schema":"commit-binding/0.1","session_id":"<SESSION_ID>","commit_sha":"<SHA1>","timestamp":"2026-02-22T09:55:01Z"}
{"schema":"commit-binding/0.1","session_id":"<SESSION_ID>","commit_sha":"<SHA2>","timestamp":"2026-02-22T09:56:20Z"}
```

## 5. `attestation.json`

Signed payload containing subject, session, event root, policy conclusion, and signing metadata.

```json
{
  "subject": {"repo": "shizuku198411/sandbox", "commit_sha": "3a1e62a00e3640b6e65cf1620c85a2dc23beef76"},
  "session": {"session_id": "28e005395ea6b8720012b3b091d826e4", "commit_bindings": [{"commit_sha": "3a1e62a..."}]},
  "event_root": {"root": "sha256:4a2f3c..."},
  "conclusion": {"pass": false, "reasons": [{"code": "FORBIDDEN_EXEC_SEEN", "detail": "count=1 samples=[sha256:...(.../codex)]"}]},
  "signature": {"key_id": "sandbox-key-1", "issuer_name": "sandbox-attestor"}
}
```

## 6. `ATTESTED`

Human-readable marker indicating `verify` was run for this repository/output.

```text
SessionAttested verification marker
timestamp: 2026-02-22T09:59:14Z
session_id: 28e005395ea6b8720012b3b091d826e4
verify_ok: false
attestation_pass: false
```

## 7. `ATTESTED_SUMMARY`

JSON array appended by `verify --write-result` with per-session verification results.

```json
[
  {
    "timestamp": "2026-02-22T09:59:14Z",
    "session_id": "28e005395ea6b8720012b3b091d826e4",
    "repo": "shizuku198411/sandbox",
    "commit_sha": ["3a1e62a00e3640b6e65cf1620c85a2dc23beef76"],
    "commit_url": ["https://github.com/shizuku198411/sandbox/commit/3a1e62a00e3640b6e65cf1620c85a2dc23beef76"],
    "verify_ok": false,
    "attestation_pass": false,
    "policy_checked": true,
    "policy_match": true,
    "reason": "FORBIDDEN_EXEC_SEEN: count=1 samples=[sha256:f211b442b(.../codex)]"
  }
]
```

## 8. `ATTESTED_POLICY_LAST`

Human-readable record of the policy used in the latest `verify` run.

Typical contents:

- `policy_path`
- `policy_id`
- `policy_version`
- `ruleset_hash`
- `timestamp`

## 9. `ATTESTED_WORKSPACE_OBSERVED`

Workspace-level cumulative observed identities updated by `verify --write-result`.

Unlike session-scoped artifacts, this file is intended for cross-session review of observed executables/writers and unresolved counters.

```json
{
  "sessions_seen": ["28e005395ea6b8720012b3b091d826e4"],
  "exec_identities": [
    {
      "sha256": "sha256:f211b442bfb2eb20e4d6d7c0593b34ec421a5bcd630873c69ed7aaedeea28a26",
      "path_hint": "/home/dev/.vscode-server/extensions/openai.chatgpt.../codex",
      "first_seen_session": "28e005395ea6b8720012b3b091d826e4",
      "last_seen_session": "28e005395ea6b8720012b3b091d826e4",
      "seen_count": 1
    }
  ],
  "writer_identities": [],
  "exec_identity_unresolved": 19,
  "writer_identity_unresolved": 2
}
```

Use it for:

- reviewing tools not yet covered by policy
- tracking what ran/wrote across the workspace over time
- policy refinement and post-hoc audit review

Note:

- `ATTESTED_OBSERVED` (session-scoped observed list) is not generated in the current implementation
- for session-level details, use `attestation.json` and `audit_summary.json`

## 10. Compatibility Guidance

- Prefer parsers that ignore unknown fields
- Treat `schema`/version fields as compatibility boundaries
- Expect field additions over time as the PoC evolves
