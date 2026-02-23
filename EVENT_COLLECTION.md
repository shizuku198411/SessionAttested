# Event Collection Mechanism (PoC)

[English](./EVENT_COLLECTION.md) | [日本語](docs/jp/EVENT_COLLECTION.md)


This document explains how SessionAttested collects `exec` and `workspace write` events using eBPF and how those events are aggregated into session artifacts.

## 1. Overview

The collector runs on the host and observes container activity (PoC: Docker-based dev container).

Targets:

- `exec` events (process execution)
- write-related operations under `/workspace`

Outputs:

- `audit_exec.jsonl`
- `audit_workspace_write.jsonl`
- `audit_summary.json`
- `event_root.json`

## 2. Attach Strategy (LSM / Tracepoint fallback)

The collector attempts to attach eBPF programs using an LSM path when supported. If unavailable on the current kernel/config, it falls back to tracepoint-based collection.

Why this matters:

- improves portability across kernels
- allows PoC execution even when some LSM hooks are unsupported

## 3. Session Scoping

Events are associated with a session primarily via container/session metadata (cgroup and container process relationship) and filtered to the target `/workspace` for write events.

This reduces noise compared to auditing the entire host endpoint.

## 4. Raw Event Logs

### 4.1 `audit_exec.jsonl`

One JSON record per observed exec event.

Contains fields such as:

- `ts_ns`
- `pid`, `ppid`, `uid`
- `comm`
- `filename` (exec target path)

### 4.2 `audit_workspace_write.jsonl`

One JSON record per workspace write-related event.

Contains fields such as:

- `ts_ns`
- `pid`, `ppid`, `uid`
- `comm`
- `filename` (workspace path)
- `op` (e.g., `open_write`)

## 5. Executable Identity Resolution (SHA256)

SessionAttested aggregates executable identities using SHA256 fingerprints.

### 5.1 Exec identity resolution (current behavior)

For `exec` events, the collector prefers:

1. event `filename` (exec target path)
2. `/proc/<pid>/exe` (fallback)

This avoids stale `exe` links during `exec` transitions (e.g., old shell path before the new binary fully takes effect).

### 5.2 Container path fallback via `/proc/<pid>/root`

Because the collector runs on the host, container paths may not exist in the host mount namespace.

Fallback:

- try direct path
- if not accessible and path is absolute, try `/proc/<pid>/root/<path>`

This is important for VS Code Remote / extension binaries under container-local paths.

### 5.3 Writer identity resolution

For workspace writes, the collector uses:

- PID -> executable identity cache (built from prior exec events)
- `/proc/<pid>/exe` / fallback resolution if cache miss

This improves attribution for worker threads/processes (e.g., `libuv-worker`) that write after a preceding `node`/tool exec.

## 6. Why `comm` May Differ from Writer Identity

`comm` is the task name seen at the time of the write syscall.

Examples:

- an AI agent or IDE extension may delegate writes to `bash`, `node`, or helper processes
- `comm` can therefore be `bash` while the relevant prohibited tool is still visible in `exec`

Operational implication (PoC):

- `forbidden_exec` is the primary verdict
- `forbidden_writers` is supplementary evidence

## 7. Aggregation (`audit_summary.json`)

After finalization, the collector writes an aggregate summary including:

- event counts (`exec_observed`, `workspace_writes_observed`)
- `executed_identities`
- `writer_identities`
- unresolved identity counters/hints
  - `exec_observed.identity_unresolved`
  - `workspace_writes_observed.writer_identity_unresolved`

These fields help distinguish:

- “not observed” vs.
- “observed but identity resolution failed”

## 8. Event Root (`event_root.json`)

SessionAttested computes a hash-chain-based root over the collected events and writes `event_root.json`.

Purpose:

- compact integrity summary of the event set
- included in `attestation.json` and covered by signature verification

## 9. PoC Limits / Future Extensions

Current PoC limits:

- some helper binaries may remain unresolved (`identity_unresolved` > 0)
- writer attribution can depend on tool internals and delegation behavior

Possible future improvements:

- stronger process lineage capture for write attribution
- richer context around parent/child relationships
- deny mode (LSM enforcement) in addition to audit-only mode
