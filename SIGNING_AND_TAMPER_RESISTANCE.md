# Signing and Tamper Resistance (PoC)

[English](./SIGNING_AND_TAMPER_RESISTANCE.md) | [日本語](docs/jp/SIGNING_AND_TAMPER_RESISTANCE.md)


This document explains what SessionAttested signs, how verification works, and how to think about tamper resistance at the PoC stage.

## 1. What Is Signed?

SessionAttested signs the attestation payload (`attestation.json`) after canonical serialization.

The attestation includes, among other fields:

- session metadata
- commit binding information
- event root (`event_root.json` summary)
- policy evaluation result (`conclusion`)
- optional policy snapshot metadata

## 2. Signing Flow (`attested attest`)

High-level flow:

1. read finalized session artifacts (`audit_summary.json`, `event_root.json`, bindings)
2. evaluate policy (`forbidden_exec`, `forbidden_writers`)
3. build `attestation.json`
4. canonicalize payload
5. sign with configured key (Ed25519 in PoC examples)
6. write:
   - `attestation.json`
   - `attestation.sig`
   - `attestation.pub`

## 3. Verification Flow (`attested verify`)

High-level flow:

1. read attestation and signature
2. verify signature against public key
3. validate structure / internal consistency
4. optionally check commit binding consistency
5. optionally compare against provided policy / policy snapshot
6. if local session state (`.attest_run/state/sessions/<session_id>`) is available, recompute `event_root` from raw audit logs (`audit_exec.jsonl`, `audit_workspace_write.jsonl`) and compare it with:
   - `event_root.json`
   - `attestation.json` (`integrity.event_root`, `integrity.event_count`)
7. optionally fail if `conclusion.pass=false` (`require-pass=true`)
8. optionally write result markers (`ATTESTED`, `ATTESTED_SUMMARY`, `ATTESTED_POLICY_LAST`, `ATTESTED_WORKSPACE_OBSERVED`)

## 4. Role of Canonical JSON

Canonicalization prevents serialization differences (field order, formatting differences) from changing the signed bytes.

This ensures:

- deterministic signatures for the same logical content
- reliable verification across environments/tools

## 5. Role of `event_root` (Hash Chain)

The collector aggregates events into a hash-chain root (`event_root.json`), which is included in the attestation.

This allows the attestation to cover the observed event set indirectly without embedding every raw event line in the attestation payload.

Practical effect:

- changing the underlying event set should change the event root
- changing the event root changes the attestation payload and breaks signature verification (or consistency checks)
- when local raw logs are available, `attested verify` can also detect post-hoc raw-log tampering by recomputing the hash chain and comparing it to the recorded `event_root`

## 6. What Tamper Resistance Means Here

At the PoC stage, tamper resistance should be interpreted as:

- **detection-oriented integrity** for exported audit results and attestations
- not absolute prevention against a fully privileged host attacker

## 7. What Is Protected (Assuming Trust Preconditions Hold)

If the trust assumptions hold (host, collector, key management), SessionAttested can provide strong evidence against:

- post-hoc modification of `attestation.json`
- mismatched `attestation.json` and `attestation.sig`
- policy-result rewrites without resigning
- unnoticed changes to event-root-bound session summaries
- post-hoc modification of local raw audit logs (`audit_exec.jsonl`, `audit_workspace_write.jsonl`) when verifying on a workspace that still has local session state

## 8. What Is Not Protected (PoC Scope)

SessionAttested does **not** by itself protect against:

- a malicious or compromised host administrator
- kernel/eBPF/collector tampering at collection time
- use of prohibited tools outside the audited environment/session
- out-of-band code generation followed by manual import into the audited workspace

## 9. Operational Guidance (PoC)

Treat the attestation as:

- signed, reproducible process evidence for a managed session
- useful for policy verification, review, and audit trails
- one layer in a larger assurance stack (not the only one)

Recommended companions:

- CI verification (`attested verify`)
- code review
- static analysis / secret scanning
- infra/endpoint security controls

## 10. Future Hardening Options

- KMS/HSM-backed signing keys
- transparency log publication
- trusted timestamping (TSA)
- stronger provenance binding (CI identities, workload identity, etc.)
