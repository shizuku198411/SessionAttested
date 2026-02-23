# Threat Model

[English](./THREAT_MODEL.md) | [日本語](docs/jp/THREAT_MODEL.md)


SessionAttested provides host-side auditing and signed attestations for development sessions. This document defines what the PoC is intended to prove, what it assumes, and what remains out of scope.

## 1. Security Goals

- auditable records of executed processes (`exec`)
- auditable records of workspace write actors (`writer`)
- binding audit results to commits (commit binding)
- verifiable signed attestation output
- policy-based fail/pass decisions (e.g., prohibited tool detection)

## 2. What It Can Prove (PoC framing)

A suitable PoC claim is:

- Given the audit evidence collected on an auditor-managed host for a specific session, it is possible to verify whether policy-prohibited executables/writers were observed in that session.

For AI-agent policy use cases:

- “Was a prohibited agent executable observed in the audited session?”

## 3. What It Does Not Prove

- that a user never used prohibited tools in any other environment
- that artifacts were not produced elsewhere and manually imported
- prompt-history/copy-paste provenance
- integrity against a malicious host admin / kernel compromise

This is high-confidence **managed-session process evidence**, not a universal proof of non-use.

## 4. Trust Assumptions

At minimum, the PoC assumes trust in:

- auditor-managed host
- host OS / kernel / eBPF execution environment
- `attested` binary used by the auditor
- signing key management for `attested attest`
- intended container launch/configuration path

## 5. Attacks / Evasions (Examples)

### Easier to detect

- prohibited executable launches (`forbidden_exec`)
- prohibited writer identities writing to the workspace (`forbidden_writers`)
- post-hoc attestation tampering (signature verification)

### Hard / out of scope

- generation in a non-audited environment and later import
- privileged host tampering (collector/kernel/log manipulation)
- cases outside the collector’s observation model

## 6. Operational Verdict Weighting (PoC)

Recommended weighting:

- `forbidden_exec`: primary verdict
- `forbidden_writers`: supplementary verdict

Reason:

- actual write syscalls may be delegated to helper processes (`bash`, `node`, etc.)
- prohibited tool binaries are often more stable and directly observable in `exec`

## 7. Residual Risks

- executable identity resolution failures (`identity_unresolved`)
- tool updates changing hashes/paths and requiring policy maintenance
- environment-specific attribution differences (UID/GID, mount layout, SSH/IDE behavior)

Operational mitigations:

- monitor unresolved counters in `audit_summary.json`
- use `attested policy candidates` for policy maintenance
- review and refresh policies regularly

## 8. Future Hardening

- transparency logs
- KMS/HSM signing keys
- trusted timestamps (TSA)
- richer process-lineage capture
- deny-mode enforcement (LSM-based)
