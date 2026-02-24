# Development-Session Attestation (DSA)

[English](./DSA.md) | [日本語](docs/jp/DSA.md)


This document defines **Development-Session Attestation (DSA)** as a higher-level concept above SessionAttested.

DSA is the idea of evaluating and reviewing software engineering work not only by final artifacts (repositories, binaries, portfolios), but also by **evidence about the development session/process** that produced them.

SessionAttested is one implementation approach for DSA, focused on host-side process/workspace audit evidence for dev-container workflows.

## 1. Why DSA (Problem Framing)

Modern AI-assisted development has dramatically increased implementation speed. At the same time, it has reduced the reliability of artifact-only evaluation in some contexts:

- a polished output does not necessarily show how much the developer understood the implementation
- prohibited tools may be difficult to confirm in hiring/tests/competitions
- suspicious or unintended processes (e.g., tool/extension-side behavior) may run during development, while remaining hard to explain later at a session/commit granularity

DSA addresses this gap by adding **session/process evidence** as a complementary evaluation and audit layer.

## 2. What DSA Is (and Is Not)

DSA is:

- a framework/idea for collecting and verifying evidence about development sessions
- a way to augment artifact-centric evaluation with process-centric evidence
- a basis for audit, explanation, and skill evaluation support

DSA is not:

- a full replacement for code review, testing, or CI
- an automatic skill scoring system
- a universal proof of behavior outside the audited session/environment

## 3. Core DSA Questions

A DSA-capable system should help answer questions such as:

- What processes executed during this development session?
- What executable identities wrote to the workspace?
- Which files were changed, and which process lineage touched them?
- Which commit(s) can this session be linked to?
- Did the session violate a defined policy?
- Can the result be independently verified later?

## 4. DSA as a Layered Model

A practical way to think about DSA is a layered model:

1. **Collection layer**
   - collect session evidence (`exec`, workspace writes, identities)
2. **Binding layer**
   - bind session evidence to commits / repositories
3. **Verification layer**
   - apply policy and verify signed outputs
4. **Review layer**
   - present evidence and verdicts for human review (UI, reports, artifacts)
5. **Evaluation policy layer**
   - define how organizations/teams use the evidence (e.g., prohibited tools, review requirements)

SessionAttested currently covers most of layers 1-4 for a specific deployment model (auditor-managed host + dev container).

## 5. DSA Use Cases (Examples)

### 5.1 Audit / Compliance

- confirming prohibited tool non-observation within a managed development session
- reviewing suspicious process execution during incident analysis
- preserving explainable evidence for later verification

### 5.2 Engineering Process Explanation

- explaining how a commit was produced (session -> process activity -> file changes)
- identifying forbidden exec lineage involvement in changed files
- reviewing session evidence after policy failures

### 5.3 Skill Evaluation Support (Complementary)

- portfolio review with process evidence (not output-only)
- hiring/training assessments where certain tools are restricted
- educational settings where the development process matters, not just the final answer

## 6. Relationship to Existing Tooling

DSA is best treated as a **complementary layer**, not a replacement.

- EDR/XDR: strong endpoint-wide visibility, weaker session/commit-specific development review
- Network monitoring: strong traffic visibility, weaker file/process-to-commit explanation
- CI/provenance: strong build/release provenance, weaker development-session provenance
- Code review/testing: strong output quality validation, weaker process evidence

DSA complements these by adding **development-session process evidence**.

## 7. SessionAttested as a DSA Implementation

SessionAttested is a policy-based development-session attestation framework that implements a concrete DSA approach:

- host-side auditing (LSM/eBPF) for dev-container sessions
- executable identity aggregation (`exec`, `writer`)
- commit binding
- signed attestation + verification
- review-oriented outputs (`ATTESTED_SUMMARY`, `ATTESTED_WORKSPACE_OBSERVED`, WebUI)

This means SessionAttested should be understood as:

- **not only an AI-agent detection tool**
- but a DSA-oriented evidence and verification base

## 8. Limits and Governance (Important)

DSA still requires governance decisions outside the implementation:

- what policy is considered acceptable
- what evidence is retained/shared
- how privacy boundaries are handled
- how evidence is interpreted for hiring/training/audit decisions

DSA provides the evidence and verification mechanics. Organizations must define the evaluation policy.
