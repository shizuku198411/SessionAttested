# SessionAttested

[English](./README.md) | [日本語](docs/jp/README.md)

![Version](https://img.shields.io/badge/version-v0.1.3-blue)
![Status](https://img.shields.io/badge/status-PoC-orange)

**SessionAttested** is a **policy-based development-session attestation framework**.
It observes host-side process evidence (`exec`, workspace writes), binds it to commits, and produces signed, verifiable outputs.

This project is also a concrete implementation path toward **Development-Session Attestation (DSA)**.
See: [`DSA.md`](DSA.md)

## Build

Prerequisites (typical):
- Linux host
- Docker
- Go
- clang/llvm + libbpf development headers (for eBPF code generation)

Build:

```bash
./scripts/build.sh build
```

Or:

```bash
go generate ./internal/collector/ebpf
go build -o attested ./cmd/attested
```

## Quick Start

Use the quick start guide:
- [`POC_QUICKSTART.md`](POC_QUICKSTART.md)

This includes:
- workspace/session flow
- attest/verify
- `attested webui`
- artifact export and GitHub workflow templates

## Documentation

Core docs:
- Changelog: [`CHANGELOG.md`](CHANGELOG.md)
- DSA concept: [`DSA.md`](DSA.md)
- Detailed project overview (use cases, architecture, strengths): [`PROJECT_OVERVIEW.md`](PROJECT_OVERVIEW.md)
- End-to-end flow: [`ATTESTATION_FLOW.md`](ATTESTATION_FLOW.md)
- Output schema examples: [`ATTESTATION_SCHEMA_EXAMPLES.md`](ATTESTATION_SCHEMA_EXAMPLES.md)
- Event collection details: [`EVENT_COLLECTION.md`](EVENT_COLLECTION.md)
- Signing/tamper model: [`SIGNING_AND_TAMPER_RESISTANCE.md`](SIGNING_AND_TAMPER_RESISTANCE.md)
- Threat model: [`THREAT_MODEL.md`](THREAT_MODEL.md)
- Policy operations: [`POLICY_GUIDE.md`](POLICY_GUIDE.md)

PoC workspace reference:
- [`attested_poc/README.md`](attested_poc/README.md)

Archived older PoC example:
- [`archive/v0.1.0/POC_EXAMPLE_CODEX_SESSION.md`](archive/v0.1.0/POC_EXAMPLE_CODEX_SESSION.md)

## License

[Apache License 2.0](LICENSE)
