# Changelog

[English](./CHANGELOG.md) | [日本語](docs/jp/CHANGELOG.md)

## v0.1.1

### Added

- `attested webui` (built-in HTTPS UI) for reviewing recorded audit results
  - attestation / verification summary
  - audit summary
  - session identities (`exec` / `writer`)
  - workspace cumulative observed identities
  - session list with PASS/FAIL conclusion
- WebUI screenshots and usage guidance in top-level README / JP README
- Quickstart guidance (EN/JP) for launching and using WebUI

### Improved

- Workspace/session UX for no-argument command flows (`./attest/attested.yaml` auto-load, `.attest_run/last_session_id`)
- WebUI usability
  - dark theme
  - table-based identity views
  - policy match highlighting
  - session comparison and browsing
- README examples and PoC references updated to the VS Code forbidden-tool comparison case (`attested_poc/`)

### Changed

- Main PoC reference moved from the older Codex example to `attested_poc/` (VS Code forbidden-tool PASS/FAIL comparison + WebUI screenshots)
- Older Codex PoC documents and artifacts archived under `archive/` / `archive/v0.1.0/`

### Notes / Known Limitations

- `attestation.json` is currently kept as `latest` output in `.attest_run/attestations/latest/`
  - WebUI uses `ATTESTED_SUMMARY` to display per-session verification results when browsing older sessions
- `ATTESTED_WORKSPACE_OBSERVED` is cumulative (workspace-scoped)
  - session-scoped `ATTESTED_OBSERVED` is not generated in the current implementation
