# SessionAttested

[日本語](./README.md) | [English](../../README.md)

![Version](https://img.shields.io/badge/version-v0.1.3-blue)
![Status](https://img.shields.io/badge/status-PoC-orange)

**SessionAttested** は、**ポリシーベースの開発セッション証明フレームワーク**です。
ホスト側で `exec` / workspace write を観測し、commit へ紐づけ、署名付きで検証可能な成果物を出力します。

本プロジェクトは、**Development-Session Attestation (DSA)** を実現する具体的実装アプローチでもあります。
参照: [`DSA.md`](DSA.md)

## ビルド

前提（一般的な環境）:
- Linux ホスト
- Docker
- Go
- clang/llvm + libbpf 開発ヘッダ（eBPF 生成用）

ビルド:

```bash
./scripts/build.sh build
```

または:

```bash
go generate ./internal/collector/ebpf
go build -o attested ./cmd/attested
```

## クイックスタート

以下を参照してください:
- [`POC_QUICKSTART.md`](POC_QUICKSTART.md)

含まれる内容:
- workspace/session の基本フロー
- attest/verify
- `attested webui`
- artifact export と GitHub workflow 雛形

## ドキュメント

主要ドキュメント:
- 変更履歴: [`CHANGELOG.md`](CHANGELOG.md)
- DSA 概念: [`DSA.md`](DSA.md)
- 詳細概要（ユースケース/アーキテクチャ/強み）: [`PROJECT_OVERVIEW.md`](PROJECT_OVERVIEW.md)
- エンドツーエンドフロー: [`ATTESTATION_FLOW.md`](ATTESTATION_FLOW.md)
- 出力スキーマ例: [`ATTESTATION_SCHEMA_EXAMPLES.md`](ATTESTATION_SCHEMA_EXAMPLES.md)
- イベント収集詳細: [`EVENT_COLLECTION.md`](EVENT_COLLECTION.md)
- 署名と改ざん困難性: [`SIGNING_AND_TAMPER_RESISTANCE.md`](SIGNING_AND_TAMPER_RESISTANCE.md)
- 脅威モデル: [`THREAT_MODEL.md`](THREAT_MODEL.md)
- ポリシー運用: [`POLICY_GUIDE.md`](POLICY_GUIDE.md)

PoC workspace 実例:
- [`attested_poc/README_jp.md`](../../attested_poc/README_jp.md)

旧 PoC 実例（アーカイブ）:
- [`archive/v0.1.0/POC_EXAMPLE_CODEX_SESSION.md`](../../archive/v0.1.0/POC_EXAMPLE_CODEX_SESSION.md)

## ライセンス

[Apache License 2.0](../../LICENSE)
