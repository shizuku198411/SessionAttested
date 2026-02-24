# 変更履歴

[日本語](./CHANGELOG.md) | [English](../../CHANGELOG.md)

## v0.1.1

### 追加

- 記録済み監査結果を HTTPS で閲覧できる `attested webui`
  - 署名付き証明 / verify 結果サマリ
  - 監査サマリ
  - セッション単位の `exec` / `writer` 一覧
  - workspace 累積の観測一覧
  - PASS/FAIL 付きセッション一覧
- ルート README / 日本語 README に WebUI 画像と利用方法を追加
- `POC_QUICKSTART`（英日）に WebUI 起動/確認手順を追加

### 改善

- 引数省略運用の UX 改善（`./attest/attested.yaml` 自動読込、`.attest_run/last_session_id` 利用）
- WebUI の視認性/運用性改善
  - ダークテーマ
  - テーブル形式の identity 表示
  - ポリシーマッチのハイライト
  - セッション切替と比較のしやすさ
- README の実例を `attested_poc/`（VS Code 禁止ツール比較）中心に更新

### 変更

- 主な PoC 実例を旧 Codex 例から `attested_poc/`（VS Code 禁止ツール PASS/FAIL 比較 + WebUI 画像）へ移行
- 旧 Codex PoC ドキュメント/成果物を `archive/` / `archive/v0.1.0/` へ移動

### 注記 / 既知の制約

- `attestation.json` は現時点で `.attest_run/attestations/latest/` の最新結果として保持される
  - WebUI で過去 session を切り替えた場合、verify 結果表示は `ATTESTED_SUMMARY` を参照して補完
- `ATTESTED_WORKSPACE_OBSERVED` は workspace 単位の累積ファイル
  - session 単位の `ATTESTED_OBSERVED` は現行実装では生成しない
