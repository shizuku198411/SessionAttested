# 変更履歴

[日本語](./CHANGELOG.md) | [English](../../CHANGELOG.md)

## v0.1.3

### 追加

- `attested export artifact`
  - artifact 公開用 staging を CLI 本体で生成
  - 既定出力先を `attest/attested_artifacts/latest` に統一
- `attested doctor`
  - 環境/状態診断（config/state/session/attestation 整合、docker/sudo/lsm の確認）
  - workspace 設定差分（再作成が必要な可能性）を検知
- workflow 雛形生成コマンド
  - `attested workflow github-artifact`
  - `attested workflow github-verify`
- 鍵運用改善
  - `attestation.json` / `ATTESTED_SUMMARY` への署名鍵 fingerprint 記録
  - `attested verify --expected-key-fingerprint` を追加
  - `attested key fingerprint` を追加
- lineage-aware policy
  - `forbidden_exec_lineage_writes` を追加
  - `FORBIDDEN_EXEC_LINEAGE_WRITE_SEEN` 判定を追加

### 改善

- WebUI のセッション相関表示を JSON 成果物優先（`session_correlation.json`）で統一
- WebUI に commit ファイル相関の `Match Kind`（`exec` / `writer` / `exec+writer`）表示を追加
- `policy candidates` が `forbidden_exec_lineage_writes` を含む候補生成に対応
- GitHub verify workflow の安定性改善
  - eBPF 生成依存 (`clang/llvm/libbpf-dev`, `go generate`) を雛形に反映
  - artifact-only verify 実行コンテキストを固定
  - verify 結果 artifact アップロードの temp path を修正

### 変更

- トップ README を再編
  - 概要/ビルド/QuickStart を中心に簡素化
  - 詳細は `PROJECT_OVERVIEW.md`（英日）へ切り出し

## v0.1.2

### 追加

- `attestation` 成果物の session 単位保存（`latest` に加えて保存）
  - `.attest_run/attestations/sessions/<SESSION_ID>/attestation.json`
  - `.attest_run/attestations/sessions/<SESSION_ID>/attestation.sig`
  - `.attest_run/attestations/sessions/<SESSION_ID>/attestation.pub`
- `audit_summary.json.workspace_files`
  - ファイル単位の書き込み集約（`path`, `write_count`, `comms`, 解決済み `writers`, 未解決件数）
- `verify --write-result` 時に生成される session 相関 JSON
  - `.attest_run/reports/sessions/<SESSION_ID>/session_correlation.json`
  - 内容:
    - 禁止 exe 系譜 -> ファイル相関
    - commit ファイル -> writer / match kind 相関
- raw 監査ログ整合性チェック（ローカル session state がある場合）
  - `attested verify` が以下から `event_root` を再計算
    - `audit_exec.jsonl`
    - `audit_workspace_write.jsonl`
  - 以下と照合
    - `event_root.json`
    - `attestation.json` の integrity フィールド
  - 不一致時は `AUDIT_LOG_INTEGRITY_MISMATCH` で fail
- WebUI のファイル/commit 相関カード
  - `Workspace Files -> Writers (Session)`
  - `Files Touched by Forbidden Exec Lineage (Session)`
  - `Commit Files -> Writers (Session)`
- e2e 改ざん試験モード
  - `scripts/test_e2e.sh --tamper-raw-log-after-attest`
  - raw 監査ログを意図的に改ざんし、`AUDIT_LOG_INTEGRITY_MISMATCH` を検証

### 改善

- WebUI が **選択 session の `attestation.json`** を参照して表示するよう改善（常に `latest` を見ない）
- WebUI の policy 表示（`Applied Policy`）が選択 session のポリシースナップショットに追従
- WebUI の `Attestation / Verification` カードの整合性改善
  - session 固有の conclusion / reason を表示
  - `ATTESTED_SUMMARY` の verify 系 booleans は補助情報として表示
  - `ATTESTED_SUMMARY` 由来の rawログ整合性ステータス（`PASS` / `FAIL` / `not checked`）を表示
- commit 相関表示の視認性改善
  - `Match Kind`（`exec` / `writer` / `exec+writer`）
  - UI 上のみノイズパスを非表示（`.git`, `.attest_run`, `ATTESTED*`）

### 変更

- WebUI の session 相関カードは、保存済み JSON 成果物（`session_correlation.json`）を正として優先表示
  - 互換性のため、未生成時のみ従来の導出ロジックに fallback
- `ATTESTED_SUMMARY` に raw 監査ログ整合性チェック結果を記録
  - `audit_log_integrity_checked`
  - `audit_log_integrity_ok`
- `ATTESTATION_SCHEMA_EXAMPLES`（英日）に以下を追記
  - `audit_summary.json.workspace_files`
  - `session_correlation.json`

### 注記

- raw log / 監査成果物は保持し、UI 側のみ表示フィルタで可読性を上げている
- 禁止 exe 系譜相関は PID/PPID 系譜による相関証跡であり、「禁止 exe が直接 write syscall を実行した」ことを直接主張するものではない

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
