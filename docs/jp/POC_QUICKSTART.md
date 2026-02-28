# PoC Quickstart (Build & Usage)

[日本語](./POC_QUICKSTART.md) | [English](../../POC_QUICKSTART.md)


このドキュメントは、`SessionAttested` を PoC として試すユーザ向けの最短手順です。

対象:

- `attested` バイナリをビルドして使いたい
- dev container 上の作業を監査したい
- `attest` / `verify` まで一通り試したい

詳細仕様は以下を参照してください。

- `ATTESTATION_FLOW.md`
- `EVENT_COLLECTION.md`
- `POLICY_GUIDE.md`
- `ATTESTATION_SCHEMA_EXAMPLES.md`

## 1. 前提

- Linux ホスト（eBPF 利用可能）
- Docker が利用可能
- `sudo` で collector を起動できる
- Go（ビルド用）
- OpenSSL（署名鍵生成用）

補足:

- PoC では dev container 方式を前提にしています（監査対象の切り出し/ノイズ削減のため）

## 2. `attested` をビルド

```bash
cd /path/to/session-attested
go build -o attested ./cmd/attested
```

任意で PATH に置く場合:

```bash
sudo install -m 0755 ./attested /usr/local/bin/attested
```

## 3. 作業用 workspace を用意（PoC 用）

新規ディレクトリを用意し、Git 初期化します。

```bash
mkdir -p ~/work/sessionattested-sandbox
cd ~/work/sessionattested-sandbox
git init
git branch -M main
```

必要に応じて:

- `git remote add origin <your-repo-url>`

## 4. workspace 初期化（推奨）

最も簡単なのは、`workspace init` に scaffold 生成を任せる方法です。

```bash
attested workspace init
```

デフォルトで準備されるもの:

- workspace 登録（`.attest_run/state/workspaces/...`）
- `attest/attested.yaml`（設定雛形）
- `attest/Dockerfile`（dev container 雛形）
- `attest/policy.yaml`（ポリシー雛形）
- `.gitignore`（ローカル監査成果物向け managed block）
- dev container（作成され、停止状態で保持）

補足:

- 対話形式で workspace 名/パス、image、build/pull、GitHub repo、git user、SSH鍵マウントの有無などを埋められます
- 多くのケースでは `attested.yaml` を手で用意する必要はありません

## 5. PoC 用ファイルを手動で配置（任意）

`workspace init` を使わず手動でセットアップしたい場合は、最低限以下を用意します。

- `Dockerfile`（dev container 用）
- `attest/attested.yaml`（PoC 設定）

このリポジトリのサンプルを流用する場合（例）:

```bash
mkdir -p attest
cp /path/to/session-attested/example/attested.config.yaml ./attest/attested.yaml
cp /path/to/session-attested/example/docker/ubuntu-24.04-ssh/Dockerfile ./Dockerfile
```

その後、`attest/attested.yaml` を workspace に合わせて修正します。

最低限確認する項目（`commands.start`）:

- `workspace_host` : ホスト側 workspace の絶対パス
- `image` : 起動するイメージ名
- `build` : `true`（PoC ではビルド起動が簡単）
- `dockerfile` : `Dockerfile`
- `publish` : SSH 用（例: `127.0.0.1:2222:22/tcp`）
- `auto_collect` : `true` 推奨

最低限確認する項目（`commands.attest` / `commands.verify`）:

- `policy`
- `out`
- `signing_key`
- `require_pass`

## 6. セッション開始（container 起動 + collector 自動起動）

```bash
attested start --json
```

出力 JSON から以下を控えます。

- `session_id`
- `container_id`

補足:

- `auto_collect: true` の場合、collector はバックグラウンド起動されます
- `ATTESTED_SESSION_ID` / `ATTESTED_STATE_DIR` はコンテナ内にも注入されます
- `./attest/attested.yaml` が存在すれば自動読込されるため、通常は `--config` は不要です
- `start` 成功時に `.attest_run/last_session_id` が自動更新されます
- `keep_container: true` の場合、`stop` してもコンテナは削除されないため、同じ環境でセッションを繰り返せます

## 7. dev container に接続して作業

SSH ポート公開を設定している場合の例:

```bash
ssh dev@127.0.0.1 -p 2222
```

PoC 例:

- ファイル作成/編集
- `attested git add`
- `attested git commit`
- `attested git push`（必要なら）

コンテナ内での例:

```bash
cd /workspace
attested git status
attested git add -A
attested git commit -m "poc: first commit"
```

補足:

- `attested git commit` は `ATTESTED_SESSION_ID` を使うため、`--session` は通常不要です

## 8. Git 操作はホスト側 / コンテナ内のどちらでも可能

運用ポリシーに応じて、Git 操作の実施場所を選べます。

- 被監査主体が dev container 内で `attested git push` まで行う
- 監査主体が host 側で `attest/verify` の pass を確認してから push する

実行方法の例:

- コンテナ内: `attested git add/commit/push`
- ホスト側: 通常の `git` または `attested git ...`

## 9. セッション終了 + attest/verify

PoC では `stop` 時にまとめて実行するのが簡単です。

```bash
attested stop --run-attest --run-verify --verify-write-result
```

これにより以下が生成/更新されます（設定次第）。

- `.attest_run/state/sessions/<SESSION_ID>/...`
- `.attest_run/attestations/latest/attestation.json`
- `ATTESTED`
- `ATTESTED_SUMMARY`
- `ATTESTED_POLICY_LAST`
- `ATTESTED_WORKSPACE_OBSERVED`

## 10. セッションは作業単位で繰り返し利用できる（コンテナ再利用）

`start` / `stop` は、コンテナの作成/削除ではなく **作業単位（session 単位）** として繰り返す使い方が基本です。

- `start` : 登録済みコンテナを起動（または再利用）して新しい session を開始
- `stop` : session を finalize し、通常はコンテナを停止（削除しない）

そのため、インストール済みツール、キャッシュ、VS Code Server 状態などの開発環境を維持したまま、監査だけを session 単位で区切れます。

## 11. 結果の確認（最初に見る場所）

まずは以下を見ると全体像を把握しやすいです。

- `ATTESTED_SUMMARY`
  - `verify_ok`, `attestation_pass`, `reason`
- `.attest_run/state/sessions/<SESSION_ID>/audit_summary.json`
  - `executed_identities`, `writer_identities`
- `.attest_run/attestations/latest/attestation.json`
  - `conclusion.reasons`
- `ATTESTED_WORKSPACE_OBSERVED`
  - workspace 全体で累積観測された exec / writer identity（未解決件数/ヒント含む）

## 12. WebUI での確認（任意だが推奨）

SessionAttested には、監査結果を視覚的に確認できるローカル HTTPS WebUI があります。

```bash
attested webui
```

別ポート/公開範囲で起動する例:

```bash
attested webui --addr 0.0.0.0:9443
```

最初に見るとよい項目:

- `Attestation / Verification` カード（`PASS` / `FAIL`, reason code）
- `Audit Summary` カード（件数 / 未解決数）
- `Executed Identities (Session)` / `Writer Identities (Session)`（ポリシーマッチのハイライト）
- `See other sessions`（セッションごとの PASS/FAIL 比較）

補足:

- TLS は自己署名証明書のため、ブラウザ警告が出ます（想定どおり）
- UI で別セッションを選択すると `ATTESTED_SUMMARY` を元に表示結果が切り替わります

## 13. v0.1.3 の運用補助コマンド（`doctor` / `export artifact` / workflow 雛形）

### 13.1 ローカル環境と状態の診断

```bash
attested doctor
```

JSON で確認する場合:

```bash
attested doctor --json
```

主に確認できる内容:

- config / session / state の整合
- docker / sudo / lsm の基本状態
- workspace コンテナ設定差分（再作成が必要な可能性）
- attestation / 署名鍵 fingerprint の整合ヒント

### 13.2 Artifact staging の出力

```bash
attested export artifact
```

既定出力先:

- `attest/attested_artifacts/latest`

raw ログも含める場合:

```bash
attested export artifact --include-raw-logs
```

### 13.3 GitHub workflow 雛形の生成

Artifact 公開用:

```bash
attested workflow github-artifact
```

GitHub 上で verify 実行する雛形（workflow内で SessionAttested を clone/build）:

```bash
attested workflow github-verify
```

## 14. ポリシー候補の生成（PoC で便利）

監査結果から candidate policy を生成できます。

```bash
attested policy candidates
```

出力例:

- `.attest_run/policy.<SESSION_ID>.candidate.yaml`

レビュー後に rename して本番ポリシーとして利用します。

## 15. PoC でよくあるハマりどころ

### collector が起動しない / finalize されない

- `sudo` 権限を確認
- `collector.log` を確認
- カーネルの LSM hook 対応状況を確認（tracepoint fallback あり）

### `verify` が fail する

- `ATTESTED_SUMMARY.reason` と `attestation.json.conclusion.reasons` を確認
- `forbidden_exec` / `forbidden_writers` に引っかかっていないか確認
- `policy_match=false` の場合は使用ポリシーが一致しているか確認
- `AUDIT_LOG_INTEGRITY_MISMATCH` の場合:
  - 最新の `attested` バイナリを使っているか確認
  - `.attest_run/state/sessions/<SESSION_ID>/` 配下の raw 監査ログが収集後に編集/差し替えされていないか確認
  - `event_root.json` と対象 session の `attestation.json`（`integrity.event_root`, `integrity.event_count`）を確認

### writer identity が期待通りに見えない

- `audit_workspace_write.jsonl` の `comm` と `audit_summary.json.writer_identities` は一致しないことがある
- まず `forbidden_exec` を主判定にする（`POLICY_GUIDE.md` 参照）

### `publish` や mount 設定を変えたのに反映されない

- Docker のポート公開や bind mount はコンテナ作成時に固定されます
- `attest/attested.yaml` の `publish` / SSH鍵マウント / `mount_attested_bin` 等を変更した場合は、コンテナ再作成が必要です
  - `attested workspace rm`
  - `attested workspace init`

## 16. 次のステップ

- `POLICY_GUIDE.md` を参照して禁止ツールポリシーを整備する
- `THREAT_MODEL.md` を参照して、監査主張の範囲を明確化する
