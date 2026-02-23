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

## 4. PoC 用ファイルを workspace に配置

最低限必要なもの:

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

## 5. セッション開始（container 起動 + collector 自動起動）

```bash
attested start --config ./attest/attested.yaml --json
```

出力 JSON から以下を控えます。

- `session_id`
- `container_id`

補足:

- `auto_collect: true` の場合、collector はバックグラウンド起動されます
- `ATTESTED_SESSION_ID` / `ATTESTED_STATE_DIR` はコンテナ内にも注入されます

## 6. dev container に接続して作業

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

## 7. セッション終了 + attest/verify

PoC では `stop` 時にまとめて実行するのが簡単です。

```bash
attested stop \
  --config ./attest/attested.yaml \
  --session <SESSION_ID> \
  --run-attest \
  --run-verify \
  --verify-write-result
```

これにより以下が生成/更新されます（設定次第）。

- `.attest_run/state/sessions/<SESSION_ID>/...`
- `.attest_run/attestations/latest/attestation.json`
- `ATTESTED`
- `ATTESTED_SUMMARY`
- `ATTESTED_POLICY_LAST`

## 8. 結果の確認（最初に見る場所）

まずは以下を見ると全体像を把握しやすいです。

- `ATTESTED_SUMMARY`
  - `verify_ok`, `attestation_pass`, `reason`
- `.attest_run/state/sessions/<SESSION_ID>/audit_summary.json`
  - `executed_identities`, `writer_identities`
- `.attest_run/attestations/latest/attestation.json`
  - `conclusion.reasons`

## 9. ポリシー候補の生成（PoC で便利）

監査結果から candidate policy を生成できます。

```bash
attested policy candidates \
  --session <SESSION_ID> \
  --state-dir ./.attest_run/state
```

出力例:

- `.attest_run/policy.<SESSION_ID>.candidate.yaml`

レビュー後に rename して本番ポリシーとして利用します。

## 10. PoC でよくあるハマりどころ

### collector が起動しない / finalize されない

- `sudo` 権限を確認
- `collector.log` を確認
- カーネルの LSM hook 対応状況を確認（tracepoint fallback あり）

### `verify` が fail する

- `ATTESTED_SUMMARY.reason` と `attestation.json.conclusion.reasons` を確認
- `forbidden_exec` / `forbidden_writers` に引っかかっていないか確認
- `policy_match=false` の場合は使用ポリシーが一致しているか確認

### writer identity が期待通りに見えない

- `audit_workspace_write.jsonl` の `comm` と `audit_summary.json.writer_identities` は一致しないことがある
- まず `forbidden_exec` を主判定にする（`POLICY_GUIDE.md` 参照）

## 11. 次のステップ

- `POLICY_GUIDE.md` を参照して禁止ツールポリシーを整備する
- `THREAT_MODEL.md` を参照して、監査主張の範囲を明確化する
