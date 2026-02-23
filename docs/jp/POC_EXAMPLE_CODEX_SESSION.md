# PoC Example: Codex Write Session (Fail Case)

[日本語](./POC_EXAMPLE_CODEX_SESSION.md) | [English](../../POC_EXAMPLE_CODEX_SESSION.md)


このドキュメントは、`SessionAttested` の PoC 実行例として、Codex による書き込みを含むセッションの監査ログ/集約結果/attestation 結果をまとめたものです。

- Session ID: `28e005395ea6b8720012b3b091d826e4`
- 目的: `forbidden_exec` / `forbidden_writers` により、Codex 実行を検知して `attestation pass=false` となることを確認する
- 結果: 想定どおり `fail`

## 1. 前提と実施内容

監査対象は dev container（`/workspace`）内の開発作業です。　　
実行作業は以下の通りです。

- `VS Code` Remote SSHによるdev containerへの接続
- `Codex` 拡張のインストール/環境セットアップ
- `Codex` による新規ファイル作成: `src/create_by_codex.txt`、既存ファイル追記/編集: `src/edited_by_codex.txt`
- `attested git add/commit` による作業反映操作

## 2. 参照ファイル

以下は、公開用にホスト固有情報をマスキングした PoC 成果物コピー（`poc_artifacts/session_28e005395ea6b8720012b3b091d826e4/`）を参照しています。

セッション関連ファイル:

- `poc_artifacts/session_28e005395ea6b8720012b3b091d826e4/.attest_run/state/sessions/28e005395ea6b8720012b3b091d826e4/meta.json`
- `poc_artifacts/session_28e005395ea6b8720012b3b091d826e4/.attest_run/state/sessions/28e005395ea6b8720012b3b091d826e4/audit_exec.jsonl`
- `poc_artifacts/session_28e005395ea6b8720012b3b091d826e4/.attest_run/state/sessions/28e005395ea6b8720012b3b091d826e4/audit_workspace_write.jsonl`
- `poc_artifacts/session_28e005395ea6b8720012b3b091d826e4/.attest_run/state/sessions/28e005395ea6b8720012b3b091d826e4/audit_summary.json`
- `poc_artifacts/session_28e005395ea6b8720012b3b091d826e4/.attest_run/state/sessions/28e005395ea6b8720012b3b091d826e4/event_root.json`
- `poc_artifacts/session_28e005395ea6b8720012b3b091d826e4/.attest_run/state/sessions/28e005395ea6b8720012b3b091d826e4/commit_binding.json`

attest/verify 結果:

- `poc_artifacts/session_28e005395ea6b8720012b3b091d826e4/.attest_run/attestations/latest/attestation.json`
- `poc_artifacts/session_28e005395ea6b8720012b3b091d826e4/ATTESTED`
- `poc_artifacts/session_28e005395ea6b8720012b3b091d826e4/ATTESTED_SUMMARY`
- `poc_artifacts/session_28e005395ea6b8720012b3b091d826e4/ATTESTED_POLICY_LAST`

## 3. 監査ウィンドウ（集約結果）

`audit_summary.json` より:

- 監査期間: `2026-02-22T09:51:43Z` - `2026-02-22T09:56:44Z`
- `exec_observed.count`: `1438`
- `workspace_writes_observed.count`: `9`
- `exec_observed.identity_unresolved`: `19`
  - Codex 実行全体の検知を阻害する状況ではなく、一部補助実行体（`lsb_release` 等）の identity 解決失敗が含まれる

## 4. Exec 検知（Codex 実行体の観測）

`audit_exec.jsonl` では、Codex 実行体および Codex が内部で起動した補助プロセス群が観測されています。

代表例:

```json
{"seq":418,"pid":318728,"ppid":318554,"comm":"node","filename":"/home/dev/.vscode-server/extensions/openai.chatgpt-0.4.76-linux-arm64/bin/linux-aarch64/codex"}
```

```json
{"seq":1009,"pid":318944,"ppid":318728,"comm":"codex","filename":"/home/dev/.vscode-server/extensions/openai.chatgpt-0.4.76-linux-arm64/bin/linux-aarch64/codex"}
```

また、Codex の一時実行ディレクトリ配下からの補助実行（`git`, `lsb_release`, `getconf` など）も多数確認できます。

例:

```json
{"comm":"tokio-runtime-w","filename":"/home/dev/.codex/tmp/arg0/codex-arg09YmlgZ/git"}
```

## 5. Workspace Write 検知（Codex による書き込み）

`audit_workspace_write.jsonl` では、対象ファイルへの書き込みイベントが記録されています。

今回のセッションでは `comm="codex"` として直接観測されました（以前のセッションではツール実装/委譲により `bash` として見えるケースもあり）。

代表例:

```json
{"seq":1010,"pid":318944,"ppid":318728,"comm":"codex","filename":"/workspace/src/create_by_codex.txt","op":"open_write"}
```

```json
{"seq":1011,"pid":318944,"ppid":318728,"comm":"codex","filename":"/workspace/src/edited_by_codex.txt","op":"open_write"}
```

## 6. 集約 identity（executed / writer）

`audit_summary.json` の集約結果では、VS Code / Codex 関連実行体が fingerprint（SHA-256）付きで記録されています。

### 6.1 executed_identities（抜粋）

- VS Code Server:
  - `/home/dev/.vscode-server/cli/servers/.../server/node`
  - `/home/dev/.vscode-server/cli/servers/.../server/bin/code-server`
  - `/home/dev/.vscode-server/code-...`
- Codex 拡張実行体:
  - `/home/dev/.vscode-server/extensions/openai.chatgpt-0.4.76-linux-arm64/bin/linux-aarch64/codex`
  - `sha256:f211b442bfb2eb20e4d6d7c0593b34ec421a5bcd630873c69ed7aaedeea28a26`

### 6.2 writer_identities（抜粋）

このセッションでは、workspace write 主体として Codex 実行体そのものが解決されています。

- `/home/dev/.vscode-server/extensions/openai.chatgpt-0.4.76-linux-arm64/bin/linux-aarch64/codex`
  - `sha256:f211b442bfb2eb20e4d6d7c0593b34ec421a5bcd630873c69ed7aaedeea28a26`

## 7. ポリシー評価（attest）

`attestation.json` の `conclusion` より、結果は `pass=false` です。

理由（抜粋）:

- `FORBIDDEN_EXEC_SEEN`
  - `count=1`
  - sample: Codex 実行体 SHA (`sha256:f211b442b...`)
- `FORBIDDEN_WRITER_SEEN`
  - `count=1`
  - sample: Codex 実行体 SHA (`sha256:f211b442b...`)

つまり、このセッションでは

- 禁止された実行体（Codex）が `exec` として観測され
- かつ workspace write 主体としても観測された

ため、PoC の意図どおり `fail` になります。

## 8. Verify 結果（ATTESTED / ATTESTED_SUMMARY）

`poc_artifacts/session_28e005395ea6b8720012b3b091d826e4/ATTESTED_SUMMARY` の該当レコードより:

- `session_id`: `28e005395ea6b8720012b3b091d826e4`
- `verify_ok`: `false`
- `attestation_pass`: `false`
- `policy_checked`: `true`
- `policy_match`: `true`
- `reason`: `FORBIDDEN_EXEC_SEEN: count=1 samples=[sha256:f211b442b(.../codex)]`
- `repo`: `shizuku198411/sandbox`
- `commit_sha`: `3a1e62a00e3640b6e65cf1620c85a2dc23beef76`

この結果は、

- 署名検証/形式検証は通るが
- ポリシー評価結果として fail（禁止実行体観測）

という想定どおりの負ケース結果です。

## 9. この PoC 実例から読み取れること

このセッションは、`SessionAttested` の PoC として以下を示しています。

- dev container 内の `exec` / `workspace write` を監査ログとして取得できる
- VS Code 拡張配下の Codex 実行体を fingerprint 付きで集約できる
- policy (`forbidden_exec`, `forbidden_writers`) により `attestation pass=false` を再現できる
- `verify` 結果を `ATTESTED_SUMMARY` に残せる

## 10. PoC実行手順

本PoCの再現可能性を示すため、以下に実行手順を記載します。

### 前提
- ホスト側に作業対象リポジトリのディレクトリ(workspace)を用意
- 本PoCではホスト側でgit init/git branch -M main/git remote add origin実行済み

### attested設定ファイル(実行環境定義)
```attested.yaml
defaults:
  state_dir: /sandbox/.attest_run/state

commands:
  start:
    image: attest_base:latest
    pull: false
    build: true
    dockerfile: Dockerfile
    auto_collect: true
    auto_collect_sudo: true
    auto_collect_wait: 10s
    inject_session_env: true
    mount_attested_bin: true
    attested_bin_container_path: /usr/local/bin/attested
    git_user_name: "git user"
    git_user_email: "git user email"
    build_arg:
      - "DEV_UID=1000"
      - "DEV_GID=1003"
    publish:
      - "0.0.0.0:2222:22/tcp"
    workspace_host: /sandbox

  collect:
    until_stop: true
    poll: 300ms
  
  stop:
    collector_wait: 20s
  
  commit:
    repo_path: /sandbox
    message: "sandbox: attested flow"
  
  attest:
    repo: git/sandbox
    policy: /sandbox/.attest_run/policy.sandbox.yaml
    out: /sandbox/.attest_run/attestations/latest
    signing_key: /sandbox/.attest_run/keys/attestation_priv.pem
    key_id: sandbox-key-1
    issuer_name: sandbox-attestor
    use_binding: true
  
  verify:
    policy: /sandbox/.attest_run/policy.sandbox.yaml
    require_pass: true
```

### Policy
```
# source: /sandbox/.attest_run/state/sessions/28e005395ea6b8720012b3b091d826e4/audit_summary.json
# session_id: 28e005395ea6b8720012b3b091d826e4

policy_id: candidate-28e005395ea6b8720012b3b091d826e4
policy_version: 1.0.0
forbidden_exec:
    - sha256: sha256:f211b442bfb2eb20e4d6d7c0593b34ec421a5bcd630873c69ed7aaedeea28a26
      comment: /home/dev/.vscode-server/extensions/openai.chatgpt-0.4.76-linux-arm64/bin/linux-aarch64/codex
forbidden_writers:
    - sha256: sha256:f211b442bfb2eb20e4d6d7c0593b34ec421a5bcd630873c69ed7aaedeea28a26
      comment: /home/dev/.vscode-server/extensions/openai.chatgpt-0.4.76-linux-arm64/bin/linux-aarch64/codex
exceptions: []
```

1. (ホスト側)新規Session開始  
`attested start --config ./attest/attested.yaml --json`  
-> ホスト側2222/tcpでSSH接続を待ち受けるdev containerが起動
2. VS Code RemoteSSHよりdev containerへ接続
3. VS Code `Codex` 拡張をインストール/環境セットアップ
4. Codexへファイル作成/編集の指示を実行  
```
   -- input --
   Codex動作確認のため、
   1. ./src/create_by_codex.txtの新規作成/内容記載
   2. ./src/edited_by_codex.txt(すでに作成済み)のファイルへ内容追記
   この2点の対応をお願いします。

   -- output --
   対応しました。

   1. 新規作成: `src/create_by_codex.txt`
   2. 追記: `src/edited_by_codex.txt`

   反映内容は以下です。

   - `src/create_by_codex.txt`
     - `This file was created by Codex.`
     - `Created for operation check.`

   - `src/edited_by_codex.txt`
     - 既存内容に加えて `Additional line appended by Codex for operation check.` を追記済みです。
```
5. `attested git add .`　および　`attested git commit -m 'codex'` を実行
6. Session終了  
`attested stop --config ./attest/attested.yaml --session "$SESSION_ID"`
7. Policy作成  
`attested policy candidates --session "$SESSION_ID" --state-dir "$PWD/.attest_run/state" --include-exec`  
-> Policy候補が作成されるため、`Codex`をforbidden exec/writerに登録
8. 評価  
`attested attest --config ./attest/attested.yaml --session "$SESSION_ID"`  
-> `attestation pass=false`
9. 評価結果を含む監査記録のVerify  
`attested verify --config ./attest/attested.yaml --attestation .attest_run/attestations/latest/attestation.json --signature .attest_run/attestations/latest/attestation.sig --public-key .attest_run/attestations/latest/attestation.pub --write-result --binding ".attest_run/state/sessions/$SESSION_ID/commit_binding.json"`  
-> NG (FORBIDDEN_EXEC_SEEN: count=1 samples=[sha256:f211b442b(/home/dev/.vscode-server/extensions/openai.chatgpt-0.4.76-linux-arm64/bin/linux-aarch64/codex)]). attestation pass=false = 評価fail理由のSummaryを確認可能
