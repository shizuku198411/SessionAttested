# Policy Guide

[日本語](./POLICY_GUIDE.md) | [English](../../POLICY_GUIDE.md)


このドキュメントは、`SessionAttested` のポリシー設計・更新・運用の実務向けガイドです。

PoC 時点の推奨方針:

- `forbidden_exec` を主判定に使う
- `forbidden_writers` を補助判定に使う

## 1. ポリシーの役割

ポリシーは、監査結果（`audit_summary.json`）に含まれる実行体/書き込み主体 identity を評価し、

- 許容するか
- 検証 fail にするか

を定義します。

PoC では「禁止対象を列挙する blocklist 形式」を基本とします。

## 2. 主要フィールド（PoC）

代表的なポリシーフォーマット:

```yaml
policy_id: "sandbox-policy"
policy_version: "1.0.0"

forbidden_exec: []
forbidden_writers: []

exceptions: []
```

### 2.1 `forbidden_exec`

- `executed_identities`（exec 集約）に対する禁止リスト
- AI Agent / 特定ツールの起動検知を主目的に使う

推奨用途:

- `codex`, `claude`, 特定 extension binary
- 組織で禁止したいコード生成/取得ツール

### 2.2 `forbidden_writers`

- `writer_identities`（workspace write 主体集約）に対する禁止リスト
- 補助証拠として使う

推奨用途:

- 直接 write 主体として安定して観測される実行体（例: 特定 editor backend）
- `forbidden_exec` と同じ hash を重ねて検証強化したい場合

### 2.3 `exceptions`

PoC では詳細運用は限定的ですが、将来的な例外（特定条件で許容）のための拡張余地です。

## 3. 判定の重みづけ

### 主判定: `forbidden_exec`

`exec` は、禁止ツール本体の存在検知に向いています。

- 上位ツールが `bash` や `node` に書き込みを委譲しても本体起動は `exec` 側で検知できることが多い

そのため、AI Agent 利用検知/不使用検証では `forbidden_exec` を主判定に置くのが実務的です。

### 補助判定: `forbidden_writers`

`workspace_write` は有用ですが、書き込み主体が実装依存で変化します。

例:

- `codex` として直接見えるケース
- `bash` / `node` / `python` として見えるケース

よって `forbidden_writers` は補助判定・補強証拠として使うのが安全です。

## 4. 候補ポリシーの作り方（推奨フロー）

### 4.1 セッションを実行して監査結果を得る

- `attested start`
- 開発作業
- `attested stop --run-attest --run-verify --verify-write-result`

### 4.2 候補を生成する

`audit_summary.json` から candidate policy を生成:

```bash
attested policy candidates \
  --session <SESSION_ID> \
  --state-dir <RUN_DIR>/state
```

出力例:

- `<RUN_DIR>/policy.<SESSION_ID>.candidate.yaml`

### 4.3 レビューして昇格する

- candidate をレビュー
- 不要なエントリ（ノイズ）を削除
- `policy_id` を本番用に変更
- `policy.sandbox.yaml` などへ rename / コピー

## 5. レビュー時の観点

### 5.1 まず確認すること

- `audit_summary.json.executed_identities`
- `audit_summary.json.writer_identities`
- `exec_observed.identity_unresolved`

### 5.2 禁止候補にしやすいもの

- 明確に禁止したい AI Agent / CLI / extension binary
- 一意性が高い path/hash を持つ実行体
- セッションに不自然なツール（ダウンローダ、外部実行器など）

### 5.3 すぐ禁止にしない方がよいもの

- 汎用 shell（`/bin/bash`）
- 汎用 interpreter（`python`, `node`）
- editor 基盤共通の実行体

これらは誤検知の影響が大きいです。禁止する場合は運用目的と例外方針を先に決めてください。

## 6. 運用パターン（例）

### 6.1 AI Agent 不使用検証（PoC の主用途）

- `forbidden_exec`: AI Agent 実行体 hash を登録
- `forbidden_writers`: 同 hash を必要に応じて登録

期待結果:

- 該当ツール未使用セッション -> `pass=true`
- 使用セッション -> `pass=false`（`FORBIDDEN_EXEC_SEEN`）

### 6.2 監査強化（補助）

- `forbidden_writers` に特定 writer を追加し、
- 「禁止ツール本体が write まで到達した」ことも fail 条件に加える

## 7. ポリシー更新のタイミング

以下のタイミングで見直しを推奨します。

- VS Code / extension / toolchain の更新後
- コンテナベースイメージ変更後
- `identity_unresolved` が増えた時
- 誤検知/見逃しが発生した時

## 8. 失敗時の読み方（attest / verify）

`attestation.json` / `verify` 出力の `reason` / `detail` には、違反 identity のサンプルが出ます。

例:

- `FORBIDDEN_EXEC_SEEN`
- `FORBIDDEN_WRITER_SEEN`

確認手順:

1. `reason.detail` の `sha256` / `path_hint` を見る
2. `audit_summary.json` の identity 配列で一致確認
3. 必要に応じて `audit_exec.jsonl` / `audit_workspace_write.jsonl` を追う
