# Attestation Flow (PoC)

[日本語](./ATTESTATION_FLOW.md) | [English](../../ATTESTATION_FLOW.md)


このドキュメントは、現時点の `SessionAttested` PoC における署名付き証明の運用フローを、

- `監査主体` / `被監査主体` のどちらの作業か
- その時点で何が行われるか

の観点で整理したものです。

## 前提

- 監査主体が管理するホスト上で `attested` を実行する
- 被監査主体は dev container（例: VS Code Remote SSH）内で作業する
- ワークスペースはコンテナ内 `/workspace` に bind mount される

## 役割

- `監査主体`:
  - セッション開始/終了
  - 監査 collector の制御
  - policy 生成/選定
  - 署名付き証明の生成/verify
- `被監査主体`:
  - dev container 内で実装作業
  - `attested git ...` を使った Git 操作（add/commit/push）

## 1. セッション開始（監査主体）

### 実行コマンド（ホスト）

```bash
attested start --json
```

### ここで行われること

- `session_id` を発行
- dev container を起動（必要に応じて image build / pull）
- `/workspace` bind mount を構成
- （設定時）collector をバックグラウンド起動（`auto_collect`）
- state/run ディレクトリ初期化
- 署名鍵が未作成なら自動生成
- コンテナ内へ `ATTESTED_SESSION_ID` / `ATTESTED_STATE_DIR` などを注入
- （設定時）Git user / SSH 鍵設定をコンテナへ注入

### 監査上の意味

- 以降の `exec` / `workspace write` は `session_id` 単位で集約される
- `start` / `stop` を繰り返すことで、同じ dev container 環境を維持したまま session を分けられる

## 2. 開発作業（被監査主体）

### 実行場所（コンテナ内）

- SSH で dev container に接続（例: VS Code Remote SSH）
- 作業ディレクトリ: `/workspace`

### ここで行われること

- コード編集（エディタ / shell / ツール）
- コマンド実行
- ファイル生成/更新

### 監査主体側で裏で起きていること

- eBPF collector が `exec` を収集
- `/workspace` 配下の write 系操作を収集
- `audit_exec.jsonl` / `audit_workspace_write.jsonl` の元データを蓄積

## 3. Git 操作（被監査主体）

### 実行コマンド（コンテナ内）

```bash
attested git status
attested git add -A
attested git commit -m "message"
attested git push -u origin main
```

### ここで行われること

- `attested git commit` は `attested commit` に委譲される
- commit 実行後に commit binding を記録
  - 最新: `commit_binding.json`
  - 履歴: `commit_bindings.jsonl`

### 監査上の意味

- セッションと commit（複数可）の紐付けが state に保存される

## 4. セッション終了 / 監査集約（監査主体）

### 実行コマンド（ホスト）

```bash
attested stop
```

または自動連携付き:

```bash
attested stop \
  --run-attest \
  --run-verify \
  --verify-write-result
```

### ここで行われること

- collector に finalize を指示
- `audit_summary.json` を生成
- `event_root.json` を生成（hash chain）
- （設定に応じて）コンテナ停止、または停止+削除
- （`--run-attest` 指定時）署名付き証明を生成
- （`--run-verify` 指定時）verify 実行

### 監査上の意味

- session の監査イベント集合が `event_root` とサマリに確定する

## 5. Policy 候補生成（監査主体）

### 実行コマンド（ホスト）

```bash
attested policy candidates \
  --session "$SESSION_ID"
```

必要に応じて `exec` も候補化:

```bash
attested policy candidates \
  --session "$SESSION_ID" \
  --include-exec
```

### ここで行われること

- `audit_summary.json` の `writer_identities`（必要に応じて `executed_identities`）から fingerprint 候補を抽出
- 正規ポリシーフォーマットの `.candidate.yaml` を生成
  - 例: `.attest_run/policy.<session_id>.candidate.yaml`

### 監査主体の判断

- `.candidate` を review
- 問題なければ rename / copy して本番ポリシーとして採用

## 6. 署名付き証明の生成（監査主体）

### 実行コマンド（ホスト）

```bash
attested attest
```

### ここで行われること

- `audit_summary.json`, `event_root.json`, `meta.json`, commit binding を読み込む
- policy を評価
  - `forbidden_exec`（主判定）
  - `forbidden_writers`（補助判定）
- `attestation.json` を生成
- `attestation.sig`（署名）を生成
- `attestation.pub`（公開鍵）を出力

### 監査上の意味

- セッション監査結果 + commit + policy 評価結果を署名付きで固定化

## 7. Verify / 記録化（監査主体）

### 実行コマンド（ホスト）

```bash
attested verify \
  --write-result
```

### ここで行われること

- 署名検証
- policy hash / commit binding の整合性検証
- `require-pass` 条件の判定
- 実行ディレクトリに結果ファイルを記録
  - `ATTESTED`（マーカー）
  - `ATTESTED_SUMMARY`（session ごとの結果一覧）
  - `ATTESTED_POLICY_LAST`（指定 policy のスナップショット）
  - `ATTESTED_WORKSPACE_OBSERVED`（workspace 累積の観測一覧）

### 監査上の意味

- 署名付き証明の検証結果が監査記録として再利用可能な形で残る

## 8. GitHub Artifact 連携（任意 / 監査主体 or CI）

### 何をするか

- 生成済みの `attestation.json/.sig/.pub` と policy / binding をリポジトリへ配置
- GitHub Actions で Artifact として公開/保管
- （任意）CI 側に `attested` バイナリ/実行環境がある場合は `verify` 再実行

### 監査上の意味

- ローカル検証に加えて、第三者が参照可能な再検証フローを提供できる

## 運用上の解釈（PoC時点）

- `forbidden_exec` は主判定
  - 禁止ツール（Codex IDE / Agent / CLI 等）の存在検知に有効
- `forbidden_writers` は補助判定
  - write の直接主体は `bash` / `node` 等に見える場合があるため、ツール内部実装に依存する

そのため、PoC時点の実運用では以下の解釈が現実的です。

- `exec` で禁止実行体を確実に検知する
- `writer` は書き込み主体の状況証拠として補強に使う
