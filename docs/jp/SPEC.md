# SPEC: SessionAttested

[日本語](./SPEC.md) | [English](../../SPEC.md)


本ドキュメントは attested の PoC 仕様を定義する。PoC は Docker 上の開発コンテナを対象とし、ホスト側監査（LSM/eBPF）で得た観測結果をコミットに紐付け、署名付き証明として出力する。

本仕様の中心は「AI Agent 検出専用」ではなく、ポリシー（禁止実行体 / 許可書き込み実行体）に基づいて開発セッションのプロセス実行とワークスペース書き込みを検証する、一般的な証明基盤である。AI Agent 禁止はその代表的なポリシー適用例として扱う。

## 1. 目的と主張

### 1.1 目的
採用試験・ポートフォリオ・監査用途等において、開発セッション中のプロセス実行とワークスペース書き込みを、環境的・プロセス的な根拠により検証可能な形で提示する。

AI Agent に一任したコード実装（AI Agent が直接ファイルを書き換える形）の抑止/検証は、その具体的ユースケースのひとつである。

### 1.2 PoCが署名する主張
- 監査主体の管理下にあるホスト上で実行されたセッション `session_id` において、
  - 対象ワークスペース `/workspace`（ホスト側 bind mount）配下への write 系操作は、許可された実行体（allowed writers）からのみ発生した
  - 禁止実行体（forbidden exec; AI Agent 類を含む）の実行・書き込みは観測されなかった（ポリシー定義の範囲内）
- 上記主張を支える監査イベント集合は `event_root` により集約され、改ざん検知可能である
- 署名付き証明文書は監査主体側の署名鍵で署名される

### 1.3 非目標
- 「特定カテゴリのツールを一切利用していない」こと一般の証明（例: 別環境で生成された成果物の手動持ち込み）
- コピペ検出・プロンプト履歴の追跡
- self-hosted 環境の完全性保証（PoCは managed host を前提）

## 2. 脅威モデル（PoC）

### 2.1 想定する攻撃
- 禁止実行体（AI Agent 類を含む）が直接ワークスペースを書き換える
- ワークスペースへの書き込みを許可外のプロセスが行う
- 監査ログの改ざん・すり替え

### 2.2 想定しない攻撃（PoC外）
- 人が外部LLMに相談して手で実装する（コピペ含む）
- 監査主体がホスト管理者権限で不正を行う
- カーネル改ざん、LSM/eBPFの無効化（監査主体側の基盤セキュリティ範囲）

## 3. アーキテクチャ（PoC / Docker）

### 3.1 構成要素
- Dev Container: ユーザが作業する Docker コンテナ
- Host Audit Collector: ホスト側で LSM/eBPF によりイベントを収集するプロセス
- Attestor: 監査サマリをポリシー評価し、署名付き証明を生成して署名するCLI/サービス

### 3.2 ワークスペースの固定
- ホスト側: `/var/lib/attested-workspaces/<session_id>/`
- コンテナ内: `/workspace` に bind mount
- 監査対象は `/workspace` 配下の write 系操作に限定する

## 4. 監査イベント

### 4.1 イベント種別
PoCでは以下2種を必須とする。

- `exec`: プロセス実行イベント
- `workspace_write`: `/workspace` 配下の write 系操作（open_write/create/rename/unlink 等）

イベント形式は `schemas/audit-event.schema.json` に従う。

### 4.2 LSMフック
- `exec`: `bprm_check_security`
- `workspace_write`:
  - 最小: `file_open`（writeフラグを検知）
  - 追加: `inode_create`, `inode_unlink`, `inode_rename`

### 4.3 実行体同定
- イベントに含まれる `process.exe` は少なくとも `(inode, dev)` を持つ
- `sha256` は userspace collector が `/proc/<pid>/exe` 等から算出し補完してよい
- `path_hint` は表示・デバッグ目的であり、検証根拠としては扱わない

### 4.4 コンテナ同定
- イベントには `cgroup_id` を含める
- userspace で `cgroup_id -> container_id` を解決する
- PoCでは識別の安定性確保のため、コンテナ起動時に `--cgroup-parent /attested/<session_id>` 等の埋め込みを推奨する

## 5. セッション（session_id）

### 5.1 セッション開始/終了
- `attested start` が `session_id` を発行し、ワークスペースを作成し、監査collectorへ登録し、dev container を起動する
- `attested stop` が dev container を停止し、collector に集約確定を指示する

### 5.2 コミットとの紐付け
- PoCの最小実装は `attested attest --session <session_id> --commit <sha>` とする
- 将来拡張として `attested commit`（safe-git相当）により結び付け強化を行う

## 6. ポリシー

ポリシーは `policy/policy.yaml` で定義する。

- `forbidden_exec`: 禁止実行体（AI Agent 類を含む）を sha256 で列挙
- `forbidden_writers`: `/workspace` への書き込みを禁止する実行体を sha256 で列挙
- `allowed_writers`: 旧 whitelist モード（後方互換; 非推奨）
- `ruleset_hash`: ポリシー正規化表現の sha256（`sha256:<hex>`）

PoC評価規則:
- `exec` で forbidden が1つでも観測されたら fail
- `workspace_write` の writer が `forbidden_writers` に含まれれば fail

### 6.1 運用上の解釈（PoC時点）
PoC時点の運用では、以下の解釈を推奨する。

- `forbidden_exec`: 主判定（禁止ツール実行の検知）
- `forbidden_writers`: 補助判定（書き込み主体の補強証跡）

理由:
- 実際のツール/拡張は、内部的に `bash` / `node` / `python` などの子プロセスへ書き込みを委譲する場合がある
- そのため `workspace_write` の直接主体（writer）は、上位のオーケストレータ/Agent名と一致しないことがある
- 一方で `exec` は禁止実行体の存在検知として有効に機能する

## 7. 整合性集約（event_root）

PoCでは hash chain による `event_root` 集約（SHA-256）を採用する。

### 7.1 canonical JSON
署名・ハッシュ計算に用いる JSON 正規化規則は以下とする。

- UTF-8
- キー順を辞書順にソート
- 空白なし（コンパクト）
- 改行なし
- 数値表現はJSON標準に従う（不要な先頭ゼロ等を禁止）

### 7.2 hash chain
- `seed = "session-attested:" + session_id`（UTF-8）
- `h0 = sha256(seed)`
- 各イベント `e_i` に対して
  - `x_i = sha256(canonical_json(e_i))`
  - `h_{i+1} = sha256(h_i || x_i)`（`||` はバイト列連結）
- `event_root = h_n`（hex）
- `event_count = n`
- イベント順序は `seq` 昇順とする

## 8. 署名付き証明（attestation.json）
- 機械形式は `schemas/attestation.schema.json` に従う
- 必須情報:
  - subject（repo/commit）
  - session（session_id, workspace）
  - environment（collector情報、container情報）
  - policy（policy_id/version, ruleset_hash）
  - audit_summary（観測数、writer集合、禁止検知数）
  - integrity（event_root, alg, event_count）
  - conclusion（pass/fail と理由コード）
  - issued_at

## 9. 署名（PoC）
PoCでは ed25519 を推奨する。

- 署名対象: `attestation.json` の canonical JSON バイト列
- 出力:
  - `attestation.json`
  - `attestation.sig`（署名バイト列; base64等）
  - `attestation.pub`（検証用公開鍵; PoCでは同梱可）

## 付録A: 失敗理由コード
- `OK`
- `FORBIDDEN_EXEC_SEEN`
- `FORBIDDEN_WRITER_SEEN`
- `UNAPPROVED_WRITER_SEEN`
- `AUDIT_GAP_DETECTED`
- `INTEGRITY_MISMATCH`
- `POLICY_MISMATCH`
