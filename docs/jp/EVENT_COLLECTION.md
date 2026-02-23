# Event Collection Mechanism (PoC)

[日本語](./EVENT_COLLECTION.md) | [English](../../EVENT_COLLECTION.md)


このドキュメントは、SessionAttested PoC におけるイベント収集の仕組み（主に eBPF collector）を説明します。

対象:
- `exec`（プロセス実行）
- `workspace_write`（`/workspace` 配下への write 系操作）

## 1. 全体像

PoC では、監査主体が管理するホスト上で eBPF collector を動かし、dev container 内の実行/書き込みイベントをホスト側で収集します。

大まかな流れ:

1. `attested start` で session を開始し、collector（常駐 or 手動）を起動
2. collector が eBPF プログラムから ringbuf 経由でイベントを受信
3. session（container）にイベントを紐付け
4. `audit_exec.jsonl` / `audit_workspace_write.jsonl` と内部集約状態に反映
5. `attested stop` 時に `audit_summary.json` / `event_root.json` を生成

## 2. 収集ロケーション

- 監査の根拠はコンテナ内ではなく **ホスト側** に置く
- 被監査主体（dev container）内のプロセスが collector を停止/改ざんしにくい
- コンテナ内ツール（VS Code, Agent, shell など）を統一的に観測できる

## 3. eBPFアタッチ方式（PoC）

環境差分に対応するため、複数のアタッチ方式を持ちます。

- 優先: LSM フック
  - `bprm_check_security`（exec 監視）
- 追加: tracepoint
  - `syscalls/sys_enter_openat`（write 系の最小検知）
- fallback: tracepoint ベース exec
  - `sys_enter_execve`
  - `sys_enter_execveat`

実行環境によっては LSM hook が利用できないため、tracepoint fallback を使います。

## 4. セッションへの紐付け

collector は受信したイベントを、どの `session_id` のコンテナで発生したかに紐付けます。

利用する情報:

- コンテナ起動時の label（`attested.session_id`）
- コンテナ init PID
- cgroup 経路（優先）
- 親子プロセス関係（fallback）

collector 内部では `sessionState` を持ち、各 session ごとにカウンタ・イベント列・identity 集合を保持します。

## 5. 収集されるイベント

### 5.1 `exec` イベント

`audit_exec.jsonl` に記録される主な項目:

- `seq`
- `ts_ns`
- `pid`, `ppid`, `uid`
- `comm`（実行時のコマンド名）
- `filename`（exec 対象パス）

用途:
- 禁止実行体（`forbidden_exec`）の検知
- 実行体 identity（sha256）の集約
- 監査ログの時系列再確認

### 5.2 `workspace_write` イベント

`audit_workspace_write.jsonl` に記録される主な項目:

- `seq`
- `ts_ns`
- `pid`, `ppid`, `uid`
- `comm`
- `filename`（書き込み対象ファイル）
- `op`（PoC では `open_write` を中心）
- `flags`

用途:
- `/workspace` 配下の書き込み監査
- 書き込み主体 identity（writer identity）の集約

## 6. 実行体 identity（sha256）の解決

PoC では、名前 (`comm`) ではなく、可能な限り実行体実体の fingerprint（sha256）で同定します。

collector はイベント受信後に userspace で identity を補完します。

### 6.1 基本方針

- `(sha256, dev, inode, path_hint)` を `ExecutableIdentity` として扱う
- `path_hint` は表示/デバッグ用
- 判定根拠は `sha256` を主とする

### 6.2 `exec` 時の解決順（現行）

`exec` イベントでは、以下を優先します。

1. eBPF イベントの `filename`（exec 対象パス）
2. `/proc/<pid>/exe`（fallback）

理由:
- `sys_enter_exec*` の時点では `/proc/<pid>/exe` が旧実行体（例: `dash`）を指すことがあるため
- `filename` の方が「これから実行される実体」を表しやすい

### 6.3 ホストからコンテナ内パスを開く fallback

ホスト側 collector からは、コンテナ内の絶対パス（例: `/home/dev/.vscode-server/.../server/node`）をそのまま `open` できないことがあります。

そのため、以下の fallback を使います。

- 直接 `stat/open`（ホスト namespace）
- 失敗時: `/proc/<pid>/root/<path>` 経由で `stat/open`

これにより、VS Code Remote / code-server / node などのコンテナ内実行体も fingerprint 化しやすくなります。

### 6.4 `workspace_write` 時の PID キャッシュ利用

`workspace_write` の時点では、`/proc/<pid>/exe` が解決不能だったり、実行体が入れ替わっていることがあります。

そのため collector は:

- `exec` 時に `pid -> ExecutableIdentity` をキャッシュ
- `workspace_write` 時はその cache を優先利用
- cache miss 時のみ `/proc/<pid>/exe` で再解決

これにより、`libuv-worker` のような worker thread 名で書き込みが見える場合でも、親の `node` 実行体 identity を writer として集約できるケースが増えます。

## 7. `comm` と writer identity が一致しない理由

これはOS/Applicationの実装依存であり、例えばAI Agentによるファイル書き込み処理において、
実行コマンド(`comm`)が`agent`であっても、内部では`bash`コマンドにより書き込みが行われる場合がある。

例:
- `audit_workspace_write.jsonl` で `comm=libuv-worker`
- `writer_identities` では `.../server/node`

## 8. 収集結果の集約ファイル

### 8.1 `audit_exec.jsonl`

- 生イベント（exec）
- 時系列調査・デバッグ向け

### 8.2 `audit_workspace_write.jsonl`

- 生イベント（workspace write）
- どのファイルに書いたかの追跡向け

### 8.3 `audit_summary.json`

collector finalize 時に生成するサマリ。

主な内容:
- `exec_observed.count`
- `executed_identities`
- `workspace_writes_observed.count`
- `writer_identities`
- （可視化）identity 解決失敗件数/ヒント
  - `exec_observed.identity_unresolved*`
  - `workspace_writes_observed.writer_identity_unresolved*`

### 8.4 `event_root.json`

収集イベント列（canonical JSON）から計算した hash chain の集約結果。

主な内容:
- `event_root`
- `event_root_alg`
- `event_count`

これが attestation の `integrity` に入ります。

## 9. finalize（`attested stop` 時）

`attested stop` で collector finalize が行われると、collector は sessionState から以下を確定します。

- 観測期間（start/end）
- カウンタ
- identity 集合（sort 済み）
- イベント列の hash chain root

出力:
- `audit_summary.json`
- `event_root.json`

この時点で、attestation 生成に必要な監査基盤データが揃います。

## 10. 現時点の限界（PoC）

- `workspace_write` の直接主体 (`comm`) は、実際の上位ツール名と一致しないことがある
  - 例: Agent/IDE の内部で `bash` や `node` に委譲される
- `write` 主体だけでツール種別を断定するのは難しい場合がある
- そのため PoC 運用では
  - `forbidden_exec` を主判定
  - `forbidden_writers` を補助判定
 という位置づけが現実的

## 11. 今後の拡張候補

- write 時の parent/ancestor lineage 収集（PID lineage）
- `cmdline` / cgroup 情報の補助記録
- `open_write` 以外の write 系操作（rename/unlink/create）の拡張監視
- K8s 環境での container/session 解決強化
- deny モード（LSM による実行拒否）との連携

