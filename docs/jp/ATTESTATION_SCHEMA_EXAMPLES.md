# Attestation Schema Examples

[日本語](./ATTESTATION_SCHEMA_EXAMPLES.md) | [English](../../ATTESTATION_SCHEMA_EXAMPLES.md)


このドキュメントは、`SessionAttested` の主要成果物フォーマットについて、PoC 時点での実用的な読み方をまとめたものです。

対象:

- `audit_summary.json`（監査集約）
- `event_root.json`（イベント集合ハッシュ）
- `commit_binding.json` / `commit_bindings.jsonl`（commit 紐づけ）
- `attestation.json`（署名対象本体）
- `ATTESTED`（プレーンテキストマーカー）
- `ATTESTED_SUMMARY`（verify 結果一覧）
- `ATTESTED_WORKSPACE_OBSERVED`（workspace 累積の観測一覧）
- `.attest_run/reports/sessions/<SESSION_ID>/session_correlation.json`（セッション相関結果）

これらの成果物は、ファイルを直接確認するか、`attested webui`（記録済み結果の閲覧 UI）で視覚的に確認できます。

注記:

- ここに記載する JSON は説明用の抜粋/簡略例です
- 将来バージョンで field が追加される可能性があります（後方互換を基本方針）

## 1. `audit_summary.json`

セッション終了後の監査集約結果です。`exec` / `workspace write` の件数、identity 集約、未解決件数などを含みます。

例:

```json
{
  "window": {
    "start_rfc3339": "2026-02-22T09:51:43Z",
    "end_rfc3339": "2026-02-22T09:56:44Z"
  },
  "exec_observed": {
    "count": 1438,
    "identity_unresolved": 19,
    "identity_unresolved_hints": [
      "pid=318769 comm=tokio-runtime-w fn=/home/dev/.codex/tmp/.../lsb_release"
    ]
  },
  "workspace_writes_observed": {
    "count": 9,
    "by_op": {
      "open_write": 9
    }
  },
  "workspace_files": [
    {
      "path": "/workspace/src/created_by_codex.txt",
      "write_count": 1,
      "comms": ["codex"],
      "writers": [
        {
          "sha256": "sha256:f211b442bfb2eb20e4d6d7c0593b34ec421a5bcd630873c69ed7aaedeea28a26",
          "inode": 8475246,
          "dev": 1048687,
          "path_hint": "/home/dev/.vscode-server/extensions/openai.chatgpt.../codex"
        }
      ]
    }
  ],
  "executed_identities": [
    {
      "sha256": "sha256:f211b442bfb2eb20e4d6d7c0593b34ec421a5bcd630873c69ed7aaedeea28a26",
      "inode": 8475246,
      "dev": 1048687,
      "path_hint": "/home/dev/.vscode-server/extensions/openai.chatgpt.../codex"
    }
  ],
  "writer_identities": [
    {
      "sha256": "sha256:f211b442bfb2eb20e4d6d7c0593b34ec421a5bcd630873c69ed7aaedeea28a26",
      "inode": 8475246,
      "dev": 1048687,
      "path_hint": "/home/dev/.vscode-server/extensions/openai.chatgpt.../codex"
    }
  ]
}
```

主要フィールド:

- `window`
  - 監査対象期間（collector finalize 済み）
- `exec_observed.count`
  - 観測された exec イベント数
- `exec_observed.identity_unresolved`
  - identity（sha256/path）解決に失敗した exec 件数
- `workspace_writes_observed.count`
  - ワークスペース書き込みイベント数
- `executed_identities`
  - 実行された実行体の fingerprint 集約
- `writer_identities`
  - workspace write 主体の fingerprint 集約
- `workspace_files`
  - ファイル単位の書き込み集約（どのファイルが、どの writer / comm で書かれたか）

実務上の見方:

- `forbidden_exec` 判定の入力は主に `executed_identities`
- `forbidden_writers` 判定の入力は主に `writer_identities`
- `identity_unresolved` が急増した場合は collector 解決精度を確認
- `workspace_files` は commit 変更ファイルとの照合や、ファイル単位の書き込み主体確認に有用

## 2. `event_root.json`

セッション内イベント列（JSONL 群）の hash chain 集約結果です。イベント集合の整合性確認に使います。

例:

```json
{
  "schema": "event-root/0.1",
  "session_id": "28e005395ea6b8720012b3b091d826e4",
  "event_count": 1447,
  "root": "sha256:4a2f3c...<snip>",
  "seed": "session-attested:28e005395ea6b8720012b3b091d826e4"
}
```

主要フィールド:

- `session_id`
  - 対象セッション ID
- `event_count`
  - 集約対象イベント数（実装依存で `exec` + `write` 等）
- `root`
  - hash chain の最終 root
- `seed`
  - chain 計算に使う seed（仕様互換性に関わる）

## 3. `commit_binding.json`（最新 commit）

セッションと最終 commit の紐づけです。従来互換のため最新 commit を単独で保持します。

例:

```json
{
  "schema": "commit-binding/0.1",
  "session_id": "28e005395ea6b8720012b3b091d826e4",
  "repo_path": "/workspace",
  "repo": "shizuku198411/sandbox",
  "commit_sha": "3a1e62a00e3640b6e65cf1620c85a2dc23beef76",
  "timestamp": "2026-02-22T09:56:20Z"
}
```

用途:

- `attest` 時の subject commit 解決
- `verify` 時の binding 整合性確認

## 4. `commit_bindings.jsonl`（複数 commit 履歴）

1 セッション内で複数回 `attested git commit` を行った場合の履歴です。1 行 1 JSON（append）。

例:

```json
{"schema":"commit-binding/0.1","session_id":"<SESSION_ID>","commit_sha":"<SHA1>","timestamp":"2026-02-22T09:55:01Z"}
{"schema":"commit-binding/0.1","session_id":"<SESSION_ID>","commit_sha":"<SHA2>","timestamp":"2026-02-22T09:56:20Z"}
```

用途:

- `attestation.json.session.commit_bindings[]` の元データ
- `ATTESTED_SUMMARY` の commit 配列生成

## 5. `attestation.json`

署名対象の本体です。監査結果、ポリシー評価結果、commit binding、イベント root などをまとめて保持します。

例（抜粋）:

```json
{
  "schema": "attestation/0.1",
  "subject": {
    "repo": "shizuku198411/sandbox",
    "commit_sha": "3a1e62a00e3640b6e65cf1620c85a2dc23beef76",
    "ref": ""
  },
  "session": {
    "session_id": "28e005395ea6b8720012b3b091d826e4",
    "commit_bindings": [
      {
        "commit_sha": "3a1e62a00e3640b6e65cf1620c85a2dc23beef76"
      }
    ]
  },
  "event_root": {
    "root": "sha256:4a2f3c...<snip>"
  },
  "conclusion": {
    "pass": false,
    "reasons": [
      {
        "code": "FORBIDDEN_EXEC_SEEN",
        "detail": "count=1 samples=[sha256:f211b442b(.../codex)]"
      },
      {
        "code": "FORBIDDEN_WRITER_SEEN",
        "detail": "count=1 samples=[sha256:f211b442b(.../codex)]"
      }
    ]
  },
  "signature": {
    "key_id": "sandbox-key-1",
    "issuer_name": "sandbox-attestor"
  }
}
```

主要フィールド:

- `subject`
  - 証明対象（repo / commit）
- `session`
  - セッション ID、commit binding 履歴スナップショット等
- `event_root`
  - イベント集合の hash 集約
- `conclusion`
  - ポリシー評価結果（`pass` / `reasons`）
- `policy_snapshot`（存在する場合）
  - 検証時照合に使うポリシースナップショット
- `signature`（メタデータ）
  - 発行者・鍵 ID 等

実務上の見方:

- `conclusion.pass=false` でも、署名自体は正しい場合がある（「正常に fail した」）
- `reason.detail` の `sha256/path_hint` から違反 identity を追える

## 6. `ATTESTED`（プレーンテキスト）

このリポジトリ/成果物が `SessionAttested` による verify 処理を経たことを示すマーカーファイルです。

例:

```text
SessionAttested verification marker
timestamp: 2026-02-22T09:59:14Z
session_id: 28e005395ea6b8720012b3b091d826e4
repo: shizuku198411/sandbox
verify_ok: false
attestation_pass: false
```

用途:

- 人間向けの簡易確認
- 「verify 実行済み」の目印

## 7. `ATTESTED_SUMMARY`（JSON 配列）

`verify --write-result` 実行時に追記される、セッション単位の検証結果一覧です。

例:

```json
[
  {
    "timestamp": "2026-02-22T09:59:14Z",
    "session_id": "28e005395ea6b8720012b3b091d826e4",
    "repo": "shizuku198411/sandbox",
    "commit_sha": [
      "3a1e62a00e3640b6e65cf1620c85a2dc23beef76"
    ],
    "commit_url": [
      "https://github.com/shizuku198411/sandbox/commit/3a1e62a00e3640b6e65cf1620c85a2dc23beef76"
    ],
    "verify_ok": false,
    "attestation_pass": false,
    "policy_checked": true,
    "policy_match": true,
    "reason": "FORBIDDEN_EXEC_SEEN: count=1 samples=[sha256:f211b442b(.../codex)]",
    "policy_id": "candidate-28e005395ea6b8720012b3b091d826e4",
    "policy_version": "1.0.0",
    "ruleset_hash": "sha256:08be1eeb...",
    "policy_path": "/sandbox/.attest_run/policy.sandbox.yaml"
  }
]
```

主要フィールド:

- `verify_ok`
  - verify コマンド全体の成功/失敗（署名/形式/整合性/require-pass 含む）
- `attestation_pass`
  - `attestation.json.conclusion.pass` の値
- `policy_checked`
  - verify 時に policy 照合を行ったか
- `policy_match`
  - policy スナップショット/指定 policy の整合性
- `reason`
  - fail 理由の要約（詳細付き）
- `commit_sha` / `commit_url`
  - セッションに紐づく commit 一覧（複数 commit 対応）

実務上の見方:

- `verify_ok=false` かつ `attestation_pass=false`
  - 仕様どおりの「ポリシー違反 fail」の可能性がある
- `verify_ok=false` かつ `policy_match=false`
  - 別ポリシーで検証している可能性
- `ATTESTED_SUMMARY` は WebUI の session 一覧 / 結果表示にも使われる
  - 現行実装では `attestation.json` が `latest` として保持されることが多いため、過去 session の verify 結果表示を補完する役割もある

## 8. `ATTESTED_POLICY_LAST`

直近 verify 時の policy 情報を保存する補助ファイルです（人間向け参照用）。

例（概念）:

```text
policy_path: /sandbox/.attest_run/policy.sandbox.yaml
policy_id: candidate-28e005395ea6b8720012b3b091d826e4
policy_version: 1.0.0
ruleset_hash: sha256:08be1eeb...
timestamp: 2026-02-22T09:59:14Z
```

用途:

- 直近 verify でどの policy を使ったかの確認

## 9. `ATTESTED_WORKSPACE_OBSERVED`（JSON / 累積）

`verify --write-result` 実行時に更新される、workspace 単位の累積観測一覧です。  
session 単位ではなく、複数 session をまたいだ `exec` / `writer` identity の棚卸しや追跡に使います。

例（簡略）:

```json
{
  "sessions_seen": [
    "28e005395ea6b8720012b3b091d826e4"
  ],
  "exec_identities": [
    {
      "sha256": "sha256:f211b442bfb2eb20e4d6d7c0593b34ec421a5bcd630873c69ed7aaedeea28a26",
      "path_hint": "/home/dev/.vscode-server/extensions/openai.chatgpt.../codex",
      "first_seen_session": "28e005395ea6b8720012b3b091d826e4",
      "last_seen_session": "28e005395ea6b8720012b3b091d826e4",
      "seen_count": 1
    }
  ],
  "writer_identities": [
    {
      "sha256": "sha256:f211b442bfb2eb20e4d6d7c0593b34ec421a5bcd630873c69ed7aaedeea28a26",
      "path_hint": "/home/dev/.vscode-server/extensions/openai.chatgpt.../codex",
      "first_seen_session": "28e005395ea6b8720012b3b091d826e4",
      "last_seen_session": "28e005395ea6b8720012b3b091d826e4",
      "seen_count": 1
    }
  ],
  "exec_identity_unresolved": 19,
  "writer_identity_unresolved": 2
}
```

用途:

- `forbidden_*` で落としきれていない観測対象の確認
- workspace 全体で発生した exe / writer の後追い
- policy 見直し時の参考情報

補足:

- session ごとの観測一覧ファイル（`ATTESTED_OBSERVED`）は現行実装では生成しません
- session 単位の詳細は `attestation.json` と `audit_summary.json` を参照します
- WebUI の `Workspace Observed` 表示はこのファイルを使います

## 10. `.attest_run/reports/sessions/<SESSION_ID>/session_correlation.json`（セッション相関結果）

`verify --write-result` 実行時に生成される、セッション単位の相関結果 JSON です。

この JSON は、WebUI の以下のカードで使われる相関結果を保存します。

- `Files Touched by Forbidden Exec Lineage (Session)`
- `Commit Files -> Writers (Session)`

例（抜粋）:

```json
{
  "schema_version": "1",
  "generated_at": "2026-02-24T12:34:56Z",
  "session_id": "d0700fe7af45c14ab2d369f749d5a514",
  "forbidden_lineage_rows": [
    {
      "file_path": "/workspace/src/created_by_codex.txt",
      "write_count": 1,
      "write_comms": ["codex"],
      "matched_execs": [
        {
          "path_hint": "/home/dev/.vscode-server/.../codex",
          "sha256": "sha256:...",
          "pid": 319201
        }
      ],
      "writer_path_hints": ["/home/dev/.vscode-server/.../codex"]
    }
  ],
  "commit_file_rows": [
    {
      "file_path": "src/created_by_codex.txt",
      "commit_shas": ["a1b2c3..."],
      "write_comms": ["codex"],
      "writer_path_hints": ["/home/dev/.vscode-server/.../codex"],
      "forbidden_lineage": true,
      "writer_policy_match": false,
      "policy_match_kind": "exec",
      "forbidden_match_info": ["/home/dev/.vscode-server/.../codex"]
    }
  ]
}
```

用途:

- WebUI 以外でも再利用可能な、再現性のある相関結果の保存
- WebUI 表示と JSON 成果物の整合（JSON 成果物を正とする）
- commit ファイル / writer / 禁止 exe 系譜の説明用データとしての利用

運用上の注意:

- WebUI は session 相関カードについて、この JSON を優先的に参照します
- ファイルが無い場合のみ、互換性のため raw log + 既存成果物から導出する fallback を使うことがあります

## 11. フィールド追加・互換性の考え方（PoC）

PoC 時点では、運用しながら field を追加する可能性があります。

推奨:

- パーサ実装は unknown field を無視する
- 必須フィールドのみ厳格に扱う
- `schema` / `policy_version` / `spec_version`（将来追加含む）を見て分岐する

## 12. トラブルシュートで最初に見るファイル

ケース別の初手:

- 「なぜ fail したか知りたい」
  - `attestation.json` (`conclusion.reasons`)
  - `ATTESTED_SUMMARY` (`reason`)
- 「何が観測されたか知りたい」
  - `audit_summary.json` (`executed_identities`, `writer_identities`)
  - `ATTESTED_WORKSPACE_OBSERVED`（workspace 累積）
- 「生ログまで追いたい」
  - `audit_exec.jsonl`
  - `audit_workspace_write.jsonl`
- 「整合性/改ざん観点を見たい」
  - `event_root.json`
