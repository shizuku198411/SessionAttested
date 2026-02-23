# Signing and Tamper Resistance (PoC)

[日本語](./SIGNING_AND_TAMPER_RESISTANCE.md) | [English](../../SIGNING_AND_TAMPER_RESISTANCE.md)


このドキュメントは、SessionAttested PoC における

- 監査結果への署名の仕組み
- 改ざんに対する考え方（何が改ざん困難か / 何が前提か）

を整理したものです。

## 1. 目的

SessionAttested の PoC は、監査結果を「見た目のログ」ではなく、**検証可能な証跡**として扱うことを目的にしています。

そのために以下を組み合わせます。

- イベント集合の整合性集約（`event_root`）
- アテステーション文書の canonical JSON 化
- 署名（ed25519）
- `verify` による再検証

## 2. 何に署名するか

PoC で署名されるのは、`attestation.json` の canonical JSON バイト列です。

### 生成物

- `attestation.json`
- `attestation.sig`
- `attestation.pub`

### `attestation.json` に含まれる主な情報

- `subject`
  - `repo`
  - `commit_sha`
- `session`
  - `session_id`
  - `commit_binding`（最新）
  - `commit_bindings`（複数 commit 履歴; 実装済み）
- `policy`
  - `policy_id`, `policy_version`
  - `ruleset_hash`
  - `forbidden_exec`, `forbidden_writers` snapshot
- `audit_summary`
  - `exec_observed`, `workspace_writes_observed`
  - `executed_identities`, `writer_identities`
- `integrity`
  - `event_root`
  - `event_root_alg`
  - `event_count`
- `conclusion`
  - `pass/fail`
  - `reasons`

重要点:
- 署名対象は `audit_summary` だけではなく、**ポリシー参照情報・commit 紐付け・event_root を含む attestation 全体**です。

## 3. 署名の仕組み（PoC）

PoC では ed25519 を使用します。

### 3.1 署名時（`attested attest`）

`attested attest` は以下を行います。

1. session の監査成果物を読み込む
   - `meta.json`
   - `audit_summary.json`
   - `event_root.json`
   - `commit_binding.json` / `commit_bindings.jsonl`
2. policy を読み込み、評価して `conclusion` を作る
3. `attestation.json` を組み立てる
4. `attestation.json` を canonical JSON に変換
5. canonical JSON に ed25519 署名
6. `attestation.sig` / `attestation.pub` を出力

### 3.2 検証時（`attested verify`）

`attested verify` は以下を確認します。

1. `attestation.json` を canonical JSON 化
2. `attestation.sig` を公開鍵で検証（署名の正当性）
3. `binding` 指定時は commit binding と subject の整合性確認
4. `--policy` 指定時は `ruleset_hash` の一致確認（policy mismatch 検出）
5. `require-pass` 条件に基づく pass/fail 判定

## 4. Canonical JSON の意味

JSON は整形やキー順の違いで見た目が変わるため、そのまま署名すると再検証が不安定になります。

そのため PoC では canonicalization を行います。

狙い:
- 同じ内容なら同じバイト列になる
- 署名/検証でブレない

結果:
- 空白/改行/キー順の違いによる署名不一致を避けられる

## 5. `event_root` によるイベント集合の集約

PoC は、監査イベント列（`exec` / `workspace_write`）を hash chain で集約し、`event_root` を生成します。

### 5.1 何のために使うか

- 生イベント全件を常に attestation に含めなくても、
  - 「このサマリはこのイベント列から作られた」という整合性アンカーを持てる
- 後からイベント列が差し替えられた場合の検知根拠になる

### 5.2 PoC の位置づけ

PoC では `event_root` 自体は署名対象の attestation に含まれるため、

- `attestation.json` 改ざん
- `event_root` 差し替え

は署名検証で検出されます。

## 6. 改ざん困難性（何が守れるか）

## 6.1 守れるもの（前提付き）

以下は、**監査主体管理下のホスト** と **署名鍵の保護** を前提に、改ざん困難にできます。

- `attestation.json` の内容差し替え
  - 署名検証で検出される
- `policy` すり替え（`--policy` 付き verify）
  - `ruleset_hash` mismatch で検出される
- commit 紐付けの差し替え（`--binding` 付き verify）
  - `INTEGRITY_MISMATCH` で検出される
- session 監査結果の結論（pass/fail）の改ざん
  - attestation 署名で保護される

## 6.2 「改ざん困難」であって「絶対防止」ではない理由

PoC は以下を前提にします。

- 監査主体がホストを管理している
- collector が正しく動作している
- カーネル/LSM/eBPF が信頼できる
- 署名鍵が漏えいしていない

この前提が崩れると、PoC 単体では防げません。

例:
- 監査主体が故意にホスト側で不正
- カーネル改ざん / eBPF 無効化
- 署名鍵の漏えい

## 7. 何が「状況証拠」になるのか

PoC が提供するのは、主に以下の組み合わせです。

- `audit_summary`（観測結果）
- `event_root`（イベント集合の整合性アンカー）
- `commit binding`（成果物との紐付け）
- `policy snapshot + ruleset_hash`（評価条件の固定）
- `attestation` 署名（内容固定）
- `verify` の再現可能性

この組み合わせにより、

- 「この commit に対し、監査主体の管理下セッションで、ある policy で評価した結果」

を第三者が再検証しやすくなります。

## 8. 改ざんに関する実運用上の考え方（PoC時点）

PoC時点では、以下の運用が現実的です。

- 監査主体側で `attest` 実行
- `verify` をローカル + CI（GitHub Actions など）で再実行
- `ATTESTED_SUMMARY` や Artifact に結果を残す
- 必要に応じて `commit_binding.json` / policy も同梱

こうすることで、単一マシン上の一度きりの判定ではなく、**再検証可能な監査証跡**に近づきます。

## 9. 現時点の限界（PoC）

- `event_root` はイベント集合の整合性アンカーだが、生イベントの完全配布/永続化までは PoCの運用次第
- 監査主体のホスト完全性は trust base（前提）
- 署名鍵管理（ローテーション、HSM、失効）は PoC 範囲外
- transparency log / timestamp authority 連携は未実装

## 10. 今後の拡張候補

- 署名鍵管理強化
  - HSM / KMS 連携
  - key rotation / key revocation
- 透明性ログ（transparency log）連携
- RFC3161 等の timestamp authority 連携
- `event_root` と生イベントの外部保管・参照性強化
- 監査主体側の runtime attestation（collector/host の健全性証明）

