# SessionAttested PoC Repo
このリポジトリは、[SessionAttested](https://github.com/shizuku198411/SessionAttested)を利用して開発を行うPoC用リポジトリです。

## 開発の流れ
### Workspace登録 (ホスト側)
作業ディレクトリで `attested workspace init`を実行し、対話形式でWorkspace設定を行います。
```bash
$ attested workspace init

# 任意のWorkspaceID
workspace name (workspace-id): attested_poc
# Workspaceパス,CWDが自動でセットされる
workspace path (workspace-host) [/path/to/attested_poc]:
# Dev Containerのイメージ、デフォルトでSSH接続が行えるubuntuイメージがビルドされます
docker image [attested_base:latest]:
is the image need build or pull? [pull|build] (default: build): 
# Dev Container内でgit pushを行う場合に、ホスト側のssh keyを利用するかどうか
mount host git ssh key into container? [y/N]: y
host ssh private key path [/path/to/.ssh/github_id_key]: 
# GitHubのリポジトリ/ユーザ情報
GitHub repo (owner/name) [optional]: shizuku198411/SessionAttested-PoC-Repo    
git user.name [optional]: shizuku198411
git user.email [optional]: <EMAIL>

workspace_id: attested_poc
workspace_meta: /path/to/attested_poc/.attest_run/state/workspaces/attested_poc.json
workspace_host: /path/to/attested_poc
container_id: fe975f3474d71698a219d0c4c424d5a2b6321c0288216830b5271895ff86ac8e
container_name: attested-poc-dev
created: true
state: container is created/registered and left stopped
scaffold:
  created: .gitignore (managed block)
  created: attest/attested.yaml
  created: attest/Dockerfile
  created: attest/policy.yaml
```
これにより、

- このリポジトリ内で監査を行うための設定ファイル/ディレクトリ群
- Dev Containerの作成

が行われます。

※Dev Containerの実体は `docker container ls -a` で確認できます。
```bash
$ docker container ls -a
CONTAINER ID   IMAGE                  COMMAND                  CREATED         STATUS                    PORTS     NAMES
fe975f3474d7   attested_base:latest   "/usr/sbin/sshd -D -e"   4 minutes ago   Created                             attested-poc-dev
```

### Session開始 (ホスト側)
Dev Containerの起動および監査を開始するため、`attested start` を実行します。

```bash
$ attested start
session_id: 2db0423d7d36c88c7e03e61d5d3c7234
session_dir: .attest_run/state/sessions/2db0423d7d36c88c7e03e61d5d3c7234
workspace_host: /path/to/attested_poc
container_id: fe975f3474d71698a219d0c4c424d5a2b6321c0288216830b5271895ff86ac8e
image: attested_base:latest
container_reused: true
meta: .attest_run/state/sessions/2db0423d7d36c88c7e03e61d5d3c7234/meta.json
collector_auto: true
collector_pid: .attest_run/state/sessions/2db0423d7d36c88c7e03e61d5d3c7234/collector.pid
collector_log: .attest_run/state/sessions/2db0423d7d36c88c7e03e61d5d3c7234/collector.log
generated_signing_key: .attest_run/keys/attestation_priv.pem
generated_public_key: .attest_run/keys/attestation_pub.pem
```

これで、監査ログ収集(attested collector)とDev Containerが起動します。

### 開発作業(Dev Container側)
ここからは通常の開発作業です。

#### 接続方式

- `docker container exec` による作業
- ターミナルからのSSH接続
- IDEからのSSH接続

など、任意のものを利用できます。SessionAttestedの監査アーキテクチャはユーザの開発手段/ツールを制限しません。

SSHで接続する場合は、`dev:devpass` が初期ユーザ/パスワードです。

#### Git初期化
ホスト側/コンテナ側いずれでも可能です。本PoCではコンテナ内で初期化を行います。
```bash
dev@fe975f3474d7:/workspace$ git init
dev@fe975f3474d7:/workspace$ git remote add origin git@github.com:shizuku198411/SessionAttested-PoC-Repo.git
dev@fe975f3474d7:/workspace$ git branch -M main
```

#### パッケージインストール&ファイル作成
このセッションでは、パッケージインストール(apt)とファイル作成を行っています。
```bash
dev@fe975f3474d7:/workspace$ sudo apt update
dev@fe975f3474d7:/workspace$ sudo apt install -y ca-certificates curl
dev@fe975f3474d7:/workspace$ mkdir src
dev@fe975f3474d7:/workspace$ touch src/main.c
# IDEでファイル編集
```

#### Git Commit
監査ログとの紐づけを行うため、コンテナ内では `attested git` コマンドを利用して操作を行います。  
※`attested git`は`git`コマンドラッパ+監査ログマッピング処理のコマンド

```bash
dev@fe975f3474d7:/workspace$ attested git add .
dev@fe975f3474d7:/workspace$ attested git commit -m 'first commit'
# == 通常のgit command出力 ==
[main (root-commit) 7c64b24] first commit
 10 files changed, 228 insertions(+)
 create mode 100644 .attest_run/keys/attestation_pub.pem
 create mode 100644 .attest_run/last_session_id
 create mode 100644 .attest_run/state/sessions/2db0423d7d36c88c7e03e61d5d3c7234/collector.pid
 create mode 100644 .attest_run/state/sessions/2db0423d7d36c88c7e03e61d5d3c7234/meta.json
 create mode 100644 .gitignore
 create mode 100644 README.md
 create mode 100644 attest/Dockerfile
 create mode 100644 attest/attested.yaml
 create mode 100644 attest/policy.yaml
 create mode 100644 src/main.c
# == SessionAttestedによるCommit紐づけ(Commit Binding) ==
committed
repo_path: .
commit_sha: 7c64b24d7504aa1b2ac361d57cd6a8e66a2aae1d
binding: .attest_run/state/sessions/2db0423d7d36c88c7e03e61d5d3c7234/commit_binding.json
bindings: .attest_run/state/sessions/2db0423d7d36c88c7e03e61d5d3c7234/commit_bindings.jsonl
```

これにより、SessionとCommitが紐づいて記録されます。

### Session終了 (ホスト側)
作業が終了したら `attested stop` を実行し、Sessionを終了します。

```bash
$ attested stop
finalized
stopped_container: true
audit_summary: .attest_run/state/sessions/2db0423d7d36c88c7e03e61d5d3c7234/audit_summary.json
event_root: .attest_run/state/sessions/2db0423d7d36c88c7e03e61d5d3c7234/event_root.json
```

この操作によりCollectorへSession終了通知を行うとともに、Sessionの監査ログが確定します。

### Attest(評価) (ホスト側)
生成された監査ログを `attested attest` を実行し、評価します。初期ポリシー(attest/policy.yaml)は全て空の状態=どのexe/writerでも許可する状態です。  

```bash
$ attested attest
wrote:
  .attest_run/attestations/latest/attestation.json
  .attest_run/attestations/latest/attestation.sig
  .attest_run/attestations/latest/attestation.pub
attestation pass=true
```

評価はPASSとなり、この評価結果が署名付き証明として `attestation.json` に保存されます。

### Verify(検証) (ホスト側)
署名付き証明の整合性チェックおよび検証済みマーカー設置を、`attested verify` を実行し行います。

```bash
$ attested verify
OK (signature valid, policy match). attestation pass=true
```

ここで、署名が正しいこと(attestation.json改竄検知)、ポリシーがマッチしていること(ポリシー改竄検知)を行います。  
また、以下のファイル群がリポジトリRootに設置されます。

- [ATTESTED](ATTESTED): SessionAttestedマーカー
- [ATTESTED_SUMMARY](ATTESTED_SUMMARY): Attest結果のサマリ。各Sessionが累積されていく
- [ATTESTED_POLICY_LAST](ATTESTED_POLICY_LAST): 直近で利用されたPolicy内容
- [ATTESTED_WORKSPACE_OBSERVED](ATTESTED_WORKSPACE_OBSERVED): Workspace全体で検知したexe/writer一覧

### GitHubへのPush (Container側/ホスト側)
PushはDev Container側/ホスト側いずれでも実行可能です。  
このPoCでは監査主体(ホスト側)がAttest/Verifyを行いPASSしていることを確認したうえでPushする運用を想定します。  

先に生成した署名付き証明ファイル群を`git add/commit`し、`git push`します。
ホスト側で作業する場合、この作業は開発作業ではなく証明設置作業であるため、
`attested git commit`ではなく、通常の`git commit`を利用してください。

```bash
$ git add .
$ git commit -m 'attested verify: pass'
[main 159e787] attested verify: pass
 13 files changed, 1552 insertions(+), 1 deletion(-)
 create mode 100644 .attest_run/attestations/latest/attestation.json
 create mode 100644 .attest_run/attestations/latest/attestation.pub
 create mode 100644 .attest_run/attestations/latest/attestation.sig
 create mode 100644 .attest_run/state/sessions/2db0423d7d36c88c7e03e61d5d3c7234/audit_summary.json
 delete mode 100644 .attest_run/state/sessions/2db0423d7d36c88c7e03e61d5d3c7234/collector.pid
 create mode 100644 .attest_run/state/sessions/2db0423d7d36c88c7e03e61d5d3c7234/collector.stop
 create mode 100644 .attest_run/state/sessions/2db0423d7d36c88c7e03e61d5d3c7234/commit_binding.json
 create mode 100644 .attest_run/state/sessions/2db0423d7d36c88c7e03e61d5d3c7234/commit_bindings.jsonl
 create mode 100644 .attest_run/state/sessions/2db0423d7d36c88c7e03e61d5d3c7234/event_root.json
 create mode 100644 ATTESTED
 create mode 100644 ATTESTED_POLICY_LAST
 create mode 100644 ATTESTED_SUMMARY
 create mode 100644 ATTESTED_WORKSPACE_OBSERVED
$ git push origin main 
Enumerating objects: 37, done.
Counting objects: 100% (37/37), done.
Delta compression using up to 4 threads
Compressing objects: 100% (29/29), done.
Writing objects: 100% (37/37), 15.50 KiB | 2.21 MiB/s, done.
Total 37 (delta 2), reused 0 (delta 0), pack-reused 0
remote: Resolving deltas: 100% (2/2), done.
To github.com:shizuku198411/SessionAttested-PoC-Repo.git
 * [new branch]      main -> main
```

### Session開始/終了/評価/検証を繰り返す
以降の作業は以下の繰り返しです。

- Session開始: `attested start`
- Dev Container内作業: 接続/作業/`attested git commit`
- Session終了: `attested stop`
- 評価/検証: `attested attest` / `attested verify`

SessionAttestedはCommitに紐づくため、Pushの有無は関係ありません。  
任意のタイミング/運用ポリシーに従いPushを行ってください。

### Workspace削除
一連の開発作業が終了した場合、`attested workspace rm` を実行し、環境クリーンアップを行います。

このコマンドはWorkspace内成果物を削除するものではなく、workspace情報(`.attest_run/state/workspace/`)およびDev Containerの削除を行うのみであり、成果物には影響しません。  
本操作以降で再度Sessionを開始したい場合は、再度`attested workspace init`から始めてください。  

## ポリシー精査/適用
SessionAttestedは、exe/writerをファイル名ではなくinode/devベースのSHA256で識別します。  
これは、実バイナリのファイル名/パスの変更(ver upに伴うパス更新や偽装)対策の側面が主にあります。  
そのため、以下の手順でポリシーの評価/策定を行うことを推奨します。

### ポリシー候補生成/適用
直近のSessionを元に、ポリシー候補を生成する `attested policy candidates` を実行します。

※`--include-exec`オプションは付与推奨
```bash
$ attested policy candidates --include-exec
wrote: .attest_run/policy.2db0423d7d36c88c7e03e61d5d3c7234.candidate.yaml
next: review and rename if you want to use it as policy
```

これにより、該当セッション内で捕捉したexec/writer一覧が記録されたポリシー候補が生成されます。

```yaml
# source: .attest_run/state/sessions/2db0423d7d36c88c7e03e61d5d3c7234/audit_summary.json
# session_id: 2db0423d7d36c88c7e03e61d5d3c7234
policy_id: candidate-2db0423d7d36c88c7e03e61d5d3c7234
policy_version: 1.0.0
forbidden_exec:
    - sha256: sha256:af955ef55333c8fc9c5aa50df91ad1a629d9a79a9afa125cd5e9629585f78015
      comment: /bin/bash
    - sha256: sha256:c883d9c27228339580994a1d0ea960645368c7d1b960a712bd0c655860c2d0d7
      comment: /bin/sh
        :
forbidden_writers:
    - sha256: sha256:c8c89c91b842b5852dea0863836e24d38fec55c263a5b4377e54b40886a1cdb9
      comment: /home/dev/.vscode-server/cli/servers/Stable-072586267e68ece9a47aa43f8c108e0dcbf44622/server/node
exceptions: []
```

この状態では/bin/bashといったすべてのexe/writerが禁止対象となってしまうため、`comment`を元に禁止対象のみを残します。

ここでは、企業ポリシーとしてVS Codeの利用を禁止しているケース(拡張機能脆弱性等によるサプライチェーン対策)を想定し、VS Code関連のexe/writerを残します。  
以下が精査後のポリシーです。

```yaml
policy_id: attested_poc-deny_vscode
policy_version: 1.0.1
forbidden_exec:
    - sha256: sha256:ee2d5f97c1dbc39fc28f66383e173ffae55420512ec0f420ff46758e2f1111c9
      comment: /home/dev/.vscode-server/cli/servers/Stable-072586267e68ece9a47aa43f8c108e0dcbf44622/server/bin/code-server
    - sha256: sha256:c8c89c91b842b5852dea0863836e24d38fec55c263a5b4377e54b40886a1cdb9
      comment: /home/dev/.vscode-server/cli/servers/Stable-072586267e68ece9a47aa43f8c108e0dcbf44622/server/node
    - sha256: sha256:26ce6cceb17ac710ee7253c49ea825c618d4f9e49a135d52b4edce336c40f620
      comment: /home/dev/.vscode-server/cli/servers/Stable-072586267e68ece9a47aa43f8c108e0dcbf44622/server/node_modules/@vscode/ripgrep/bin/rg
    - sha256: sha256:2bfe7e6f1939a446c2a4d21998202a247ce58edb1890e10d97b633a91e5a71b5
      comment: /home/dev/.vscode-server/cli/servers/Stable-072586267e68ece9a47aa43f8c108e0dcbf44622/server/out/vs/base/node/cpuUsage.sh
    - sha256: sha256:b5bcad68e567f13e111d24b5dc9a7abc544b4dc81c4817ab5518789461581ac6
      comment: /home/dev/.vscode-server/code-072586267e68ece9a47aa43f8c108e0dcbf44622
forbidden_writers:
    - sha256: sha256:c8c89c91b842b5852dea0863836e24d38fec55c263a5b4377e54b40886a1cdb9
      comment: /home/dev/.vscode-server/cli/servers/Stable-072586267e68ece9a47aa43f8c108e0dcbf44622/server/node
exceptions: []
```

vscode関連のexe/writerを残しています。  
これを本番ポリシーである `attest/policy.yaml` に反映(rename or 内容コピペ)します。
また、ポリシー更新後に正しく適用されているかどうかの判別を行うため、 `policy_version` の更新を推奨します。

## ポリシー更新後の動作確認
上記でVS Code関連を禁止exe/writerとしてセットしたため、以下2ケースで開発Sessionを行います。

### Case1: ポリシー遵守開発Session(VS Code未使用)
Windows TerminalからDev ContainerへSSH接続を行い、作業を行います。
```bash
$ attested start

# == Windows TerminalからDev Container接続、作業 + attested git commit ==

$ attested stop
$ attested attest
wrote:
  .attest_run/attestations/latest/attestation.json
  .attest_run/attestations/latest/attestation.sig
  .attest_run/attestations/latest/attestation.pub
attestation pass=true
pyxgun@develop:~/sandbox/attested_poc$ attested verify
OK (signature valid, policy match). attestation pass=true
```

検証結果=PASSとなっているため、ポリシー違反ではないことがわかります。  
意図したポリシーが適用されているかどうかの確認は、

- `ATTESTED_POLICY_LAST`: 直近適用ポリシー
- `ATTESTED_SUMMARY`: 該当Sessionの適用ポリシーversion

で行えます。  
本ケースの `ATTESTED_SUMMARY` は以下のように記録されました。  

```yaml
  {
    "attestation_pass": true,
    "commit_sha": [
      "dc599bc9d570b5f4509f2d2d8c52f371c2b84585"
    ],
    "commit_url": [
      "https://github.com/shizuku198411/SessionAttested-PoC-Repo/commit/dc599bc9d570b5f4509f2d2d8c52f371c2b84585"
    ],
    "policy_checked": true,
    "policy_id": "attested_poc-policy",
    "policy_match": true,
    "policy_path": "attest/policy.yaml",
    "policy_version": "1.0.1",
    "repo": "shizuku198411/SessionAttested-PoC-Repo",
    "ruleset_hash": "sha256:ca2fb483248d378125189a8ca64ca13978c66bfcf71f4028ec3f6fe58c2c1813",
    "session_id": "69836cb2cff5f47c102130a912b2b74e",
    "timestamp": "2026-02-24T01:10:56Z",
    "verify_ok": true
  }
```

`policy_version`:`0.1.0` のため、VS Codeを禁止とするポリシーが適用されていることがわかります。

### Case2: ポリシー違反開発Session(VS Code使用)
次に、VS Code(Remote SSH)からDev ContainerへSSH接続を行い、作業を行います。

```bash
$ attested start

# == VS CodeからDev Container接続、作業 + attested git commit ==

$ attested stop

$ attested attest
wrote:
  .attest_run/attestations/latest/attestation.json
  .attest_run/attestations/latest/attestation.sig
  .attest_run/attestations/latest/attestation.pub
attestation pass=false
$ attested verify
NG (FORBIDDEN_EXEC_SEEN: count=5 samples=[sha256:26ce6cceb(/home/dev/.vscode-server/cli/servers/Stable-072586267e68ece9a47aa43f8c108e0dcbf44622/server/node_modules/@vscode/ripgrep/bin/rg), sha256:2bfe7e6f1(/home/dev/.vscode-server/cli/servers/Stable-072586267e68ece9a47aa43f8c108e0dcbf44622/server/out/vs/base/node/cpuUsage.sh), sha256:b5bcad68e(/home/dev/.vscode-server/code-072586267e68ece9a47aa43f8c108e0dcbf44622), sha256:c8c89c91b(/home/dev/.vscode-server/cli/servers/Stable-072586267e68ece9a47aa43f8c108e0dcbf44622/server/node), sha256:ee2d5f97c(/home/dev/.vscode-server/cli/servers/Stable-072586267e68ece9a47aa43f8c108e0dcbf44622/server/bin/code-server)]). attestation pass=false
```

`FORBIDDEN_EXEC_SEEN`により検証結果=FALSE、つまりポリシー違反であることがわかります。
ここでの表示はexeのみの表示のため、`.attest_run/attestations/latest/attestation.json` を確認してみます。

```yaml
  "conclusion": {
    "pass": false,
    "reasons": [
      {
        "code": "FORBIDDEN_EXEC_SEEN",
        "detail": "count=5 samples=[sha256:26ce6cceb(/home/dev/.vscode-server/cli/servers/Stable-072586267e68ece9a47aa43f8c108e0dcbf44622/server/node_modules/@vscode/ripgrep/bin/rg), sha256:2bfe7e6f1(/home/dev/.vscode-server/cli/servers/Stable-072586267e68ece9a47aa43f8c108e0dcbf44622/server/out/vs/base/node/cpuUsage.sh), sha256:b5bcad68e(/home/dev/.vscode-server/code-072586267e68ece9a47aa43f8c108e0dcbf44622), sha256:c8c89c91b(/home/dev/.vscode-server/cli/servers/Stable-072586267e68ece9a47aa43f8c108e0dcbf44622/server/node), sha256:ee2d5f97c(/home/dev/.vscode-server/cli/servers/Stable-072586267e68ece9a47aa43f8c108e0dcbf44622/server/bin/code-server)]"
      },
      {
        "code": "FORBIDDEN_WRITER_SEEN",
        "detail": "count=1 samples=[sha256:c8c89c91b(/home/dev/.vscode-server/cli/servers/Stable-072586267e68ece9a47aa43f8c108e0dcbf44622/server/node)]"
      }
    ]
  },
```

`conclusion` が評価結果の記載ブロックです。  
評価FAILの理由として、`FORBIDDEN_EXEC_SEEN` / `FORBIDDEN_WRITER_SEEN` が挙げられています。  
つまり、ポリシーで禁止しているexe/writerどちらも検出されたSessionであることを示しています。


## WebUIによるWorkspace監査ログ確認
ここまでの監査ログは生ログで確認できますが、より視覚的に確認ができるWebUIを実装しています。  
WebUI起動は以下のコマンドで行えます。

```bash
$ attested webui --addr 0.0.0.0:9443
```
※`--addr`オプションで任意のポート/公開範囲を指定できます。  
起動後、ブラウザより`https://<host>:<port>`へアクセスします(自己署名証明書によるTLS接続)

アクセス後、最新セッション毎の評価結果が表示されます。  
別セッションの確認は "See other sessions (n)" からアクセスできます。

![sessions](docs/assets/attested_webui_sessions.png)

### Case1のWebUI結果
Case1のセッションは以下のように表示されます。  

![case1_summary](docs/assets/attested_webui_case1_1.png)

- `conclusion: PASS` = 評価/検証ともに合格
- `verify_ok/attestation_pass: true` = ポリシー違反が無く、検証も合格
- `policy_checked/policy_match: true` = Policyが改竄されていなく、意図したPolicyが評価に利用されている

という結果が確認できます。

### Case2のWebUI結果
一方で、Case2のセッションは以下のように表示されます。

![case2_summary](docs/assets/attested_webui_case2_1.png)

- `conclusion: FAIL` = 評価/検証いずれかが不合格
- `Reason: FORBIDDEN_EXEC_SEEN` = 禁止exe検知による不合格
- `verify_ok/attestation_pass: false` = ポリシー違反が検知され不合格
- `policy_checked/policy_match: true` = Policyが改竄されていなく、意図したPolicyが評価に利用されている

このことから、

- 定義されたポリシーは改竄されず評価に利用され、そのポリシーに違反したexeが検知されている

ということがわかります。  
ページ下部ではより詳細なexe/writer一覧が確認できます。

![case2_identities](docs/assets/attested_webui_case2_2.png)

適用されたポリシー(Applied Policy)と検知したexe/writer(Executed/Writer Identities)が表示されており、  
ポリシー違反となっているexe/writerはハイライト表示されます。  

通常運用においては、

- 生ログ: Artifact保管用/後から検証するための証跡として利用
- WebUI：各SessionのPASS/FAIL、ポリシー違反exe/writerの確認、ポリシー精査

という目的で利用することを推奨します。
