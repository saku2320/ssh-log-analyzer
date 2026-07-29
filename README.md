## SSHログ解析ツール（CLI）

## 概要
auth.logを解析し、SSHログイン試行やsudo/suコマンド実行を検出・可視化するCLIツール

開発環境：ubuntu(bash) or Fedora Asahi Linux <br>
実験環境：ubuntu（bash）<br>
使用言語：C言語

## 構成内容

```
ssh-log-analyzer$ tree
├── Makefile
├── README.md
├──.gitignore
├── sample_log/
│   └── auth.log
└── src/
    ├── analyzer.c
    ├── analyzer.h
    ├── main.c
    ├── parser.c
    ├── parser.h
    ├── report.c
    └── report.h
```

## 出力内容
#### SSHログ分析結果
- 総成功回数
- 総失敗回数
- 総root試行回数
- sudoコマンド実行回数
- suコマンド実行回数
#### sudo/su実行ログ
- sudo実行ユーザ、切替先ユーザ、TTY、作業ディレクトリ、実行コマンド
- su切替先ユーザ、ログインユーザ、TTY
- su後に入力した個別コマンドはauth.logに記録されないため、本ツールでは表示不可
#### ログ統計
- 読み込んだログの行数
- 認証関連の行数
- 無視された行数
- 検出されたIPの総数
#### IP統計
- 検出された全IPごとの国・地域、成功・失敗回数（国・地域はログに記録がある場合のみ）
#### IP単位の時系列表示
- 指定したIPに関連するSSH失敗、SSH成功、sudo/su実行を時刻順にタイムライン形式で出力
- sudo/suはauth.log上に接続元IPが直接残らないため、指定IPからログイン成功したユーザーの操作として推定できる範囲で表示
#### 国・地域警告
- 接続元IPに紐づく国・地域情報がログに記録されている場合、そのIPと国・地域を警告表示
#### ブルートフォース警告
- 同一IPから短時間に連続失敗が発生した場合、IP、検知期間、失敗回数、対象ユーザを警告表示
- 検知条件は `1分以内に10回`、`5分以内に30回`、`10分以内に50回`
#### 失敗後ログイン成功警告
- 同一IP・同一ユーザーで10回以上失敗した後、30分以内にログイン成功した場合、侵入の可能性が高い重大アラートとして表示
#### 危険度スコア
- IPごとに攻撃兆候を点数化し、HIGHまたはCRITICALに分類されたIPのみ表示
- スコア条件は `5分以内の失敗回数`、`rootへのログイン試行`、`存在しないユーザーへの試行`、`10人以上のユーザーを試行`、`失敗後にログイン成功`
#### 失敗IP Top5
- 失敗回数が多い順にIPのTop5
#### 成功IP Top5
- 成功回数が多い順にIPのTop5
#### ユーザ統計
- 検出された全ユーザ名ごとの成功・失敗回数
#### 失敗ユーザ Top5
- 失敗回数が多い順にユーザ名のTop5
#### 成功ユーザ Top5
- 成功回数が多い順にユーザ名のTop5


## 対応ログ形式例
現時点では以下のような認証ログを対象としている。今後、より多くの形式に対応させていく予定。
- `Failed password for invalid user ... from ...`
- `Failed password for ... from ...`
- `Accepted password for ... from ...`
- `Invalid user ... from ...`
- `pam_unix(sshd:auth): authentication failure; ... rhost=... user=...` (IPのみの取得)
- `sudo: ... COMMAND=...`
- `su: (to ...) ...`
- `country=...` / `region=...` などの国・地域情報を含むログ（ログ内に情報がある場合のみ表示）

## 進捗
- 130行程度のサンプルログ（auth.log）での成功・失敗判定それぞれのユーザ名＆IPの出力
- 総成功・失敗回数の出力
- root試行回数の出力
- IPごとの成功・失敗回数の出力
- 一定時間内の連続失敗からブルートフォース攻撃疑いを出力
- 失敗回数が多いIPのTop５を降順で出力
- 約1万900行のサンプルログファイルでも抽出漏れ等がないように改良
- Makefileを作成し、ビルドや実行のコマンドを省略できるように改良
- 対応ログ形式を追加（Invalid userログ＆PAMログ）
- ログイン試行に使われたユーザ名ごとの成功・失敗回数の出力を追加
- 失敗回数が多いユーザ名のTop5を降順で出力
- 不審IP検出基準をコマンド実行時に引数として自由に変更できるように改良
- 失敗IP・不審IP・失敗ユーザ名等を色分けして表示できるように改良
- `failed` でSSH失敗ログのみを簡単に出力できるように改良
- `success` でSSH成功ログのみを簡単に出力できるように改良
- 失敗・成功ログについて、IPまたはユーザに絞った集計レポートを出力できるように改良
- 成功回数が多いIPとユーザ名のTop5を降順で出力
- `sudo` でsudoコマンド実行ログのみを簡単に出力できるように改良
- `su` でsuコマンド実行ログのみを簡単に出力できるように改良
- `sudo` で実行ユーザ・切替先ユーザ・TTY・作業ディレクトリ・実行コマンドを詳細表示できるように改良
- `su` で切替先ユーザ・ログインユーザ・TTYを詳細表示できるように改良
- ログに国・地域情報が含まれる場合、接続元IPごとの国・地域表示と警告表示を追加
- 失敗回数の合計ではなく、一定時間内の連続失敗からSSHブルートフォース攻撃疑いを検知できるように改良
- 同一IP・同一ユーザーで繰り返し失敗した後のログイン成功を重大アラートとして検知できるように改良
- IPごとの危険度スコアを算出し、HIGH/CRITICALのみ理由付きで表示できるように改良

## 目標
- ブルートフォース攻撃疑いを検出可に
- ありえない時間帯（企業であれば業務時間外など）に行われたログの検出


## パフォーマンス上の注意点
本ツールはauth.logを対象として解析を行います。<br>
読み込める行数に関しては、理論上は大規模なログにも対応することができますが、攻撃元IPやユーザ等の種類が非常に多い場合は処理速度やメモリ使用量に影響が出る可能性があります。<br>

現在の実装では、新しいIPを読み込むたびに既存のIP情報を探索する処理が行われるため、攻撃元IPがすべて異なるようなログでは、探索回数が増加し、マシンスペックによっては処理が遅くなる可能性があります。

## ビルド方法
```bash
make re
```

## 実行方法
```bash
make run
make run ja
```

#### フィルタ実行例
```bash
make run failed
make run success
make run root
make run sudo
make run su
make run ip=192.0.2.10
make run failed ip
make run failed user
make run success ip
make run success user
make run failed ip ja
```

使用できるフィルタ条件
- `failed`: SSH失敗ログのみ出力
- `success`: SSH成功ログのみ出力
- `root`: rootログイン試行のみ出力
- `sudo`: sudoコマンド実行ログと詳細情報を出力
- `su`: suコマンド実行ログとauth.logから分かる範囲の詳細情報を出力
- `ip=<IPアドレス>`: 指定IPのSSH失敗・SSH成功・sudo/su実行を時系列で出力
- `failed ip`: `Unique IPs tracked`、`Brute-force Alerts`、`Post-failure Login Success Alerts`、`Risk Assessment`、`Geo Location Warnings`、`Top 5 Failed IPs`を出力
- `failed user`: `Unique users tracked`、`User Statistics`、`Brute-force Alerts`、`Post-failure Login Success Alerts`、`Risk Assessment`、`Geo Location Warnings`、`Top 5 Targeted Users`を出力
- `success ip`: `Unique IPs tracked`、`IP Statistics`、`Post-failure Login Success Alerts`、`Risk Assessment`、`Geo Location Warnings`、`Top 5 Successful IPs`を出力
- `success user`: `Unique users tracked`、`User Statistics`、`Post-failure Login Success Alerts`、`Risk Assessment`、`Geo Location Warnings`、`Top 5 Successful Users`を出力

`failed` のような単体フィルタを指定した場合は、条件に一致したログ行と一致件数のみを出力する。
`failed ip` や `success user` のように種類を追加した場合は、指定した集計セクションのみを出力する。
フィルタを指定しない場合は、すべての集計結果を出力する。

`ip=<IPアドレス>` を指定した場合は、通常の集計結果ではなく、指定IPに関する大まかな時系列のみを出力する。
出力例:

```text
IP: 192.0.2.10

10:01:02 Failed password for root
10:01:05 Failed password for admin
10:01:09 Failed password for test
10:01:15 Accepted password for user1
10:03:22 sudo COMMAND=/bin/bash
```

すべての既存コマンドは、末尾に `ja` を付けることで日本語出力に切り替えられる。
`ja` を付けた場合も、ユーザー名、IP、時刻、ログ原文などログ由来の内容はそのままに、見出しや項目名、説明文を日本語で出力する。
`[ALERT]`、`[CRITICAL]`、`Risk Assessment`、`Risk Level`、`Risk Score`、`LOW`、`MEDIUM`、`HIGH`、`CRITICAL` など、単独で表示される英語ラベルは見やすさのため英語のまま出力する。

ブルートフォース警告では、同一IPについて `1分以内に10回`、`5分以内に30回`、`10分以内に50回` のいずれかを満たす失敗ログを検出する。
複数条件に該当する場合は、そのIPで最も広い条件に該当した代表区間を表示する。
ログ行に時刻情報がない失敗ログは、短時間判定の対象外となる。

失敗後ログイン成功警告では、同一IP・同一ユーザーで10回以上失敗した後、30分以内に成功ログが出た場合に `[CRITICAL] Login succeeded after repeated failures` を表示する。
ログ行に時刻情報がない失敗ログまたは成功ログは、この重大アラート判定の対象外となる。

危険度スコアでは、IPごとに以下の条件で加点する。
- `5分以内の失敗回数`: 下表に基づいて加点
- `rootへのログイン試行`: +20
- `存在しないユーザーへの試行`: +10
- `10人以上のユーザーを試行`: +20
- `失敗後にログイン成功`: +50

| 5分以内の失敗回数 | 加点 |
| --------: | ---: |
| 0～9回 | 0点 |
| 10～49回 | +20点 |
| 50～99回 | +30点 |
| 100～249回 | +40点 |
| 250回以上 | +50点 |

合計点は `0～29 LOW`、`30～59 MEDIUM`、`60～89 HIGH`、`90以上 CRITICAL` に分類する。
出力が多くなりすぎないよう、`Risk Assessment` ではHIGHまたはCRITICALに分類されたIPのみ表示する。

ログ行に `country=JP`、`region=Tokyo`、`geoip_country=Japan`、`geoip_region=Tokyo` などの国・地域情報が含まれる場合は、既存の各実行コマンドの出力に国・地域項目と警告が追加される。
ログに国・地域情報がない場合は、IP統計では `(not recorded)` と表示し、警告欄では未記録として表示する。

`sudo` の詳細表示では、auth.logの `COMMAND=` から実行コマンドを出力する。
`su` の詳細表示では、標準的なauth.logに残る切替先ユーザやTTYは出力できるが、su後のシェル内で入力した個別コマンドはauth.logだけでは取得できない。

#### 直接実行コマンド
```bash
gcc -Wall -Wextra -std=c11 -o ssh_log_analyzer src/main.c src/analyzer.c src/parser.c src/report.c
./ssh_log_analyzer sample_log/auth.log failed
./ssh_log_analyzer sample_log/auth.log sudo
./ssh_log_analyzer sample_log/auth.log su
./ssh_log_analyzer sample_log/auth.log ip=192.0.2.10
./ssh_log_analyzer sample_log/auth.log failed ip
./ssh_log_analyzer sample_log/auth.log failed user
./ssh_log_analyzer sample_log/auth.log success ip
./ssh_log_analyzer sample_log/auth.log success user
./ssh_log_analyzer sample_log/auth.log failed ip ja
```
