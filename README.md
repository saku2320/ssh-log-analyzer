## SSHログ解析ツール（CLI）

## 概要
auth.logを解析し、SSHログイン試行を検出・可視化するCLIツール

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
#### ログ統計
- 読み込んだログの行数
- SSH認証関連の行数
- 無視された行数
- 検出されたIPの総数
#### IP統計
- 検出された全IPごとの成功・失敗回数
#### 不審IP
- 失敗回数が一定以上の不審IPの抽出とそれぞれの失敗回数（検出順）
#### 失敗IP Top5
- 失敗回数が多い順にIPのTop5
#### ユーザ統計
- 検出された全ユーザ名ごとの成功・失敗回数
#### 失敗ユーザ Top5
- 失敗回数が多い順にユーザ名のTop5


## 対応ログ形式例
現時点では以下のようなSSH認証ログを対象としている。今後、より多くの形式に対応させていく予定。
- `Failed password for invalid user ... from ...`
- `Failed password for ... from ...`
- `Accepted password for ... from ...`
- `Invalid user ... from ...`
- `pam_unix(sshd:auth): authentication failure; ... rhost=... user=...` (IPのみの取得)

## 進捗
- 130行程度のサンプルログ（auth.log）での成功・失敗判定それぞれのユーザ名＆IPの出力
- 総成功・失敗回数の出力
- root試行回数の出力
- IPごとの成功・失敗回数の出力
- 失敗回数から、より怪しいIPとそのIPの失敗回数を出力
- 失敗回数が多いIPのTop５を降順で出力
- 約1万900行のサンプルログファイルでも抽出漏れ等がないように改良
- Makefileを作成し、ビルドや実行のコマンドを省略できるように改良
- 対応ログ形式を追加（Invalid userログ＆PAMログ）
- ログイン試行に使われたユーザ名ごとの成功・失敗回数の出力を追加
- 失敗回数が多いユーザ名のTop5を降順で出力
- 不審IP検出基準をコマンド実行時に引数として自由に変更可に
- 失敗IP・不審IP・失敗ユーザ名等を色分けして表示できるように改良
- `failed` でSSH失敗ログのみを簡単に出力できるように改良

## 目標
- ブルートフォース攻撃疑いを検出可に
- ありえない時間帯（企業であれば業務時間外など）に行われたログの検出
- 接続元IPから国・地域を特定し、警告を表示
- sudo やsuコマンドの実行の検知


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
make run ??
```

> ??には不審IPのしきい値として引数を指定 <br>
指定しない場合、自動的に５が入る

#### フィルタ実行例
```bash
make run failed
make run success
make run root
make run failed ip
make run failed user
make run success ip
make run success user
```

使用できるフィルタ条件
- `failed`: SSH失敗ログのみ出力
- `success`: SSH成功ログのみ出力
- `root`: rootログイン試行のみ出力
- `failed ip`: `Unique IPs tracked`、`Suspicious IPs`、`Top 5 Failed IPs`のみ出力
- `failed user`: `Unique users tracked`、`User Statistics`、`Top 5 Targeted Users`のみ出力
- `success ip`: `Unique IPs tracked`、`IP Statistics`、`Top 5 Successful IPs`のみ出力
- `success user`: `Unique users tracked`、`User Statistics`、`Top 5 Successful Users`のみ出力
- `all`: フィルタなし

`failed` のような単体フィルタを指定した場合は、条件に一致したログ行と一致件数のみを出力する。
`failed ip` や `success user` のように種類を追加した場合は、指定した集計セクションのみを出力する。

#### 直接実行コマンド
```bash
gcc -Wall -Wextra -std=c11 -o ssh_log_analyzer src/main.c src/analyzer.c src/parser.c src/report.c
./ssh_log_analyzer sample_log/auth.log ??
./ssh_log_analyzer sample_log/auth.log failed
./ssh_log_analyzer sample_log/auth.log failed ip
./ssh_log_analyzer sample_log/auth.log failed user
./ssh_log_analyzer sample_log/auth.log success ip
./ssh_log_analyzer sample_log/auth.log success user
```
