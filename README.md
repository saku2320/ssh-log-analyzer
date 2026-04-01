# SSH Log Analyzer

C言語で作成するSSHログ解析ツール

## 概要
auth.logを解析し、不正ログイン試行を検出・可視化するCLIツール

実験環境：ubuntu（bash）

## 出力内容
- 総成功回数
- 総失敗回数
- 総root試行回数
- 検出されたIPごとの成功・失敗回数
- 失敗回数が一定以上の不審IPの抽出とそれぞれの失敗回数（検出順）
- 失敗回数が多い順にIPのTop5表示

## ビルド方法
```bash
make
```

## 実行方法
```bash
make run
```
### 直接実行コマンド
```bash
gcc -Wall -Wextra -std=c11 -o ssh_log_analyzer src/main.c src/analyzer.c src/parser.c src/report.c
./ssh_log_analyzer sample_log/auth.log
```

## 構成内容
ssh-log-analyzer$ tree <br>
.<br>
├── Makefile<br>
├── README.md<br>
├── sample_log<br>
│   └── auth.log<br>
└── src<br>
    ├── analyzer.c<br>
    ├── analyzer.h<br>
    ├── main.c<br>
    ├── parser.c<br>
    ├── parser.h<br>
    ├── report.c<br>
    └── report.h<br>

## 対応ログ形式例
現時点では以下のようなSSH認証ログを対象としている。今後、より多くの形式に対応させていく。
- `Failed password for invalid user ... from ...`
- `Failed password for ... from ...`
- `Accepted password for ... from ...`

## 進捗
- 130行程度のサンプルログ（auth.log）での成功・失敗判定それぞれのユーザ名＆IPの出力
- 総成功・失敗回数の出力
- root試行回数の出力
- IPごとの成功・失敗回数の出力
- 失敗回数から、より怪しいIPとそのIPの失敗回数を出力
- 失敗回数が多いIPのTop５を降順で出力
- 約1万900行のサンプルログファイルでも抽出漏れ等がないように改良
- Makefileを作成し、ビルドや実行のコマンドを省略できるように改良


