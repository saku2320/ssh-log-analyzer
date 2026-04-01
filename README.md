# SSH Log Analyzer

C言語で作成するSSHログ解析ツール

## 概要
Linuxのauth.logを解析し、不正ログイン試行を検出・可視化するCLIツール

想定環境：ubuntu（bash）

## 進捗
- 130行程度のサンプルログ（auth.log）での成功・失敗判定それぞれのユーザ名＆IPの出力
- 総成功・失敗回数の出力
- root試行回数の出力
- IPごとの成功・失敗回数の出力
