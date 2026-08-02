CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g
TARGET = ssh_log_analyzer
WEB_TARGET = ssh_log_web

SRCS = src/main.c src/parser.c src/analyzer.c src/report.c
OBJS = $(SRCS:.c=.o)
WEB_SRCS = src/web.c src/parser.c
WEB_OBJS = $(WEB_SRCS:.c=.web.o)

LOGFILE = sample_log/auth.log
PORT ?= 8080

ARGS ?= $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
RUN_ARGS := $(ARGS) $(if $(ip),ip=$(ip),)


all: $(TARGET)

help:
ifeq ($(filter ja,$(ARGS)),ja)
	@$(MAKE) --no-print-directory help-ja
else
	@$(MAKE) --no-print-directory help-en
endif

help-en:
	@printf '%s\n' 'SSH Log Analyzer command help'
	@printf '%s\n' ''
	@printf '%s\n' 'Build / cleanup:'
	@printf '  %-46s %s\n' 'make all' 'Build the CLI analyzer.'
	@printf '  %-46s %s\n' 'make re' 'Clean and rebuild the CLI analyzer.'
	@printf '  %-46s %s\n' 'make clean' 'Remove generated binaries and object files.'
	@printf '%s\n' ''
	@printf '%s\n' 'CLI analysis:'
	@printf '  %-46s %s\n' 'make run' 'Analyze LOGFILE and print the full CLI report.'
	@printf '  %-46s %s\n' 'make run ja' 'Print the full CLI report in Japanese.'
	@printf '  %-46s %s\n' 'make run failed' 'Show SSH failed-login log lines only.'
	@printf '  %-46s %s\n' 'make run success' 'Show SSH successful-login log lines only.'
	@printf '  %-46s %s\n' 'make run root' 'Show root login attempts only.'
	@printf '  %-46s %s\n' 'make run sudo' 'Show sudo command execution details only.'
	@printf '  %-46s %s\n' 'make run su' 'Show su command execution details only.'
	@printf '  %-46s %s\n' 'make run audit' 'Show audit/supporting session logs only.'
	@printf '  %-46s %s\n' 'make run ip=192.0.2.10' 'Show a timeline for one source IP.'
	@printf '  %-46s %s\n' 'make run failed ip' 'Show failed-login IP report and risk alerts.'
	@printf '  %-46s %s\n' 'make run failed user' 'Show failed-login user report and risk alerts.'
	@printf '  %-46s %s\n' 'make run success ip' 'Show successful-login IP report and root alerts.'
	@printf '  %-46s %s\n' 'make run success user' 'Show successful-login user report and root alerts.'
	@printf '  %-46s %s\n' 'make run failed ip ja' 'Show the failed IP report in Japanese.'
	@printf '%s\n' ''
	@printf '%s\n' 'Web UI:'
	@printf '  %-46s %s\n' 'make start analyzer' 'Start the Web UI at http://localhost:8080.'
	@printf '  %-46s %s\n' 'make start analyzer PORT=8081' 'Start the Web UI on another port.'
	@printf '  %-46s %s\n' 'make start analyzer LOGFILE=path/auth.log' 'Start the Web UI with a specific initial log.'
	@printf '%s\n' ''
	@printf '%s\n' 'Variables:'
	@printf '  %-46s %s\n' 'LOGFILE=sample_log/sam/auth.log' 'Change the target log file.'
	@printf '  %-46s %s\n' 'PORT=8081' 'Change the Web UI port.'
	@printf '%s\n' ''
	@printf '%s\n' 'Stop Web UI: press Ctrl+C in the terminal running make start analyzer.'

help-ja:
	@printf '%s\n' 'SSH Log Analyzer コマンドヘルプ'
	@printf '%s\n' ''
	@printf '%s\n' 'ビルド / 削除:'
	@printf '  %-46s %s\n' 'make all' 'CLI版の解析ツールをビルドします。'
	@printf '  %-46s %s\n' 'make re' '生成物を削除してからCLI版を再ビルドします。'
	@printf '  %-46s %s\n' 'make clean' '生成された実行ファイルとオブジェクトファイルを削除します。'
	@printf '%s\n' ''
	@printf '%s\n' 'CLI解析:'
	@printf '  %-46s %s\n' 'make run' 'LOGFILEを解析し、CLIの全体レポートを表示します。'
	@printf '  %-46s %s\n' 'make run ja' 'CLIの全体レポートを日本語で表示します。'
	@printf '  %-46s %s\n' 'make run failed' 'SSHログイン失敗ログだけを表示します。'
	@printf '  %-46s %s\n' 'make run success' 'SSHログイン成功ログだけを表示します。'
	@printf '  %-46s %s\n' 'make run root' 'rootログイン試行だけを表示します。'
	@printf '  %-46s %s\n' 'make run sudo' 'sudoコマンド実行ログと詳細だけを表示します。'
	@printf '  %-46s %s\n' 'make run su' 'suコマンド実行ログと詳細だけを表示します。'
	@printf '  %-46s %s\n' 'make run audit' '監査ログ・セッション補助情報だけを表示します。'
	@printf '  %-46s %s\n' 'make run ip=192.0.2.10' '指定した接続元IPの時系列を表示します。'
	@printf '  %-46s %s\n' 'make run failed ip' 'ログイン失敗IPレポートと危険度警告を表示します。'
	@printf '  %-46s %s\n' 'make run failed user' 'ログイン失敗ユーザーレポートと危険度警告を表示します。'
	@printf '  %-46s %s\n' 'make run success ip' 'ログイン成功IPレポートとroot警告を表示します。'
	@printf '  %-46s %s\n' 'make run success user' 'ログイン成功ユーザーレポートとroot警告を表示します。'
	@printf '  %-46s %s\n' 'make run failed ip ja' 'ログイン失敗IPレポートを日本語で表示します。'
	@printf '%s\n' ''
	@printf '%s\n' 'Web UI:'
	@printf '  %-46s %s\n' 'make start analyzer' 'Web UIを http://localhost:8080 で起動します。'
	@printf '  %-46s %s\n' 'make start analyzer PORT=8081' 'Web UIを別ポートで起動します。'
	@printf '  %-46s %s\n' 'make start analyzer LOGFILE=path/auth.log' '起動時の解析対象ログを指定してWeb UIを起動します。'
	@printf '%s\n' ''
	@printf '%s\n' '変数:'
	@printf '  %-46s %s\n' 'LOGFILE=sample_log/sam/auth.log' '解析対象ログファイルを変更します。'
	@printf '  %-46s %s\n' 'PORT=8081' 'Web UIのポート番号を変更します。'
	@printf '%s\n' ''
	@printf '%s\n' 'Web UIの終了方法: make start analyzer を実行しているターミナルで Ctrl+C を押します。'

commands: help

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(WEB_TARGET): $(WEB_OBJS)
	$(CC) $(CFLAGS) -o $(WEB_TARGET) $(WEB_OBJS)

src/%.web.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@


run: $(TARGET)
	@./$(TARGET) $(LOGFILE) $(RUN_ARGS)

start: $(WEB_TARGET)
	@./$(WEB_TARGET) $(LOGFILE) $(PORT)

clean:
	rm -f $(TARGET) $(WEB_TARGET) $(OBJS) $(WEB_OBJS)

re: clean all

%:
	@:

.PHONY: all help help-en help-ja commands run start clean re
