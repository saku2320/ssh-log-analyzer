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

.PHONY: all help commands run start clean re
