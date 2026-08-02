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

.PHONY: all run start clean re
