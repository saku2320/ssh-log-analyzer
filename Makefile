CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g
TARGET = ssh_log_analyzer

SRCS = src/main.c src/parser.c src/analyzer.c src/report.c
OBJS = $(SRCS:.c=.o)

LOGFILE = sample_log/auth.log

ARGS ?= $(wordlist 2,$(words $(MAKECMDGOALS)),$(MAKECMDGOALS))
RUN_ARGS := $(if $(ARGS),$(ARGS),5)


all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@


run: $(TARGET)
	@./$(TARGET) $(LOGFILE) $(RUN_ARGS)

clean:
	rm -f $(TARGET) $(OBJS)

re: clean all

%:
	@:

.PHONY: all run clean re
