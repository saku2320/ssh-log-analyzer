CC = gcc
CFLAGS = -Wall -Wextra -std=c11 -g
TARGET = ssh_log_analyzer

SRCS = src/main.c src/parser.c src/analyzer.c src/report.c
OBJS = $(SRCS:.c=.o)

LOGFILE = sample_log/auth.log

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

src/%.o: src/%.c
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	@./$(TARGET) $(LOGFILE)

clean:
	rm -f $(TARGET) $(OBJS)

re: clean all

.PHONY: all run clean re
