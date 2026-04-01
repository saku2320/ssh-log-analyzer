#ifndef PARSER_H
#define PARSER_H

#define MAX_IP_LENGTH 64
#define MAX_USER_LENGTH 64

typedef struct {
    int is_failed;
    int is_success;
    int is_root;
    char ip[MAX_IP_LENGTH];
    char user[MAX_USER_LENGTH];
} LogEntry;

int parse_log_line(const char *line, LogEntry *entry);

#endif
