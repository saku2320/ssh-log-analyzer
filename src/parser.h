#ifndef PARSER_H
#define PARSER_H

#define MAX_IP_LENGTH 64
#define MAX_USER_LENGTH 64
#define MAX_COMMAND_LENGTH 256
#define MAX_PATH_LENGTH 256
#define MAX_TTY_LENGTH 64
#define MAX_GEO_LENGTH 64
#define MAX_TIME_LENGTH 16
#define MAX_TIMESTAMP_LENGTH 32
#define MAX_AUTH_METHOD_LENGTH 16

typedef struct {
    int is_failed;
    int is_success;
    int is_root;
    int is_sudo;
    int is_su;
    int is_invalid_user;
    int has_timestamp;
    int timestamp_seconds;
    char time_text[MAX_TIME_LENGTH];
    char timestamp_text[MAX_TIMESTAMP_LENGTH];
    char ip[MAX_IP_LENGTH];
    char country[MAX_GEO_LENGTH];
    char region[MAX_GEO_LENGTH];
    char user[MAX_USER_LENGTH];
    char auth_method[MAX_AUTH_METHOD_LENGTH];
    char sudo_user[MAX_USER_LENGTH];
    char sudo_target_user[MAX_USER_LENGTH];
    char sudo_tty[MAX_TTY_LENGTH];
    char sudo_pwd[MAX_PATH_LENGTH];
    char command[MAX_COMMAND_LENGTH];
    char su_target_user[MAX_USER_LENGTH];
    char su_login_user[MAX_USER_LENGTH];
    char su_tty[MAX_TTY_LENGTH];
} LogEntry;

int parse_log_line(const char *line, LogEntry *entry);

#endif
