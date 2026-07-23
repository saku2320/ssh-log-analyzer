#ifndef PARSER_H
#define PARSER_H

#define MAX_IP_LENGTH 64
#define MAX_USER_LENGTH 64
#define MAX_COMMAND_LENGTH 256
#define MAX_PATH_LENGTH 256
#define MAX_TTY_LENGTH 64

typedef struct {
    int is_failed;
    int is_success;
    int is_root;
    int is_sudo;
    int is_su;
    char ip[MAX_IP_LENGTH];
    char user[MAX_USER_LENGTH];
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
