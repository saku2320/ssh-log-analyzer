#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include "parser.h"

static void init_log_entry(LogEntry *entry) {
    entry->is_failed = 0;
    entry->is_success = 0;
    entry->is_root = 0;
    entry->is_sudo = 0;
    entry->is_su = 0;
    entry->ip[0] = '\0';
    entry->user[0] = '\0';
    entry->sudo_user[0] = '\0';
    entry->sudo_target_user[0] = '\0';
    entry->sudo_tty[0] = '\0';
    entry->sudo_pwd[0] = '\0';
    entry->command[0] = '\0';
    entry->su_target_user[0] = '\0';
    entry->su_login_user[0] = '\0';
    entry->su_tty[0] = '\0';
}

static void extract_ip(const char *line, LogEntry *entry) {
    const char *from_pos = strstr(line, " from ");

    if (from_pos != NULL) {
        sscanf(from_pos + 6, "%63s", entry->ip);
    }
}

static const char *skip_spaces(const char *value) {
    while (*value != '\0' && isspace((unsigned char)*value)) {
        value++;
    }

    return value;
}

static void rstrip_copy(char *dest, size_t dest_size, const char *start, const char *end) {
    size_t length;

    while (end > start && isspace((unsigned char)*(end - 1))) {
        end--;
    }

    length = (size_t)(end - start);
    if (length >= dest_size) {
        length = dest_size - 1;
    }

    memcpy(dest, start, length);
    dest[length] = '\0';
}

static void extract_value_after_key(const char *line, const char *key, char *dest, size_t dest_size) {
    const char *start;
    const char *end;

    start = strstr(line, key);
    if (start == NULL) {
        return;
    }

    start += strlen(key);
    end = strstr(start, " ; ");
    if (end == NULL) {
        end = start + strlen(start);
        while (end > start && (*(end - 1) == '\n' || *(end - 1) == '\r')) {
            end--;
        }
    }

    rstrip_copy(dest, dest_size, start, end);
}

static void extract_sudo_details(const char *line, LogEntry *entry) {
    const char *sudo_pos;
    const char *user_start;
    const char *user_end;

    sudo_pos = strstr(line, " sudo:");
    if (sudo_pos == NULL) {
        return;
    }

    user_start = skip_spaces(sudo_pos + strlen(" sudo:"));
    user_end = strstr(user_start, " : ");
    if (user_end != NULL) {
        rstrip_copy(entry->sudo_user, sizeof(entry->sudo_user), user_start, user_end);
    }

    extract_value_after_key(line, "TTY=", entry->sudo_tty, sizeof(entry->sudo_tty));
    extract_value_after_key(line, "PWD=", entry->sudo_pwd, sizeof(entry->sudo_pwd));
    extract_value_after_key(line, "USER=", entry->sudo_target_user, sizeof(entry->sudo_target_user));
    extract_value_after_key(line, "COMMAND=", entry->command, sizeof(entry->command));
}

static void extract_su_details(const char *line, LogEntry *entry) {
    const char *target_start;
    const char *target_end;
    const char *login_start;
    const char *login_end;
    const char *tty_start;
    const char *tty_end;

    target_start = strstr(line, "(to ");
    if (target_start != NULL) {
        target_start += strlen("(to ");
        target_end = strchr(target_start, ')');
        if (target_end != NULL) {
            rstrip_copy(entry->su_target_user, sizeof(entry->su_target_user), target_start, target_end);
            login_start = skip_spaces(target_end + 1);
            login_end = strstr(login_start, " on ");
            if (login_end != NULL) {
                rstrip_copy(entry->su_login_user, sizeof(entry->su_login_user), login_start, login_end);

                tty_start = login_end + strlen(" on ");
                tty_end = tty_start;
                while (*tty_end != '\0' && !isspace((unsigned char)*tty_end)) {
                    tty_end++;
                }
                rstrip_copy(entry->su_tty, sizeof(entry->su_tty), tty_start, tty_end);
            }
        }
    }
}

int parse_log_line(const char *line, LogEntry *entry) {
    const char *user_start = NULL;
    const char *user_pos = NULL;
    const char *from_pos = NULL;

    init_log_entry(entry);

    if (strstr(line, " sudo:") != NULL && strstr(line, "COMMAND=") != NULL) {
        entry->is_sudo = 1;
        extract_sudo_details(line, entry);

    } else if (strstr(line, " su:") != NULL &&
               strstr(line, "(to ") != NULL &&
               strstr(line, "pam_unix(") == NULL) {
        entry->is_su = 1;
        extract_su_details(line, entry);

    } else if (strstr(line, "Failed password for invalid user ") != NULL) {
        entry->is_failed = 1;
        user_start = strstr(line, "Failed password for invalid user ");
        if (user_start != NULL) {
            sscanf(user_start + strlen("Failed password for invalid user "), "%63s", entry->user);
        }
        extract_ip(line, entry);

    } else if (strstr(line, "Failed password for ") != NULL) {
        entry->is_failed = 1;
        user_start = strstr(line, "Failed password for ");
        if (user_start != NULL) {
            sscanf(user_start + strlen("Failed password for "), "%63s", entry->user);
        }
        extract_ip(line, entry);

    } else if (strstr(line, "Accepted password for ") != NULL) {
        entry->is_success = 1;
        user_start = strstr(line, "Accepted password for ");
        if (user_start != NULL) {
            sscanf(user_start + strlen("Accepted password for "), "%63s", entry->user);
        }
        extract_ip(line, entry);

    } else if (strstr(line, "Invalid user ") != NULL) {
        entry->is_failed = 1;
        user_pos = strstr(line, "Invalid user ");
        if (user_pos != NULL) {
            sscanf(user_pos + strlen("Invalid user "), "%63s", entry->user);
        }

        from_pos = strstr(line, " from ");
        if (from_pos != NULL) {
            sscanf(from_pos + 6, "%63s", entry->ip);
        }

    }else if (strstr(line, "authentication failure") != NULL) {
        const char *rhost = NULL;

        entry->is_failed = 1;

        rhost = strstr(line, "rhost=");
        if (rhost != NULL) {
            sscanf(rhost + 6, "%63s", entry->ip);
        }

    }else {
        return 0;
    }

    if (strcmp(entry->user, "root") == 0) {
        entry->is_root = 1;
    }

    return 1;
}
