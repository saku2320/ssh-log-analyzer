#include <stdio.h>
#include <string.h>
#include "parser.h"

static void init_log_entry(LogEntry *entry) {
    entry->is_failed = 0;
    entry->is_success = 0;
    entry->is_root = 0;
    entry->ip[0] = '\0';
    entry->user[0] = '\0';
}

static void extract_ip(const char *line, LogEntry *entry) {
    const char *from_pos = strstr(line, " from ");

    if (from_pos != NULL) {
        sscanf(from_pos + 6, "%63s", entry->ip);
    }
}

int parse_log_line(const char *line, LogEntry *entry) {
    const char *user_start = NULL;

    init_log_entry(entry);

    if (strstr(line, "Failed password for invalid user ") != NULL) {
        entry->is_failed = 1;
        user_start = strstr(line, "Failed password for invalid user ");
        if (user_start != NULL) {
            sscanf(user_start + strlen("Failed password for invalid user "), "%63s", entry->user);
        }
    } else if (strstr(line, "Failed password for ") != NULL) {
        entry->is_failed = 1;
        user_start = strstr(line, "Failed password for ");
        if (user_start != NULL) {
            sscanf(user_start + strlen("Failed password for "), "%63s", entry->user);
        }
    } else if (strstr(line, "Accepted password for ") != NULL) {
        entry->is_success = 1;
        user_start = strstr(line, "Accepted password for ");
        if (user_start != NULL) {
            sscanf(user_start + strlen("Accepted password for "), "%63s", entry->user);
        }
    } else {
        return 0;
    }

    extract_ip(line, entry);

    if (strcmp(entry->user, "root") == 0) {
        entry->is_root = 1;
    }

    return 1;
}
