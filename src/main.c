#include <stdio.h>
#include <stdlib.h>
#include "parser.h"

#define MAX_LINE_LENGTH 1024

int main(int argc, char *argv[]) {
    FILE *fp;
    char line[MAX_LINE_LENGTH];
    LogEntry entry;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <logfile>\n", argv[0]);
        return 1;
    }

    fp = fopen(argv[1], "r");
    if (fp == NULL) {
        perror("Failed to open file");
        return 1;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (parse_log_line(line, &entry)) {
            printf("type: ");
            if (entry.is_failed) {
                printf("FAILED");
            } else if (entry.is_success) {
                printf("SUCCESS");
            }

            printf(", user: %s, ip: %s", entry.user, entry.ip);

            if (entry.is_root) {
                printf(", root attempt");
            }

            printf("\n");
        }
    }

    fclose(fp);
    return 0;
}
