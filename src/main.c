#include <stdio.h>
#include <stdlib.h>
#include "parser.h"
#include "analyzer.h"

#define MAX_LINE_LENGTH 1024

int main(int argc, char *argv[]) {
    FILE *fp;
    char line[MAX_LINE_LENGTH];
    LogEntry entry;
    Summary summary;
    IpStats stats[MAX_IP_STATS];
    int i;

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <logfile>\n", argv[0]);
        return 1;
    }

    fp = fopen(argv[1], "r");
    if (fp == NULL) {
        perror("Failed to open file");
        return 1;
    }

    init_summary(&summary);
    init_ip_stats(stats, MAX_IP_STATS);

    while (fgets(line, sizeof(line), fp) != NULL) {
        if (parse_log_line(line, &entry)) {
            update_summary(&summary, &entry);
            update_ip_stats(stats, MAX_IP_STATS, &entry);
        }
    }

    fclose(fp);

    printf("===== SSH Log Analysis Result =====\n");
    printf("Total failed login attempts : %d\n", summary.total_failed);
    printf("Total successful logins     : %d\n", summary.total_success);
    printf("Root login attempts         : %d\n", summary.root_attempts);

    printf("\n===== IP Statistics =====\n");
    for (i = 0; i < MAX_IP_STATS; i++) {
        if (stats[i].ip[0] != '\0') {
            printf("IP: %-15s | Failed: %-3d | Success: %-3d\n",
                   stats[i].ip,
                   stats[i].failed_count,
                   stats[i].success_count);
        }
    }

    return 0;
}
