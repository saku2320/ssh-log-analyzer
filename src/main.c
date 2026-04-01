#include <stdio.h>
#include <stdlib.h>
#include "parser.h"
#include "analyzer.h"
#include "report.h"

#define MAX_LINE_LENGTH 1024
#define ALERT_THRESHOLD 5
#define TOP_N 5

int main(int argc, char *argv[]) {
    FILE *fp;
    char line[MAX_LINE_LENGTH];
    LogEntry entry;
    Summary summary;
    IpStatsList stats;

    unsigned long total_lines = 0;
    unsigned long parsed_lines = 0;
    unsigned long ignored_lines = 0;

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
    init_ip_stats_list(&stats);

    while (fgets(line, sizeof(line), fp) != NULL) {
        total_lines++;

        if (parse_log_line(line, &entry)) {
            parsed_lines++;
            update_summary(&summary, &entry);

            if (!update_ip_stats(&stats, &entry)) {
                fprintf(stderr, "Failed to update IP stats: out of memory\n");
                fclose(fp);
                free_ip_stats_list(&stats);
                return 1;
            }
        } else {
            ignored_lines++;
        }
    }

    fclose(fp);

    print_summary(&summary);

    printf("\n===== Processing Stats =====\n");
    printf("Total lines read           : %lu\n", total_lines);
    printf("Parsed SSH auth lines      : %lu\n", parsed_lines);
    printf("Ignored lines              : %lu\n", ignored_lines);
    printf("Unique IPs tracked         : %zu\n", stats.count);

    print_ip_stats(&stats);
    print_suspicious_ips(&stats, ALERT_THRESHOLD);
    print_top_failed_ips(&stats, TOP_N);

    free_ip_stats_list(&stats);
    return 0;
}
