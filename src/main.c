#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parser.h"
#include "analyzer.h"
#include "report.h"

#define MAX_LINE_LENGTH 1024
#define ALERT_THRESHOLD 5
#define TOP_N 5
#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_RESET "\033[0m"

typedef enum {
    FILTER_ALL,
    FILTER_FAILED,
    FILTER_SUCCESS,
    FILTER_ROOT
} FilterMode;

static void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s <logfile> [threshold] [--filter all|failed|success|root]\n", program_name);
    fprintf(stderr, "       %s <logfile> [threshold] [--failed-only|--success-only|--root-only]\n", program_name);
}

static int parse_positive_int(const char *value, int *result) {
    char *endptr;
    long parsed;

    parsed = strtol(value, &endptr, 10);
    if (*value == '\0' || *endptr != '\0' || parsed <= 0) {
        return 0;
    }

    *result = (int)parsed;
    return 1;
}

static int parse_filter_value(const char *value, FilterMode *filter_mode) {
    if (strcmp(value, "all") == 0) {
        *filter_mode = FILTER_ALL;
    } else if (strcmp(value, "failed") == 0 || strcmp(value, "ssh-failed") == 0) {
        *filter_mode = FILTER_FAILED;
    } else if (strcmp(value, "success") == 0 || strcmp(value, "ssh-success") == 0) {
        *filter_mode = FILTER_SUCCESS;
    } else if (strcmp(value, "root") == 0) {
        *filter_mode = FILTER_ROOT;
    } else {
        return 0;
    }

    return 1;
}

static const char *filter_label(FilterMode filter_mode) {
    switch (filter_mode) {
        case FILTER_FAILED:
            return "SSH failed only";
        case FILTER_SUCCESS:
            return "SSH success only";
        case FILTER_ROOT:
            return "root attempts only";
        case FILTER_ALL:
        default:
            return "all";
    }
}

static int entry_matches_filter(const LogEntry *entry, FilterMode filter_mode) {
    switch (filter_mode) {
        case FILTER_FAILED:
            return entry->is_failed;
        case FILTER_SUCCESS:
            return entry->is_success;
        case FILTER_ROOT:
            return entry->is_root;
        case FILTER_ALL:
        default:
            return 0;
    }
}

int main(int argc, char *argv[]) {
    FILE *fp;
    char line[MAX_LINE_LENGTH];
    LogEntry entry;
    Summary summary;
    IpStatsList stats;
    int alert_threshold;
    UserStatsList users;
    FilterMode filter_mode = FILTER_ALL;
    unsigned long filtered_lines = 0;
    int i;

    unsigned long total_lines = 0;
    unsigned long parsed_lines = 0;
    unsigned long ignored_lines = 0;

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    alert_threshold = ALERT_THRESHOLD;

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--filter") == 0) {
            if (i + 1 >= argc || !parse_filter_value(argv[i + 1], &filter_mode)) {
                fprintf(stderr, "Filter must be one of: all, failed, success, root\n");
                print_usage(argv[0]);
                return 1;
            }
            i++;
        } else if (strcmp(argv[i], "--failed-only") == 0) {
            filter_mode = FILTER_FAILED;
        } else if (strcmp(argv[i], "--success-only") == 0) {
            filter_mode = FILTER_SUCCESS;
        } else if (strcmp(argv[i], "--root-only") == 0) {
            filter_mode = FILTER_ROOT;
        } else if (!parse_positive_int(argv[i], &alert_threshold)) {
            fprintf(stderr, "Unknown option or invalid threshold: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    fp = fopen(argv[1], "r");
    if (fp == NULL) {
        perror("Failed to open file");
        return 1;
    }


    init_summary(&summary);
    init_ip_stats_list(&stats);

    init_user_stats_list(&users);

    if (filter_mode != FILTER_ALL) {
        printf("===== Filtered Log Lines (%s) =====\n", filter_label(filter_mode));
    }

while (fgets(line, sizeof(line), fp) != NULL) {
    total_lines++;

    if (parse_log_line(line, &entry)) {
        parsed_lines++;
        update_summary(&summary, &entry);

        if (entry_matches_filter(&entry, filter_mode)) {
            printf("%s", line);
            filtered_lines++;
        }

        if (!update_ip_stats(&stats, &entry)) {
            fprintf(stderr, "Failed to update IP stats: out of memory\n");
            fclose(fp);
            free_ip_stats_list(&stats);
            free_user_stats_list(&users);
            return 1;
        }

        if (!update_user_stats(&users, &entry)) {
            fprintf(stderr, "Failed to update user stats: out of memory\n");
            fclose(fp);
            free_ip_stats_list(&stats);
            free_user_stats_list(&users);
            return 1;
        }
    } else {
        ignored_lines++;
    }
}


    fclose(fp);

    if (filter_mode != FILTER_ALL) {
        printf("Matched filtered lines      : " COLOR_GREEN "%lu" COLOR_RESET "\n", filtered_lines);
        free_ip_stats_list(&stats);
        free_user_stats_list(&users);
        return 0;
    }

    print_summary(&summary);

    printf("\n===== Processing Stats =====\n");
    printf("Total lines read           : " COLOR_GREEN "%lu" COLOR_RESET "\n", total_lines);
    printf("Parsed SSH auth lines      : " COLOR_GREEN "%lu" COLOR_RESET "\n", parsed_lines);
    printf("Ignored lines              : " COLOR_YELLOW "%lu" COLOR_RESET "\n", ignored_lines);
    printf("Unique IPs tracked         : " COLOR_RED "%zu" COLOR_RESET "\n", stats.count);

    print_ip_stats(&stats);
    print_suspicious_ips(&stats, alert_threshold);
    print_top_failed_ips(&stats, TOP_N);

    print_user_stats(&users);
    print_top_targeted_users(&users, TOP_N);

    free_ip_stats_list(&stats);

    free_user_stats_list(&users);

    return 0;
}
