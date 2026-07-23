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
    FILTER_ROOT,
    FILTER_SUDO,
    FILTER_SU
} FilterMode;

typedef enum {
    REPORT_NONE,
    REPORT_IP,
    REPORT_USER
} ReportMode;

static void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s <logfile> [threshold] [failed|success|root|sudo|su]\n", program_name);
    fprintf(stderr, "       %s <logfile> [threshold] [failed|success] [ip|user]\n", program_name);
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
    if (strcmp(value, "failed") == 0 || strcmp(value, "ssh-failed") == 0) {
        *filter_mode = FILTER_FAILED;
    } else if (strcmp(value, "success") == 0 || strcmp(value, "ssh-success") == 0) {
        *filter_mode = FILTER_SUCCESS;
    } else if (strcmp(value, "root") == 0) {
        *filter_mode = FILTER_ROOT;
    } else if (strcmp(value, "sudo") == 0) {
        *filter_mode = FILTER_SUDO;
    } else if (strcmp(value, "su") == 0) {
        *filter_mode = FILTER_SU;
    } else {
        return 0;
    }

    return 1;
}

static int parse_filter_argument(const char *value, FilterMode *filter_mode) {
    return parse_filter_value(value, filter_mode);
}

static int parse_report_argument(const char *value, ReportMode *report_mode) {
    if (strcmp(value, "ip") == 0 || strcmp(value, "ips") == 0) {
        *report_mode = REPORT_IP;
    } else if (strcmp(value, "user") == 0 || strcmp(value, "users") == 0) {
        *report_mode = REPORT_USER;
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
        case FILTER_SUDO:
            return "sudo command executions only";
        case FILTER_SU:
            return "su command executions only";
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
        case FILTER_SUDO:
            return entry->is_sudo;
        case FILTER_SU:
            return entry->is_su;
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
    ReportMode report_mode = REPORT_NONE;
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
        if (parse_filter_argument(argv[i], &filter_mode)) {
            continue;
        } else if (parse_report_argument(argv[i], &report_mode)) {
            continue;
        } else if (!parse_positive_int(argv[i], &alert_threshold)) {
            fprintf(stderr, "Unknown option or invalid threshold: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    if (report_mode != REPORT_NONE && filter_mode != FILTER_FAILED && filter_mode != FILTER_SUCCESS) {
        fprintf(stderr, "Report mode must be used with failed or success.\n");
        print_usage(argv[0]);
        return 1;
    }

    fp = fopen(argv[1], "r");
    if (fp == NULL) {
        perror("Failed to open file");
        return 1;
    }


    init_summary(&summary);
    init_ip_stats_list(&stats);

    init_user_stats_list(&users);

    if (filter_mode != FILTER_ALL && report_mode == REPORT_NONE) {
        printf("===== Filtered Log Lines (%s) =====\n", filter_label(filter_mode));
    }

while (fgets(line, sizeof(line), fp) != NULL) {
    total_lines++;

    if (parse_log_line(line, &entry)) {
        parsed_lines++;
        update_summary(&summary, &entry);

        if (report_mode == REPORT_NONE && entry_matches_filter(&entry, filter_mode)) {
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

    if (report_mode == REPORT_IP && filter_mode == FILTER_FAILED) {
        printf("===== Failed IP Report =====\n");
        printf("Unique IPs tracked         : " COLOR_RED "%zu" COLOR_RESET "\n", stats.count);
        print_suspicious_ips(&stats, alert_threshold);
        print_top_failed_ips(&stats, TOP_N);
        free_ip_stats_list(&stats);
        free_user_stats_list(&users);
        return 0;
    }

    if (report_mode == REPORT_USER && filter_mode == FILTER_FAILED) {
        printf("===== Failed User Report =====\n");
        printf("Unique users tracked       : " COLOR_RED "%zu" COLOR_RESET "\n", users.count);
        print_user_stats(&users);
        print_top_targeted_users(&users, TOP_N);
        free_ip_stats_list(&stats);
        free_user_stats_list(&users);
        return 0;
    }

    if (report_mode == REPORT_IP && filter_mode == FILTER_SUCCESS) {
        printf("===== Success IP Report =====\n");
        printf("Unique IPs tracked         : " COLOR_GREEN "%zu" COLOR_RESET "\n", stats.count);
        print_ip_stats(&stats);
        print_top_successful_ips(&stats, TOP_N);
        free_ip_stats_list(&stats);
        free_user_stats_list(&users);
        return 0;
    }

    if (report_mode == REPORT_USER && filter_mode == FILTER_SUCCESS) {
        printf("===== Success User Report =====\n");
        printf("Unique users tracked       : " COLOR_GREEN "%zu" COLOR_RESET "\n", users.count);
        print_user_stats(&users);
        print_top_successful_users(&users, TOP_N);
        free_ip_stats_list(&stats);
        free_user_stats_list(&users);
        return 0;
    }

    if (filter_mode != FILTER_ALL) {
        printf("Matched filtered lines      : " COLOR_GREEN "%lu" COLOR_RESET "\n", filtered_lines);
        free_ip_stats_list(&stats);
        free_user_stats_list(&users);
        return 0;
    }

    print_summary(&summary);

    printf("\n===== Processing Stats =====\n");
    printf("Total lines read           : " COLOR_GREEN "%lu" COLOR_RESET "\n", total_lines);
    printf("Parsed auth lines          : " COLOR_GREEN "%lu" COLOR_RESET "\n", parsed_lines);
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
