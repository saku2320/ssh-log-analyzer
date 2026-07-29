#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "parser.h"
#include "analyzer.h"
#include "report.h"

#define MAX_LINE_LENGTH 1024
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

typedef struct {
    char users[256][MAX_USER_LENGTH];
    size_t count;
} TargetUserList;

static void print_usage(const char *program_name) {
    fprintf(stderr, "Usage: %s <logfile> [failed|success|root|sudo|su] [ja]\n", program_name);
    fprintf(stderr, "       %s <logfile> [failed|success] [ip|user] [ja]\n", program_name);
    fprintf(stderr, "       %s <logfile> ip=<address> [ja]\n", program_name);
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

static int parse_ip_timeline_argument(const char *value, const char **target_ip) {
    if (strncmp(value, "ip=", 3) != 0 || value[3] == '\0') {
        return 0;
    }

    *target_ip = value + 3;
    return 1;
}

static const char *filter_label(FilterMode filter_mode, OutputLanguage language) {
    switch (filter_mode) {
        case FILTER_FAILED:
            return language == OUTPUT_JA ? "SSH失敗のみ" : "SSH failed only";
        case FILTER_SUCCESS:
            return language == OUTPUT_JA ? "SSH成功のみ" : "SSH success only";
        case FILTER_ROOT:
            return language == OUTPUT_JA ? "root試行のみ" : "root attempts only";
        case FILTER_SUDO:
            return language == OUTPUT_JA ? "sudoコマンド実行のみ" : "sudo command executions only";
        case FILTER_SU:
            return language == OUTPUT_JA ? "suコマンド実行のみ" : "su command executions only";
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

static const char *display_value(const char *value, OutputLanguage language) {
    if (value[0] == '\0') {
        return language == OUTPUT_JA ? "(不明)" : "(unknown)";
    }

    return value;
}

static int entry_has_geo(const LogEntry *entry) {
    return entry->country[0] != '\0' || entry->region[0] != '\0';
}

static void print_entry_geo_detail(const LogEntry *entry, OutputLanguage language) {
    if (entry_has_geo(entry)) {
        printf(language == OUTPUT_JA ? "  国・地域警告 : 国=%s, 地域=%s\n" : "  Geo warning : country=%s, region=%s\n",
               display_value(entry->country, language),
               display_value(entry->region, language));
    }
}

static void print_filtered_entry_detail(const LogEntry *entry,
                                        FilterMode filter_mode,
                                        const char *line,
                                        unsigned long index,
                                        OutputLanguage language) {
    if (filter_mode == FILTER_SUDO) {
        printf(language == OUTPUT_JA ? "[%lu] sudoコマンド実行\n" : "[%lu] sudo command execution\n", index);
        printf(language == OUTPUT_JA ? "  ユーザー     : %s\n" : "  User        : %s\n", display_value(entry->sudo_user, language));
        printf(language == OUTPUT_JA ? "  切替先ユーザー : %s\n" : "  Target user : %s\n", display_value(entry->sudo_target_user, language));
        printf("  TTY         : %s\n", display_value(entry->sudo_tty, language));
        printf("  PWD         : %s\n", display_value(entry->sudo_pwd, language));
        printf(language == OUTPUT_JA ? "  コマンド     : %s\n" : "  Command     : %s\n", display_value(entry->command, language));
        print_entry_geo_detail(entry, language);
        printf(language == OUTPUT_JA ? "  元ログ       : %s" : "  Raw log     : %s", line);
        return;
    }

    if (filter_mode == FILTER_SU) {
        printf(language == OUTPUT_JA ? "[%lu] suコマンド実行\n" : "[%lu] su command execution\n", index);
        printf(language == OUTPUT_JA ? "  ログインユーザー : %s\n" : "  Login user  : %s\n", display_value(entry->su_login_user, language));
        printf(language == OUTPUT_JA ? "  切替先ユーザー   : %s\n" : "  Target user : %s\n", display_value(entry->su_target_user, language));
        printf("  TTY         : %s\n", display_value(entry->su_tty, language));
        printf(language == OUTPUT_JA ? "  コマンド         : auth.logには記録されません\n" : "  Command     : not recorded in auth.log\n");
        print_entry_geo_detail(entry, language);
        printf(language == OUTPUT_JA ? "  元ログ           : %s" : "  Raw log     : %s", line);
        return;
    }

    printf("%s", line);
    print_entry_geo_detail(entry, language);
}

static int target_user_is_tracked(const TargetUserList *target_users, const char *user) {
    size_t i;

    if (user[0] == '\0') {
        return 0;
    }

    for (i = 0; i < target_users->count; i++) {
        if (strcmp(target_users->users[i], user) == 0) {
            return 1;
        }
    }

    return 0;
}

static void track_target_user(TargetUserList *target_users, const char *user) {
    if (user[0] == '\0' || target_user_is_tracked(target_users, user)) {
        return;
    }

    if (target_users->count >= sizeof(target_users->users) / sizeof(target_users->users[0])) {
        return;
    }

    strncpy(target_users->users[target_users->count], user, MAX_USER_LENGTH - 1);
    target_users->users[target_users->count][MAX_USER_LENGTH - 1] = '\0';
    target_users->count++;
}

static const char *entry_time_display(const LogEntry *entry) {
    return entry->has_timestamp ? entry->time_text : "--:--:--";
}

static void print_ip_timeline_header(const char *target_ip, OutputLanguage language) {
    printf(language == OUTPUT_JA ? "IP: %s\n\n" : "IP: %s\n\n", target_ip);
}

static int print_ip_timeline_entry(const LogEntry *entry,
                                   const char *target_ip,
                                   TargetUserList *target_users,
                                   OutputLanguage language) {
    if (entry->ip[0] != '\0' && strcmp(entry->ip, target_ip) == 0) {
        if (entry->is_failed) {
            if (entry->user[0] == '\0') {
                printf("%s Authentication failure\n", entry_time_display(entry));
            } else {
                printf("%s Failed password for %s\n",
                       entry_time_display(entry),
                       display_value(entry->user, language));
            }
            return 1;
        }

        if (entry->is_success) {
            printf("%s Accepted password for %s\n",
                   entry_time_display(entry),
                   display_value(entry->user, language));
            track_target_user(target_users, entry->user);
            return 1;
        }
    }

    if (entry->is_sudo && target_user_is_tracked(target_users, entry->sudo_user)) {
        printf("%s sudo COMMAND=%s\n",
               entry_time_display(entry),
               display_value(entry->command, language));
        return 1;
    }

    if (entry->is_su && target_user_is_tracked(target_users, entry->su_login_user)) {
        printf("%s su to %s\n",
               entry_time_display(entry),
               display_value(entry->su_target_user, language));
        return 1;
    }

    return 0;
}

int main(int argc, char *argv[]) {
    FILE *fp;
    char line[MAX_LINE_LENGTH];
    LogEntry entry;
    Summary summary;
    IpStatsList stats;
    FailureEventList failure_events;
    SuccessEventList success_events;
    int ignored_threshold;
    UserStatsList users;
    FilterMode filter_mode = FILTER_ALL;
    ReportMode report_mode = REPORT_NONE;
    OutputLanguage output_language = OUTPUT_EN;
    const char *target_ip = NULL;
    TargetUserList target_users;
    unsigned long timeline_lines = 0;
    unsigned long filtered_lines = 0;
    int i;

    unsigned long total_lines = 0;
    unsigned long parsed_lines = 0;
    unsigned long ignored_lines = 0;

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    for (i = 2; i < argc; i++) {
        if (strcmp(argv[i], "ja") == 0) {
            output_language = OUTPUT_JA;
            continue;
        } else if (parse_ip_timeline_argument(argv[i], &target_ip)) {
            continue;
        } else if (parse_filter_argument(argv[i], &filter_mode)) {
            continue;
        } else if (parse_report_argument(argv[i], &report_mode)) {
            continue;
        } else if (parse_positive_int(argv[i], &ignored_threshold)) {
            continue;
        } else {
            fprintf(stderr, "Unknown option or invalid threshold: %s\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    set_report_language(output_language);
    target_users.count = 0;

    if (report_mode != REPORT_NONE && filter_mode != FILTER_FAILED && filter_mode != FILTER_SUCCESS) {
        fprintf(stderr, "Report mode must be used with failed or success.\n");
        print_usage(argv[0]);
        return 1;
    }

    if (target_ip != NULL && (filter_mode != FILTER_ALL || report_mode != REPORT_NONE)) {
        fprintf(stderr, "IP timeline mode cannot be combined with filters or report modes.\n");
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
    init_failure_event_list(&failure_events);
    init_success_event_list(&success_events);

    init_user_stats_list(&users);

    if (target_ip != NULL) {
        print_ip_timeline_header(target_ip, output_language);
    } else if (filter_mode != FILTER_ALL && report_mode == REPORT_NONE) {
        printf("===== %s (%s) =====\n",
               output_language == OUTPUT_JA ? "フィルタ済みログ行" : "Filtered Log Lines",
               filter_label(filter_mode, output_language));
    }

while (fgets(line, sizeof(line), fp) != NULL) {
    total_lines++;

    if (parse_log_line(line, &entry)) {
        parsed_lines++;
        update_summary(&summary, &entry);

        if (target_ip != NULL) {
            if (print_ip_timeline_entry(&entry, target_ip, &target_users, output_language)) {
                timeline_lines++;
            }
        } else if (report_mode == REPORT_NONE && entry_matches_filter(&entry, filter_mode)) {
            filtered_lines++;
            print_filtered_entry_detail(&entry, filter_mode, line, filtered_lines, output_language);
        }

        if (!update_ip_stats(&stats, &entry)) {
            fprintf(stderr, "Failed to update IP stats: out of memory\n");
            fclose(fp);
            free_ip_stats_list(&stats);
            free_failure_event_list(&failure_events);
            free_success_event_list(&success_events);
            free_user_stats_list(&users);
            return 1;
        }

        if (!update_user_stats(&users, &entry)) {
            fprintf(stderr, "Failed to update user stats: out of memory\n");
            fclose(fp);
            free_ip_stats_list(&stats);
            free_failure_event_list(&failure_events);
            free_success_event_list(&success_events);
            free_user_stats_list(&users);
            return 1;
        }

        if (!update_failure_events(&failure_events, &entry)) {
            fprintf(stderr, "Failed to update failure events: out of memory\n");
            fclose(fp);
            free_ip_stats_list(&stats);
            free_failure_event_list(&failure_events);
            free_success_event_list(&success_events);
            free_user_stats_list(&users);
            return 1;
        }

        if (!update_success_events(&success_events, &entry)) {
            fprintf(stderr, "Failed to update success events: out of memory\n");
            fclose(fp);
            free_ip_stats_list(&stats);
            free_failure_event_list(&failure_events);
            free_success_event_list(&success_events);
            free_user_stats_list(&users);
            return 1;
        }
    } else {
        ignored_lines++;
    }
}


    fclose(fp);

    if (target_ip != NULL) {
        if (timeline_lines == 0) {
            printf("%s\n", output_language == OUTPUT_JA ? "対象IPのログは見つかりませんでした。" : "No timeline events found for this IP.");
        }
        free_ip_stats_list(&stats);
        free_failure_event_list(&failure_events);
        free_success_event_list(&success_events);
        free_user_stats_list(&users);
        return 0;
    }

    if (report_mode == REPORT_IP && filter_mode == FILTER_FAILED) {
        printf("===== %s =====\n", output_language == OUTPUT_JA ? "失敗IPレポート" : "Failed IP Report");
        printf("%s         : " COLOR_RED "%zu" COLOR_RESET "\n", output_language == OUTPUT_JA ? "追跡IP数" : "Unique IPs tracked", stats.count);
        print_bruteforce_alerts(&failure_events);
        print_post_failure_success_alerts(&failure_events, &success_events);
        print_risk_assessment(&failure_events, &success_events);
        print_geo_warnings(&stats);
        print_top_failed_ips(&stats, TOP_N);
        free_ip_stats_list(&stats);
        free_failure_event_list(&failure_events);
        free_success_event_list(&success_events);
        free_user_stats_list(&users);
        return 0;
    }

    if (report_mode == REPORT_USER && filter_mode == FILTER_FAILED) {
        printf("===== %s =====\n", output_language == OUTPUT_JA ? "失敗ユーザーレポート" : "Failed User Report");
        printf("%s       : " COLOR_RED "%zu" COLOR_RESET "\n", output_language == OUTPUT_JA ? "追跡ユーザー数" : "Unique users tracked", users.count);
        print_user_stats(&users);
        print_bruteforce_alerts(&failure_events);
        print_post_failure_success_alerts(&failure_events, &success_events);
        print_risk_assessment(&failure_events, &success_events);
        print_geo_warnings(&stats);
        print_top_targeted_users(&users, TOP_N);
        free_ip_stats_list(&stats);
        free_failure_event_list(&failure_events);
        free_success_event_list(&success_events);
        free_user_stats_list(&users);
        return 0;
    }

    if (report_mode == REPORT_IP && filter_mode == FILTER_SUCCESS) {
        printf("===== %s =====\n", output_language == OUTPUT_JA ? "成功IPレポート" : "Success IP Report");
        printf("%s         : " COLOR_GREEN "%zu" COLOR_RESET "\n", output_language == OUTPUT_JA ? "追跡IP数" : "Unique IPs tracked", stats.count);
        print_ip_stats(&stats);
        print_post_failure_success_alerts(&failure_events, &success_events);
        print_risk_assessment(&failure_events, &success_events);
        print_geo_warnings(&stats);
        print_top_successful_ips(&stats, TOP_N);
        free_ip_stats_list(&stats);
        free_failure_event_list(&failure_events);
        free_success_event_list(&success_events);
        free_user_stats_list(&users);
        return 0;
    }

    if (report_mode == REPORT_USER && filter_mode == FILTER_SUCCESS) {
        printf("===== %s =====\n", output_language == OUTPUT_JA ? "成功ユーザーレポート" : "Success User Report");
        printf("%s       : " COLOR_GREEN "%zu" COLOR_RESET "\n", output_language == OUTPUT_JA ? "追跡ユーザー数" : "Unique users tracked", users.count);
        print_user_stats(&users);
        print_post_failure_success_alerts(&failure_events, &success_events);
        print_risk_assessment(&failure_events, &success_events);
        print_geo_warnings(&stats);
        print_top_successful_users(&users, TOP_N);
        free_ip_stats_list(&stats);
        free_failure_event_list(&failure_events);
        free_success_event_list(&success_events);
        free_user_stats_list(&users);
        return 0;
    }

    if (filter_mode != FILTER_ALL) {
        printf("%s      : " COLOR_GREEN "%lu" COLOR_RESET "\n", output_language == OUTPUT_JA ? "一致したログ行数" : "Matched filtered lines", filtered_lines);
        free_ip_stats_list(&stats);
        free_failure_event_list(&failure_events);
        free_success_event_list(&success_events);
        free_user_stats_list(&users);
        return 0;
    }

    print_summary(&summary);

    printf("\n===== %s =====\n", output_language == OUTPUT_JA ? "処理統計" : "Processing Stats");
    printf("%s           : " COLOR_GREEN "%lu" COLOR_RESET "\n", output_language == OUTPUT_JA ? "読み込んだ行数" : "Total lines read", total_lines);
    printf("%s          : " COLOR_GREEN "%lu" COLOR_RESET "\n", output_language == OUTPUT_JA ? "解析対象行数" : "Parsed auth lines", parsed_lines);
    printf("%s              : " COLOR_YELLOW "%lu" COLOR_RESET "\n", output_language == OUTPUT_JA ? "無視された行数" : "Ignored lines", ignored_lines);
    printf("%s         : " COLOR_RED "%zu" COLOR_RESET "\n", output_language == OUTPUT_JA ? "追跡IP数" : "Unique IPs tracked", stats.count);

    print_ip_stats(&stats);
    print_bruteforce_alerts(&failure_events);
    print_post_failure_success_alerts(&failure_events, &success_events);
    print_risk_assessment(&failure_events, &success_events);
    print_geo_warnings(&stats);
    print_top_failed_ips(&stats, TOP_N);
    print_top_successful_ips(&stats, TOP_N);

    print_user_stats(&users);
    print_top_targeted_users(&users, TOP_N);

    free_ip_stats_list(&stats);
    free_failure_event_list(&failure_events);
    free_success_event_list(&success_events);

    free_user_stats_list(&users);

    return 0;
}
