#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "report.h"

#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BOLD "\033[1m"
#define COLOR_RESET "\033[0m"
#define BRUTEFORCE_RULE_COUNT 3

typedef struct {
    int window_seconds;
    int failure_threshold;
} BruteForceRule;

static const BruteForceRule BRUTEFORCE_RULES[BRUTEFORCE_RULE_COUNT] = {
    {60, 10},
    {300, 30},
    {600, 50}
};

static void copy_ip_stats(IpStats *dest, const IpStats *src, size_t count) {
    size_t i;

    for (i = 0; i < count; i++) {
        dest[i] = src[i];
    }
}

static void sort_by_failed_count_desc(IpStats stats[], size_t count) {
    size_t i;
    size_t j;
    IpStats temp;

    for (i = 0; i < count; i++) {
        for (j = 0; j + 1 < count - i; j++) {
            if (stats[j].failed_count < stats[j + 1].failed_count) {
                temp = stats[j];
                stats[j] = stats[j + 1];
                stats[j + 1] = temp;
            }
        }
    }
}

static void sort_by_success_count_desc(IpStats stats[], size_t count) {
    size_t i;
    size_t j;
    IpStats temp;

    for (i = 0; i < count; i++) {
        for (j = 0; j + 1 < count - i; j++) {
            if (stats[j].success_count < stats[j + 1].success_count) {
                temp = stats[j];
                stats[j] = stats[j + 1];
                stats[j + 1] = temp;
            }
        }
    }
}

static const char *geo_display_value(const char *value) {
    if (value[0] == '\0') {
        return "(not recorded)";
    }

    return value;
}

static int has_geo(const IpStats *stats) {
    return stats->country[0] != '\0' || stats->region[0] != '\0';
}

static int user_is_listed(const char *users[], size_t user_count, const char *user) {
    size_t i;

    for (i = 0; i < user_count; i++) {
        if (strcmp(users[i], user) == 0) {
            return 1;
        }
    }

    return 0;
}

static void print_alert_users(const FailureEventList *list, size_t start, size_t end, const char *ip) {
    const char *users[128];
    size_t user_count = 0;
    size_t i;

    for (i = start; i <= end; i++) {
        if (strcmp(list->items[i].ip, ip) != 0) {
            continue;
        }

        if (list->items[i].user[0] == '\0') {
            continue;
        }

        if (user_count < 128 && !user_is_listed(users, user_count, list->items[i].user)) {
            users[user_count] = list->items[i].user;
            user_count++;
        }
    }

    printf("Users      : ");
    if (user_count == 0) {
        printf("(unknown)");
    } else {
        for (i = 0; i < user_count; i++) {
            if (i > 0) {
                printf(", ");
            }
            printf("%s", users[i]);
        }
    }
    printf("\n");
}

static void print_bruteforce_alert(const FailureEventList *list, const char *ip, size_t start, size_t end, int failures) {
    printf(COLOR_BOLD COLOR_RED "[ALERT] SSH brute-force suspected" COLOR_RESET "\n");
    printf("IP Address : %s\n", ip);
    printf("Period     : %s - %s\n", list->items[start].time_text, list->items[end].time_text);
    printf("Failures   : %d\n", failures);
    print_alert_users(list, start, end, ip);
    printf("\n");
}

static int ip_already_checked(const FailureEventList *list, size_t current) {
    size_t i;

    for (i = 0; i < current; i++) {
        if (strcmp(list->items[i].ip, list->items[current].ip) == 0) {
            return 1;
        }
    }

    return 0;
}

static void find_best_window_for_ip(const FailureEventList *list,
                                    const char *ip,
                                    int window_seconds,
                                    size_t *best_start,
                                    size_t *best_end,
                                    int *best_count) {
    size_t start;
    size_t end;
    int count;

    *best_start = 0;
    *best_end = 0;
    *best_count = 0;

    for (start = 0; start < list->count; start++) {
        if (strcmp(list->items[start].ip, ip) != 0) {
            continue;
        }

        count = 0;
        for (end = start; end < list->count; end++) {
            if (list->items[end].timestamp_seconds - list->items[start].timestamp_seconds > window_seconds) {
                break;
            }

            if (strcmp(list->items[end].ip, ip) == 0) {
                count++;
                if (count > *best_count) {
                    *best_count = count;
                    *best_start = start;
                    *best_end = end;
                }
            }
        }
    }
}

void print_bruteforce_alerts(const FailureEventList *list) {
    size_t i;
    size_t rule_index;
    size_t best_start;
    size_t best_end;
    size_t alert_start;
    size_t alert_end;
    int best_count;
    int alert_count;
    int found = 0;

    printf("\n" COLOR_BOLD COLOR_RED "===== Brute-force Alerts =====" COLOR_RESET "\n");

    if (list->count == 0) {
        printf("No timestamped failed login events found.\n");
        return;
    }

    for (i = 0; i < list->count; i++) {
        if (ip_already_checked(list, i)) {
            continue;
        }

        alert_start = 0;
        alert_end = 0;
        alert_count = 0;

        for (rule_index = 0; rule_index < BRUTEFORCE_RULE_COUNT; rule_index++) {
            find_best_window_for_ip(list,
                                    list->items[i].ip,
                                    BRUTEFORCE_RULES[rule_index].window_seconds,
                                    &best_start,
                                    &best_end,
                                    &best_count);
            if (best_count >= BRUTEFORCE_RULES[rule_index].failure_threshold) {
                alert_start = best_start;
                alert_end = best_end;
                alert_count = best_count;
            }
        }

        if (alert_count > 0) {
            print_bruteforce_alert(list, list->items[i].ip, alert_start, alert_end, alert_count);
            found = 1;
        }
    }

    if (!found) {
        printf("No brute-force patterns found.\n");
    }
}

void print_summary(const Summary *summary) {
    printf("===== SSH Log Analysis Result =====\n");
    printf("Total failed login attempts : " COLOR_RED "%d" COLOR_RESET "\n", summary->total_failed);
    printf("Total successful logins     : " COLOR_GREEN "%d" COLOR_RESET "\n", summary->total_success);
    printf("Root login attempts         : " COLOR_YELLOW "%d" COLOR_RESET "\n", summary->root_attempts);
    printf("sudo command executions     : " COLOR_YELLOW "%d" COLOR_RESET "\n", summary->sudo_commands);
    printf("su command executions       : " COLOR_YELLOW "%d" COLOR_RESET "\n", summary->su_commands);
}

void print_ip_stats(const IpStatsList *list) {
    size_t i;

    printf("\n===== IP Statistics =====\n");
    for (i = 0; i < list->count; i++) {
        printf("IP: %-15s | Country: %-15s | Region: %-15s | Failed: %-3d | Success: %-3d\n",
               list->items[i].ip,
               geo_display_value(list->items[i].country),
               geo_display_value(list->items[i].region),
               list->items[i].failed_count,
               list->items[i].success_count);
    }
}

void print_geo_warnings(const IpStatsList *list) {
    size_t i;
    int found = 0;

    printf("\n" COLOR_BOLD COLOR_YELLOW "===== Geo Location Warnings =====" COLOR_RESET "\n");

    for (i = 0; i < list->count; i++) {
        if (has_geo(&list->items[i])) {
            printf("- %s: country=%s, region=%s\n",
                   list->items[i].ip,
                   geo_display_value(list->items[i].country),
                   geo_display_value(list->items[i].region));
            found = 1;
        }
    }

    if (!found) {
        printf("No country/region information recorded in log.\n");
    }
}

void print_suspicious_ips(const IpStatsList *list, int threshold) {
    size_t i;
    int found = 0;

    printf("\n" COLOR_BOLD COLOR_RED "===== Suspicious IPs (failed >= %d) =====" COLOR_RESET "\n", threshold);

    for (i = 0; i < list->count; i++) {
        if (list->items[i].failed_count >= threshold) {
            printf("- %s (%d failed attempts, country=%s, region=%s)\n",
                   list->items[i].ip,
                   list->items[i].failed_count,
                   geo_display_value(list->items[i].country),
                   geo_display_value(list->items[i].region));
            found = 1;
        }
    }

    if (!found) {
        printf("No suspicious IPs found.\n");
    }
}

void print_top_failed_ips(const IpStatsList *list, int top_n) {
    IpStats *sorted_stats;
    size_t i;
    int rank = 0;

    printf("\n" COLOR_BOLD COLOR_RED "===== Top %d Failed IPs =====" COLOR_RESET "\n", top_n);

    if (list->count == 0) {
        printf("No failed login IPs found.\n");
        return;
    }

    sorted_stats = malloc(list->count * sizeof(IpStats));
    if (sorted_stats == NULL) {
        printf("Failed to allocate memory for ranking.\n");
        return;
    }

    copy_ip_stats(sorted_stats, list->items, list->count);
    sort_by_failed_count_desc(sorted_stats, list->count);

    for (i = 0; i < list->count && rank < top_n; i++) {
        if (sorted_stats[i].failed_count > 0) {
            rank++;
            printf("%d. %s (%d failed attempts, country=%s, region=%s)\n",
                   rank,
                   sorted_stats[i].ip,
                   sorted_stats[i].failed_count,
                   geo_display_value(sorted_stats[i].country),
                   geo_display_value(sorted_stats[i].region));
        }
    }

    if (rank == 0) {
        printf("No failed login IPs found.\n");
    }

    free(sorted_stats);
}

void print_top_successful_ips(const IpStatsList *list, int top_n) {
    IpStats *sorted_stats;
    size_t i;
    int rank = 0;

    printf("\n" COLOR_BOLD COLOR_GREEN "===== Top %d Successful IPs =====" COLOR_RESET "\n", top_n);

    if (list->count == 0) {
        printf("No successful login IPs found.\n");
        return;
    }

    sorted_stats = malloc(list->count * sizeof(IpStats));
    if (sorted_stats == NULL) {
        printf("Failed to allocate memory for ranking.\n");
        return;
    }

    copy_ip_stats(sorted_stats, list->items, list->count);
    sort_by_success_count_desc(sorted_stats, list->count);

    for (i = 0; i < list->count && rank < top_n; i++) {
        if (sorted_stats[i].success_count > 0) {
            rank++;
            printf("%d. %s (%d successful logins, country=%s, region=%s)\n",
                   rank,
                   sorted_stats[i].ip,
                   sorted_stats[i].success_count,
                   geo_display_value(sorted_stats[i].country),
                   geo_display_value(sorted_stats[i].region));
        }
    }

    if (rank == 0) {
        printf("No successful login IPs found.\n");
    }

    free(sorted_stats);
}





void print_user_stats(const UserStatsList *list) {
    size_t i;

    printf("\n===== User Statistics =====\n");
    for (i = 0; i < list->count; i++) {
        printf("User: %-15s | Failed: %-3d | Success: %-3d\n",
               list->items[i].user,
               list->items[i].failed_count,
               list->items[i].success_count);
    }
}





static void copy_user_stats(UserStats *dest, const UserStats *src, size_t count) {
    size_t i;

    for (i = 0; i < count; i++) {
        dest[i] = src[i];
    }
}

static void sort_user_by_failed_count_desc(UserStats stats[], size_t count) {
    size_t i;
    size_t j;
    UserStats temp;

    for (i = 0; i < count; i++) {
        for (j = 0; j + 1 < count - i; j++) {
            if (stats[j].failed_count < stats[j + 1].failed_count) {
                temp = stats[j];
                stats[j] = stats[j + 1];
                stats[j + 1] = temp;
            }
        }
    }
}

static void sort_user_by_success_count_desc(UserStats stats[], size_t count) {
    size_t i;
    size_t j;
    UserStats temp;

    for (i = 0; i < count; i++) {
        for (j = 0; j + 1 < count - i; j++) {
            if (stats[j].success_count < stats[j + 1].success_count) {
                temp = stats[j];
                stats[j] = stats[j + 1];
                stats[j + 1] = temp;
            }
        }
    }
}

void print_top_targeted_users(const UserStatsList *list, int top_n) {
    UserStats *sorted_users;
    size_t i;
    int rank = 0;

    printf("\n" COLOR_BOLD COLOR_RED "===== Top %d Targeted Users =====" COLOR_RESET "\n", top_n);

    if (list->count == 0) {
        printf("No targeted users found.\n");
        return;
    }

    sorted_users = malloc(list->count * sizeof(UserStats));
    if (sorted_users == NULL) {
        printf("Failed to allocate memory for user ranking.\n");
        return;
    }

    copy_user_stats(sorted_users, list->items, list->count);
    sort_user_by_failed_count_desc(sorted_users, list->count);

    for (i = 0; i < list->count && rank < top_n; i++) {
        if (sorted_users[i].failed_count > 0) {
            rank++;
            printf("%d. %s (%d failed attempts)\n",
                   rank,
                   sorted_users[i].user,
                   sorted_users[i].failed_count);
        }
    }

    if (rank == 0) {
        printf("No targeted users found.\n");
    }

    free(sorted_users);
}

void print_top_successful_users(const UserStatsList *list, int top_n) {
    UserStats *sorted_users;
    size_t i;
    int rank = 0;

    printf("\n" COLOR_BOLD COLOR_GREEN "===== Top %d Successful Users =====" COLOR_RESET "\n", top_n);

    if (list->count == 0) {
        printf("No successful login users found.\n");
        return;
    }

    sorted_users = malloc(list->count * sizeof(UserStats));
    if (sorted_users == NULL) {
        printf("Failed to allocate memory for user ranking.\n");
        return;
    }

    copy_user_stats(sorted_users, list->items, list->count);
    sort_user_by_success_count_desc(sorted_users, list->count);

    for (i = 0; i < list->count && rank < top_n; i++) {
        if (sorted_users[i].success_count > 0) {
            rank++;
            printf("%d. %s (%d successful logins)\n",
                   rank,
                   sorted_users[i].user,
                   sorted_users[i].success_count);
        }
    }

    if (rank == 0) {
        printf("No successful login users found.\n");
    }

    free(sorted_users);
}
