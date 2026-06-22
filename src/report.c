#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "report.h"

#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_BOLD "\033[1m"
#define COLOR_RESET "\033[0m"

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

void print_summary(const Summary *summary) {
    printf("===== SSH Log Analysis Result =====\n");
    printf("Total failed login attempts : " COLOR_RED "%d" COLOR_RESET "\n", summary->total_failed);
    printf("Total successful logins     : " COLOR_GREEN "%d" COLOR_RESET "\n", summary->total_success);
    printf("Root login attempts         : " COLOR_YELLOW "%d" COLOR_RESET "\n", summary->root_attempts);
}

void print_ip_stats(const IpStatsList *list) {
    size_t i;

    printf("\n===== IP Statistics =====\n");
    for (i = 0; i < list->count; i++) {
        if (list->items[i].failed_count > 0) {
            printf("IP: " COLOR_RED "%-15s" COLOR_RESET " | Failed: " COLOR_RED "%-3d" COLOR_RESET " | Success: " COLOR_GREEN "%-3d" COLOR_RESET "\n",
                   list->items[i].ip,
                   list->items[i].failed_count,
                   list->items[i].success_count);
        } else {
            printf("IP: %-15s | Failed: %-3d | Success: " COLOR_GREEN "%-3d" COLOR_RESET "\n",
                   list->items[i].ip,
                   list->items[i].failed_count,
                   list->items[i].success_count);
        }
    }
}

void print_suspicious_ips(const IpStatsList *list, int threshold) {
    size_t i;
    int found = 0;

    printf("\n===== Suspicious IPs (failed >= %d) =====\n", threshold);

    for (i = 0; i < list->count; i++) {
        if (list->items[i].failed_count >= threshold) {
            printf(COLOR_BOLD COLOR_RED "- %s (%d failed attempts)" COLOR_RESET "\n",
                   list->items[i].ip,
                   list->items[i].failed_count);
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

    printf("\n===== Top %d Failed IPs =====\n", top_n);

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
            printf(COLOR_RED "%d. %s (%d failed attempts)" COLOR_RESET "\n",
                   rank,
                   sorted_stats[i].ip,
                   sorted_stats[i].failed_count);
        }
    }

    if (rank == 0) {
        printf("No failed login IPs found.\n");
    }

    free(sorted_stats);
}





void print_user_stats(const UserStatsList *list) {
    size_t i;

    printf("\n===== User Statistics =====\n");
    for (i = 0; i < list->count; i++) {
        if (list->items[i].failed_count > 0) {
            printf("User: " COLOR_RED "%-15s" COLOR_RESET " | Failed: " COLOR_RED "%-3d" COLOR_RESET " | Success: " COLOR_GREEN "%-3d" COLOR_RESET "\n",
                   list->items[i].user,
                   list->items[i].failed_count,
                   list->items[i].success_count);
        } else {
            printf("User: %-15s | Failed: %-3d | Success: " COLOR_GREEN "%-3d" COLOR_RESET "\n",
                   list->items[i].user,
                   list->items[i].failed_count,
                   list->items[i].success_count);
        }
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

void print_top_targeted_users(const UserStatsList *list, int top_n) {
    UserStats *sorted_users;
    size_t i;
    int rank = 0;

    printf("\n===== Top %d Targeted Users =====\n", top_n);

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
            printf(COLOR_RED "%d. %s (%d failed attempts)" COLOR_RESET "\n",
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
