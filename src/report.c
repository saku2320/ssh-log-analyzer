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
        printf("IP: %-15s | Failed: %-3d | Success: %-3d\n",
               list->items[i].ip,
               list->items[i].failed_count,
               list->items[i].success_count);
    }
}

void print_suspicious_ips(const IpStatsList *list, int threshold) {
    size_t i;
    int found = 0;

    printf("\n" COLOR_BOLD COLOR_RED "===== Suspicious IPs (failed >= %d) =====" COLOR_RESET "\n", threshold);

    for (i = 0; i < list->count; i++) {
        if (list->items[i].failed_count >= threshold) {
            printf("- %s (%d failed attempts)\n",
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
            printf("%d. %s (%d failed attempts)\n",
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
            printf("%d. %s (%d successful logins)\n",
                   rank,
                   sorted_stats[i].ip,
                   sorted_stats[i].success_count);
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
