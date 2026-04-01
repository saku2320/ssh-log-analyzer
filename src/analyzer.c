#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "analyzer.h"

#define INITIAL_IP_CAPACITY 16

void init_summary(Summary *summary) {
    summary->total_failed = 0;
    summary->total_success = 0;
    summary->root_attempts = 0;
}

void init_ip_stats_list(IpStatsList *list) {
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

void free_ip_stats_list(IpStatsList *list) {
    free(list->items);
    list->items = NULL;
    list->count = 0;
    list->capacity = 0;
}

static int ensure_capacity(IpStatsList *list) {
    IpStats *new_items;
    size_t new_capacity;

    if (list->count < list->capacity) {
        return 1;
    }

    if (list->capacity == 0) {
        new_capacity = INITIAL_IP_CAPACITY;
    } else {
        new_capacity = list->capacity * 2;
    }

    new_items = realloc(list->items, new_capacity * sizeof(IpStats));
    if (new_items == NULL) {
        return 0;
    }

    list->items = new_items;
    list->capacity = new_capacity;
    return 1;
}

void update_summary(Summary *summary, const LogEntry *entry) {
    if (entry->is_failed) {
        summary->total_failed++;
    }

    if (entry->is_success) {
        summary->total_success++;
    }

    if (entry->is_root) {
        summary->root_attempts++;
    }
}

int update_ip_stats(IpStatsList *list, const LogEntry *entry) {
    size_t i;

    if (entry->ip[0] == '\0') {
        return 1;
    }

    for (i = 0; i < list->count; i++) {
        if (strcmp(list->items[i].ip, entry->ip) == 0) {
            if (entry->is_failed) {
                list->items[i].failed_count++;
            }
            if (entry->is_success) {
                list->items[i].success_count++;
            }
            return 1;
        }
    }

    if (!ensure_capacity(list)) {
        return 0;
    }

    strncpy(list->items[list->count].ip, entry->ip, MAX_IP_LENGTH - 1);
    list->items[list->count].ip[MAX_IP_LENGTH - 1] = '\0';
    list->items[list->count].failed_count = entry->is_failed ? 1 : 0;
    list->items[list->count].success_count = entry->is_success ? 1 : 0;
    list->count++;

    return 1;
}
