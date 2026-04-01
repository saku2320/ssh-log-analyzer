#include <stdio.h>
#include <string.h>
#include "analyzer.h"

void init_summary(Summary *summary) {
    summary->total_failed = 0;
    summary->total_success = 0;
    summary->root_attempts = 0;
}

void init_ip_stats(IpStats stats[], int size) {
    int i;

    for (i = 0; i < size; i++) {
        stats[i].ip[0] = '\0';
        stats[i].failed_count = 0;
        stats[i].success_count = 0;
    }
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

void update_ip_stats(IpStats stats[], int size, const LogEntry *entry) {
    int i;
    int empty_index = -1;

    if (entry->ip[0] == '\0') {
        return;
    }

    for (i = 0; i < size; i++) {
        if (strcmp(stats[i].ip, entry->ip) == 0) {
            if (entry->is_failed) {
                stats[i].failed_count++;
            }
            if (entry->is_success) {
                stats[i].success_count++;
            }
            return;
        }

        if (empty_index == -1 && stats[i].ip[0] == '\0') {
            empty_index = i;
        }
    }

    if (empty_index != -1) {
        strncpy(stats[empty_index].ip, entry->ip, MAX_IP_LENGTH - 1);
        stats[empty_index].ip[MAX_IP_LENGTH - 1] = '\0';

        if (entry->is_failed) {
            stats[empty_index].failed_count = 1;
        }

        if (entry->is_success) {
            stats[empty_index].success_count = 1;
        }
    }
}
