#ifndef ANALYZER_H
#define ANALYZER_H

#include "parser.h"

#define MAX_IP_STATS 1000

typedef struct {
    int total_failed;
    int total_success;
    int root_attempts;
} Summary;

typedef struct {
    char ip[MAX_IP_LENGTH];
    int failed_count;
    int success_count;
} IpStats;

void init_summary(Summary *summary);
void init_ip_stats(IpStats stats[], int size);
void update_summary(Summary *summary, const LogEntry *entry);
void update_ip_stats(IpStats stats[], int size, const LogEntry *entry);

#endif
