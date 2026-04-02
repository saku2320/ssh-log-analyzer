#ifndef ANALYZER_H
#define ANALYZER_H

#include <stddef.h>
#include "parser.h"

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

typedef struct {
    IpStats *items;
    size_t count;
    size_t capacity;
} IpStatsList;




typedef struct {
    char user[MAX_USER_LENGTH];
    int failed_count;
    int success_count;
} UserStats;

typedef struct {
    UserStats *items;
    size_t count;
    size_t capacity;
} UserStatsList;

void init_user_stats_list(UserStatsList *list);
void free_user_stats_list(UserStatsList *list);
int update_user_stats(UserStatsList *list, const LogEntry *entry);




void init_summary(Summary *summary);

void init_ip_stats_list(IpStatsList *list);
void free_ip_stats_list(IpStatsList *list);

void update_summary(Summary *summary, const LogEntry *entry);
int update_ip_stats(IpStatsList *list, const LogEntry *entry);

#endif
