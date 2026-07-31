#ifndef ANALYZER_H
#define ANALYZER_H

#include <stddef.h>
#include "parser.h"

typedef struct {
    int total_failed;
    int total_success;
    int root_attempts;
    int sudo_commands;
    int su_commands;
} Summary;

typedef struct {
    char ip[MAX_IP_LENGTH];
    char country[MAX_GEO_LENGTH];
    char region[MAX_GEO_LENGTH];
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

typedef struct {
    char ip[MAX_IP_LENGTH];
    char user[MAX_USER_LENGTH];
    char time_text[MAX_TIME_LENGTH];
    int timestamp_seconds;
    int is_root;
    int is_invalid_user;
} FailureEvent;

typedef struct {
    FailureEvent *items;
    size_t count;
    size_t capacity;
} FailureEventList;

typedef struct {
    char ip[MAX_IP_LENGTH];
    char user[MAX_USER_LENGTH];
    char timestamp_text[MAX_TIMESTAMP_LENGTH];
    char time_text[MAX_TIME_LENGTH];
    int timestamp_seconds;
} SuccessEvent;

typedef struct {
    SuccessEvent *items;
    size_t count;
    size_t capacity;
} SuccessEventList;

void init_user_stats_list(UserStatsList *list);
void free_user_stats_list(UserStatsList *list);
int update_user_stats(UserStatsList *list, const LogEntry *entry);




void init_summary(Summary *summary);

void init_ip_stats_list(IpStatsList *list);
void free_ip_stats_list(IpStatsList *list);

void update_summary(Summary *summary, const LogEntry *entry);
int update_ip_stats(IpStatsList *list, const LogEntry *entry);

void init_failure_event_list(FailureEventList *list);
void free_failure_event_list(FailureEventList *list);
int update_failure_events(FailureEventList *list, const LogEntry *entry);

void init_success_event_list(SuccessEventList *list);
void free_success_event_list(SuccessEventList *list);
int update_success_events(SuccessEventList *list, const LogEntry *entry);

#endif
