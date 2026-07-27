#ifndef REPORT_H
#define REPORT_H

#include "analyzer.h"

typedef enum {
    OUTPUT_EN,
    OUTPUT_JA
} OutputLanguage;

void set_report_language(OutputLanguage language);

void print_summary(const Summary *summary);
void print_ip_stats(const IpStatsList *list);
void print_suspicious_ips(const IpStatsList *list, int threshold);
void print_top_failed_ips(const IpStatsList *list, int top_n);
void print_top_successful_ips(const IpStatsList *list, int top_n);
void print_geo_warnings(const IpStatsList *list);
void print_bruteforce_alerts(const FailureEventList *list);
void print_post_failure_success_alerts(const FailureEventList *failures, const SuccessEventList *successes);
void print_risk_assessment(const FailureEventList *failures, const SuccessEventList *successes);

void print_user_stats(const UserStatsList *list);
void print_top_targeted_users(const UserStatsList *list, int top_n);
void print_top_successful_users(const UserStatsList *list, int top_n);

#endif
