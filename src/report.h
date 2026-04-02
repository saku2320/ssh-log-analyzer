#ifndef REPORT_H
#define REPORT_H

#include "analyzer.h"

void print_summary(const Summary *summary);
void print_ip_stats(const IpStatsList *list);
void print_suspicious_ips(const IpStatsList *list, int threshold);
void print_top_failed_ips(const IpStatsList *list, int top_n);

void print_user_stats(const UserStatsList *list);
void print_top_targeted_users(const UserStatsList *list, int top_n);

#endif
