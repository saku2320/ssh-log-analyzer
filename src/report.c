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
#define CRITICAL_FAILURE_THRESHOLD 10
#define CRITICAL_SUCCESS_WINDOW_SECONDS 1800
#define PASSWORD_SPRAY_UNIQUE_USER_THRESHOLD 10

static OutputLanguage report_language = OUTPUT_EN;

void set_report_language(OutputLanguage language) {
    report_language = language;
}

static int is_ja(void) {
    return report_language == OUTPUT_JA;
}

static const char *not_recorded_text(void) {
    return is_ja() ? "(記録なし)" : "(not recorded)";
}

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
        return not_recorded_text();
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

static void print_bruteforce_alert(const char *ip, const char *user, int failures) {
    printf(COLOR_BOLD COLOR_RED "[ALERT] %s" COLOR_RESET "\n",
           is_ja() ? "SSHブルートフォース攻撃の疑い" : "SSH brute-force suspected");
    printf("%s: %s\n", is_ja() ? "IP" : "IP", ip);
    printf("%s: %s\n", is_ja() ? "ユーザー" : "User", user);
    printf("%s: %d\n", is_ja() ? "失敗回数" : "Failures", failures);
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

static int ip_user_already_checked(const FailureEventList *list, size_t current) {
    size_t i;

    for (i = 0; i < current; i++) {
        if (strcmp(list->items[i].ip, list->items[current].ip) == 0 &&
            strcmp(list->items[i].user, list->items[current].user) == 0) {
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

static void find_best_window_for_ip_user(const FailureEventList *list,
                                         const char *ip,
                                         const char *user,
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
        if (strcmp(list->items[start].ip, ip) != 0 ||
            strcmp(list->items[start].user, user) != 0) {
            continue;
        }

        count = 0;
        for (end = start; end < list->count; end++) {
            if (list->items[end].timestamp_seconds - list->items[start].timestamp_seconds > window_seconds) {
                break;
            }

            if (strcmp(list->items[end].ip, ip) == 0 &&
                strcmp(list->items[end].user, user) == 0) {
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

static void find_best_spray_window_for_ip(const FailureEventList *list,
                                          const char *ip,
                                          int window_seconds,
                                          size_t *best_start,
                                          size_t *best_end,
                                          int *best_failures,
                                          int *best_unique_users) {
    size_t start;
    size_t end;
    const char *users[256];
    size_t user_count;
    int failures;

    *best_start = 0;
    *best_end = 0;
    *best_failures = 0;
    *best_unique_users = 0;

    for (start = 0; start < list->count; start++) {
        if (strcmp(list->items[start].ip, ip) != 0) {
            continue;
        }

        failures = 0;
        user_count = 0;
        for (end = start; end < list->count; end++) {
            if (list->items[end].timestamp_seconds - list->items[start].timestamp_seconds > window_seconds) {
                break;
            }

            if (strcmp(list->items[end].ip, ip) == 0) {
                failures++;
                if (list->items[end].user[0] != '\0' &&
                    user_count < 256 &&
                    !user_is_listed(users, user_count, list->items[end].user)) {
                    users[user_count] = list->items[end].user;
                    user_count++;
                }
                if ((int)user_count > *best_unique_users ||
                    ((int)user_count == *best_unique_users && failures > *best_failures)) {
                    *best_unique_users = (int)user_count;
                    *best_failures = failures;
                    *best_start = start;
                    *best_end = end;
                }
            }
        }
    }
}

static void print_average_failures_per_user(double average_failures) {
    int average_as_int = (int)average_failures;

    if (average_failures == average_as_int) {
        printf("%d", average_as_int);
    } else {
        printf("%.2f", average_failures);
    }
}

void print_bruteforce_alerts(const FailureEventList *list) {
    size_t i;
    size_t rule_index;
    size_t best_start;
    size_t best_end;
    int best_count;
    int alert_count;
    int found = 0;

    printf("\n" COLOR_BOLD COLOR_RED "===== %s =====" COLOR_RESET "\n",
           is_ja() ? "ブルートフォース警告" : "Brute-force Alerts");

    if (list->count == 0) {
        printf("%s\n", is_ja() ? "時刻付きの失敗ログは見つかりませんでした。" : "No timestamped failed login events found.");
        return;
    }

    for (i = 0; i < list->count; i++) {
        if (list->items[i].user[0] == '\0' || ip_user_already_checked(list, i)) {
            continue;
        }

        alert_count = 0;

        for (rule_index = 0; rule_index < BRUTEFORCE_RULE_COUNT; rule_index++) {
            find_best_window_for_ip_user(list,
                                         list->items[i].ip,
                                         list->items[i].user,
                                         BRUTEFORCE_RULES[rule_index].window_seconds,
                                         &best_start,
                                         &best_end,
                                         &best_count);
            if (best_count >= BRUTEFORCE_RULES[rule_index].failure_threshold) {
                alert_count = best_count;
            }
        }

        if (alert_count > 0) {
            print_bruteforce_alert(list->items[i].ip, list->items[i].user, alert_count);
            found = 1;
        }
    }

    if (!found) {
        printf("%s\n", is_ja() ? "ブルートフォース攻撃のパターンは見つかりませんでした。" : "No brute-force patterns found.");
    }
}

void print_password_spraying_alerts(const FailureEventList *list) {
    size_t i;
    size_t rule_index;
    size_t best_start;
    size_t best_end;
    int best_failures;
    int best_unique_users;
    int alert_failures;
    int alert_unique_users;
    int found = 0;
    double average_failures;

    printf("\n" COLOR_BOLD COLOR_RED "===== %s =====" COLOR_RESET "\n",
           is_ja() ? "パスワードスプレー警告" : "Password Spraying Alerts");

    if (list->count == 0) {
        printf("%s\n", is_ja() ? "時刻付きの失敗ログは見つかりませんでした。" : "No timestamped failed login events found.");
        return;
    }

    for (i = 0; i < list->count; i++) {
        if (ip_already_checked(list, i)) {
            continue;
        }

        alert_failures = 0;
        alert_unique_users = 0;

        for (rule_index = 0; rule_index < BRUTEFORCE_RULE_COUNT; rule_index++) {
            find_best_spray_window_for_ip(list,
                                          list->items[i].ip,
                                          BRUTEFORCE_RULES[rule_index].window_seconds,
                                          &best_start,
                                          &best_end,
                                          &best_failures,
                                          &best_unique_users);
            if (best_unique_users >= PASSWORD_SPRAY_UNIQUE_USER_THRESHOLD) {
                alert_failures = best_failures;
                alert_unique_users = best_unique_users;
            }
        }

        if (alert_unique_users > 0) {
            average_failures = (double)alert_failures / alert_unique_users;
            printf(COLOR_BOLD COLOR_RED "[ALERT] %s" COLOR_RESET "\n",
                   is_ja() ? "SSHパスワードスプレー攻撃の疑い" : "SSH password spraying suspected");
            printf("%s: %s\n", is_ja() ? "IP" : "IP", list->items[i].ip);
            printf("%s: %d\n", is_ja() ? "失敗回数" : "Failures", alert_failures);
            printf("%s: %d\n", is_ja() ? "ユニークユーザー数" : "Unique Users", alert_unique_users);
            printf("%s: ", is_ja() ? "ユーザーあたり平均失敗回数" : "Average failures per user");
            print_average_failures_per_user(average_failures);
            printf("\n\n");
            found = 1;
        }
    }

    if (!found) {
        printf("%s\n", is_ja() ? "パスワードスプレー攻撃のパターンは見つかりませんでした。" : "No password spraying patterns found.");
    }
}

static int count_failures_before_success(const FailureEventList *failures, const SuccessEvent *success) {
    size_t i;
    int count = 0;
    int elapsed;

    for (i = 0; i < failures->count; i++) {
        if (strcmp(failures->items[i].ip, success->ip) != 0 ||
            strcmp(failures->items[i].user, success->user) != 0) {
            continue;
        }

        elapsed = success->timestamp_seconds - failures->items[i].timestamp_seconds;
        if (elapsed >= 0 && elapsed <= CRITICAL_SUCCESS_WINDOW_SECONDS) {
            count++;
        }
    }

    return count;
}

void print_post_failure_success_alerts(const FailureEventList *failures, const SuccessEventList *successes) {
    size_t i;
    int failed_count;
    int found = 0;

    printf("\n" COLOR_BOLD COLOR_RED "===== %s =====" COLOR_RESET "\n",
           is_ja() ? "失敗後ログイン成功警告" : "Post-failure Login Success Alerts");

    if (failures->count == 0 || successes->count == 0) {
        printf("%s\n", is_ja() ? "時刻付きの失敗ログと成功ログの組み合わせは見つかりませんでした。" : "No timestamped failure/success pairs found.");
        return;
    }

    for (i = 0; i < successes->count; i++) {
        failed_count = count_failures_before_success(failures, &successes->items[i]);
        if (failed_count >= CRITICAL_FAILURE_THRESHOLD) {
            printf(COLOR_BOLD COLOR_RED "[CRITICAL] %s" COLOR_RESET "\n",
                   is_ja() ? "繰り返し失敗後にログイン成功" : "Login succeeded after repeated failures");
            printf("%s    : %s\n", is_ja() ? "IPアドレス" : "IP Address", successes->items[i].ip);
            printf("%s          : %s\n", is_ja() ? "ユーザー" : "User", successes->items[i].user);
            printf("%s  : %d\n", is_ja() ? "失敗回数" : "Failed Count", failed_count);
            printf("%s  : %s\n\n", is_ja() ? "成功時刻" : "Success Time", successes->items[i].timestamp_text);
            found = 1;
        }
    }

    if (!found) {
        printf("%s\n", is_ja() ? "繰り返し失敗後のログイン成功は見つかりませんでした。" : "No successful logins after repeated failures found.");
    }
}

static const char *risk_level(int score) {
    if (score >= 90) {
        return "CRITICAL";
    }

    if (score >= 60) {
        return "HIGH";
    }

    if (score >= 30) {
        return "MEDIUM";
    }

    return "LOW";
}

static int ip_has_root_target(const FailureEventList *failures, const char *ip) {
    size_t i;

    for (i = 0; i < failures->count; i++) {
        if (strcmp(failures->items[i].ip, ip) == 0 && failures->items[i].is_root) {
            return 1;
        }
    }

    return 0;
}

static int ip_has_invalid_user_target(const FailureEventList *failures, const char *ip) {
    size_t i;

    for (i = 0; i < failures->count; i++) {
        if (strcmp(failures->items[i].ip, ip) == 0 && failures->items[i].is_invalid_user) {
            return 1;
        }
    }

    return 0;
}

static int count_unique_users_for_ip(const FailureEventList *failures, const char *ip) {
    const char *users[256];
    size_t user_count = 0;
    size_t i;

    for (i = 0; i < failures->count; i++) {
        if (strcmp(failures->items[i].ip, ip) != 0 || failures->items[i].user[0] == '\0') {
            continue;
        }

        if (user_count < 256 && !user_is_listed(users, user_count, failures->items[i].user)) {
            users[user_count] = failures->items[i].user;
            user_count++;
        }
    }

    return (int)user_count;
}

static int ip_has_success_after_failures(const FailureEventList *failures,
                                         const SuccessEventList *successes,
                                         const char *ip) {
    size_t i;

    for (i = 0; i < successes->count; i++) {
        if (strcmp(successes->items[i].ip, ip) != 0) {
            continue;
        }

        if (count_failures_before_success(failures, &successes->items[i]) >= CRITICAL_FAILURE_THRESHOLD) {
            return 1;
        }
    }

    return 0;
}

static int five_min_failure_score(int failures) {
    if (failures >= 250) {
        return 50;
    }

    if (failures >= 100) {
        return 40;
    }

    if (failures >= 50) {
        return 30;
    }

    if (failures >= 10) {
        return 20;
    }

    return 0;
}

static void print_risk_reasons(int best_five_min_failures,
                               int five_min_score,
                               int has_root,
                               int has_invalid_user,
                               int unique_users,
                               int has_post_failure_success) {
    printf("%s:\n", is_ja() ? "理由" : "Reasons");
    if (five_min_score > 0) {
        printf(is_ja() ? "- 5分以内に%d回ログイン失敗 (+%d)\n" : "- %d failed logins within 5 minutes (+%d)\n",
               best_five_min_failures,
               five_min_score);
    }
    if (has_root) {
        printf("%s\n", is_ja() ? "- rootアカウントが狙われました" : "- Root account targeted");
    }
    if (has_invalid_user) {
        printf("%s\n", is_ja() ? "- 存在しないユーザーへの試行を検出" : "- Invalid user login attempts detected");
    }
    if (unique_users >= 10) {
        printf(is_ja() ? "- %d人の異なるユーザーが狙われました\n" : "- %d different users targeted\n", unique_users);
    }
    if (has_post_failure_success) {
        printf("%s\n", is_ja() ? "- 繰り返し失敗後にログイン成功" : "- Successful login after repeated failures");
    }
}

void print_risk_assessment(const FailureEventList *failures, const SuccessEventList *successes) {
    size_t i;
    size_t best_start;
    size_t best_end;
    int best_count;
    int has_root;
    int has_invalid_user;
    int unique_users;
    int has_post_failure_success;
    int five_min_score;
    int score;
    int found = 0;

    printf("\n" COLOR_BOLD COLOR_RED "===== %s =====" COLOR_RESET "\n",
           is_ja() ? "Risk Assessment (HIGH/CRITICAL)" : "Risk Assessment (HIGH/CRITICAL)");

    if (failures->count == 0) {
        printf("%s\n", is_ja() ? "危険度スコア算出対象の失敗ログは見つかりませんでした。" : "No failed login events found for risk scoring.");
        return;
    }

    for (i = 0; i < failures->count; i++) {
        if (ip_already_checked(failures, i)) {
            continue;
        }

        find_best_window_for_ip(failures, failures->items[i].ip, 300, &best_start, &best_end, &best_count);
        (void)best_start;
        (void)best_end;

        has_root = ip_has_root_target(failures, failures->items[i].ip);
        has_invalid_user = ip_has_invalid_user_target(failures, failures->items[i].ip);
        unique_users = count_unique_users_for_ip(failures, failures->items[i].ip);
        has_post_failure_success = ip_has_success_after_failures(failures, successes, failures->items[i].ip);

        five_min_score = five_min_failure_score(best_count);
        score = five_min_score;
        if (has_root) {
            score += 20;
        }
        if (has_invalid_user) {
            score += 10;
        }
        if (unique_users >= 10) {
            score += 20;
        }
        if (has_post_failure_success) {
            score += 50;
        }

        if (score >= 60) {
            printf("%s : %s\n", is_ja() ? "Risk Level" : "Risk Level", risk_level(score));
            printf("%s : %d\n", is_ja() ? "Risk Score" : "Risk Score", score);
            printf("%s : %s\n", is_ja() ? "IPアドレス" : "IP Address", failures->items[i].ip);
            print_risk_reasons(best_count,
                               five_min_score,
                               has_root,
                               has_invalid_user,
                               unique_users,
                               has_post_failure_success);
            printf("\n");
            found = 1;
        }
    }

    if (!found) {
        printf("%s\n", is_ja() ? "HIGHまたはCRITICALの危険度は見つかりませんでした。" : "No HIGH or CRITICAL risks found.");
    }
}

void print_summary(const Summary *summary) {
    printf("===== %s =====\n", is_ja() ? "SSHログ分析結果" : "SSH Log Analysis Result");
    printf("%s : " COLOR_RED "%d" COLOR_RESET "\n", is_ja() ? "ログイン失敗合計" : "Total failed login attempts", summary->total_failed);
    printf("%s     : " COLOR_GREEN "%d" COLOR_RESET "\n", is_ja() ? "ログイン成功合計" : "Total successful logins", summary->total_success);
    printf("%s         : " COLOR_YELLOW "%d" COLOR_RESET "\n", is_ja() ? "rootログイン試行" : "Root login attempts", summary->root_attempts);
    printf("%s     : " COLOR_YELLOW "%d" COLOR_RESET "\n", is_ja() ? "sudoコマンド実行" : "sudo command executions", summary->sudo_commands);
    printf("%s       : " COLOR_YELLOW "%d" COLOR_RESET "\n", is_ja() ? "suコマンド実行" : "su command executions", summary->su_commands);
}

void print_ip_stats(const IpStatsList *list) {
    size_t i;

    printf("\n===== %s =====\n", is_ja() ? "IP統計" : "IP Statistics");
    for (i = 0; i < list->count; i++) {
        printf("%s: %-15s | %s: %-15s | %s: %-15s | %s: %-3d | %s: %-3d\n",
               is_ja() ? "IP" : "IP",
               list->items[i].ip,
               is_ja() ? "国" : "Country",
               geo_display_value(list->items[i].country),
               is_ja() ? "地域" : "Region",
               geo_display_value(list->items[i].region),
               is_ja() ? "失敗" : "Failed",
               list->items[i].failed_count,
               is_ja() ? "成功" : "Success",
               list->items[i].success_count);
    }
}

void print_geo_warnings(const IpStatsList *list) {
    size_t i;
    int found = 0;

    printf("\n" COLOR_BOLD COLOR_YELLOW "===== %s =====" COLOR_RESET "\n",
           is_ja() ? "国・地域警告" : "Geo Location Warnings");

    for (i = 0; i < list->count; i++) {
        if (has_geo(&list->items[i])) {
            printf(is_ja() ? "- %s: 国=%s, 地域=%s\n" : "- %s: country=%s, region=%s\n",
                   list->items[i].ip,
                   geo_display_value(list->items[i].country),
                   geo_display_value(list->items[i].region));
            found = 1;
        }
    }

    if (!found) {
        printf("%s\n", is_ja() ? "ログに国・地域情報は記録されていません。" : "No country/region information recorded in log.");
    }
}

void print_suspicious_ips(const IpStatsList *list, int threshold) {
    size_t i;
    int found = 0;

    printf("\n" COLOR_BOLD COLOR_RED "===== ");
    printf(is_ja() ? "不審IP (失敗 >= %d)" : "Suspicious IPs (failed >= %d)", threshold);
    printf(" =====" COLOR_RESET "\n");

    for (i = 0; i < list->count; i++) {
        if (list->items[i].failed_count >= threshold) {
            printf(is_ja() ? "- %s (%d回失敗, 国=%s, 地域=%s)\n" : "- %s (%d failed attempts, country=%s, region=%s)\n",
                   list->items[i].ip,
                   list->items[i].failed_count,
                   geo_display_value(list->items[i].country),
                   geo_display_value(list->items[i].region));
            found = 1;
        }
    }

    if (!found) {
        printf("%s\n", is_ja() ? "不審IPは見つかりませんでした。" : "No suspicious IPs found.");
    }
}

void print_top_failed_ips(const IpStatsList *list, int top_n) {
    IpStats *sorted_stats;
    size_t i;
    int rank = 0;

    printf("\n" COLOR_BOLD COLOR_RED "===== ");
    printf(is_ja() ? "失敗IP Top %d" : "Top %d Failed IPs", top_n);
    printf(" =====" COLOR_RESET "\n");

    if (list->count == 0) {
        printf("%s\n", is_ja() ? "失敗ログのIPは見つかりませんでした。" : "No failed login IPs found.");
        return;
    }

    sorted_stats = malloc(list->count * sizeof(IpStats));
    if (sorted_stats == NULL) {
        printf("%s\n", is_ja() ? "ランキング用メモリの確保に失敗しました。" : "Failed to allocate memory for ranking.");
        return;
    }

    copy_ip_stats(sorted_stats, list->items, list->count);
    sort_by_failed_count_desc(sorted_stats, list->count);

    for (i = 0; i < list->count && rank < top_n; i++) {
        if (sorted_stats[i].failed_count > 0) {
            rank++;
            printf(is_ja() ? "%d. %s (%d回失敗, 国=%s, 地域=%s)\n" : "%d. %s (%d failed attempts, country=%s, region=%s)\n",
                   rank,
                   sorted_stats[i].ip,
                   sorted_stats[i].failed_count,
                   geo_display_value(sorted_stats[i].country),
                   geo_display_value(sorted_stats[i].region));
        }
    }

    if (rank == 0) {
        printf("%s\n", is_ja() ? "失敗ログのIPは見つかりませんでした。" : "No failed login IPs found.");
    }

    free(sorted_stats);
}

void print_top_successful_ips(const IpStatsList *list, int top_n) {
    IpStats *sorted_stats;
    size_t i;
    int rank = 0;

    printf("\n" COLOR_BOLD COLOR_GREEN "===== ");
    printf(is_ja() ? "成功IP Top %d" : "Top %d Successful IPs", top_n);
    printf(" =====" COLOR_RESET "\n");

    if (list->count == 0) {
        printf("%s\n", is_ja() ? "成功ログのIPは見つかりませんでした。" : "No successful login IPs found.");
        return;
    }

    sorted_stats = malloc(list->count * sizeof(IpStats));
    if (sorted_stats == NULL) {
        printf("%s\n", is_ja() ? "ランキング用メモリの確保に失敗しました。" : "Failed to allocate memory for ranking.");
        return;
    }

    copy_ip_stats(sorted_stats, list->items, list->count);
    sort_by_success_count_desc(sorted_stats, list->count);

    for (i = 0; i < list->count && rank < top_n; i++) {
        if (sorted_stats[i].success_count > 0) {
            rank++;
            printf(is_ja() ? "%d. %s (%d回成功, 国=%s, 地域=%s)\n" : "%d. %s (%d successful logins, country=%s, region=%s)\n",
                   rank,
                   sorted_stats[i].ip,
                   sorted_stats[i].success_count,
                   geo_display_value(sorted_stats[i].country),
                   geo_display_value(sorted_stats[i].region));
        }
    }

    if (rank == 0) {
        printf("%s\n", is_ja() ? "成功ログのIPは見つかりませんでした。" : "No successful login IPs found.");
    }

    free(sorted_stats);
}





void print_user_stats(const UserStatsList *list) {
    size_t i;

    printf("\n===== %s =====\n", is_ja() ? "ユーザー統計" : "User Statistics");
    for (i = 0; i < list->count; i++) {
        printf("%s: %-15s | %s: %-3d | %s: %-3d\n",
               is_ja() ? "ユーザー" : "User",
               list->items[i].user,
               is_ja() ? "失敗" : "Failed",
               list->items[i].failed_count,
               is_ja() ? "成功" : "Success",
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

    printf("\n" COLOR_BOLD COLOR_RED "===== ");
    printf(is_ja() ? "狙われたユーザー Top %d" : "Top %d Targeted Users", top_n);
    printf(" =====" COLOR_RESET "\n");

    if (list->count == 0) {
        printf("%s\n", is_ja() ? "狙われたユーザーは見つかりませんでした。" : "No targeted users found.");
        return;
    }

    sorted_users = malloc(list->count * sizeof(UserStats));
    if (sorted_users == NULL) {
        printf("%s\n", is_ja() ? "ユーザーランキング用メモリの確保に失敗しました。" : "Failed to allocate memory for user ranking.");
        return;
    }

    copy_user_stats(sorted_users, list->items, list->count);
    sort_user_by_failed_count_desc(sorted_users, list->count);

    for (i = 0; i < list->count && rank < top_n; i++) {
        if (sorted_users[i].failed_count > 0) {
            rank++;
            printf(is_ja() ? "%d. %s (%d回失敗)\n" : "%d. %s (%d failed attempts)\n",
                   rank,
                   sorted_users[i].user,
                   sorted_users[i].failed_count);
        }
    }

    if (rank == 0) {
        printf("%s\n", is_ja() ? "狙われたユーザーは見つかりませんでした。" : "No targeted users found.");
    }

    free(sorted_users);
}

void print_top_successful_users(const UserStatsList *list, int top_n) {
    UserStats *sorted_users;
    size_t i;
    int rank = 0;

    printf("\n" COLOR_BOLD COLOR_GREEN "===== ");
    printf(is_ja() ? "成功ユーザー Top %d" : "Top %d Successful Users", top_n);
    printf(" =====" COLOR_RESET "\n");

    if (list->count == 0) {
        printf("%s\n", is_ja() ? "成功ログのユーザーは見つかりませんでした。" : "No successful login users found.");
        return;
    }

    sorted_users = malloc(list->count * sizeof(UserStats));
    if (sorted_users == NULL) {
        printf("%s\n", is_ja() ? "ユーザーランキング用メモリの確保に失敗しました。" : "Failed to allocate memory for user ranking.");
        return;
    }

    copy_user_stats(sorted_users, list->items, list->count);
    sort_user_by_success_count_desc(sorted_users, list->count);

    for (i = 0; i < list->count && rank < top_n; i++) {
        if (sorted_users[i].success_count > 0) {
            rank++;
            printf(is_ja() ? "%d. %s (%d回成功)\n" : "%d. %s (%d successful logins)\n",
                   rank,
                   sorted_users[i].user,
                   sorted_users[i].success_count);
        }
    }

    if (rank == 0) {
        printf("%s\n", is_ja() ? "成功ログのユーザーは見つかりませんでした。" : "No successful login users found.");
    }

    free(sorted_users);
}
