// Self-contained test runner (no framework dependency).
#include <httplib/httplib.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdio>
#include <fstream>
#include <functional>
#include <memory>
#include <random>
#include <sstream>
#include <thread>

#include "loginguard/analysis.hpp"
#include "loginguard/api.hpp"
#include "loginguard/cidr_trie.hpp"
#include "loginguard/config.hpp"
#include "loginguard/detector.hpp"
#include "loginguard/scorer.hpp"
#include "loginguard/dsu.hpp"
#include "loginguard/evaluate.hpp"
#include "loginguard/loggen.hpp"
#include "loginguard/parser.hpp"
#include "loginguard/sliding_window.hpp"
#include "loginguard/storage.hpp"
#include "loginguard/topk.hpp"
#include "loginguard/util.hpp"

using namespace lg;
using json = nlohmann::json;

// ------------------------------------------------------------------ mini framework
struct TestCase {
    const char* name;
    std::function<void()> fn;
};
static std::vector<TestCase>& registry() {
    static std::vector<TestCase> r;
    return r;
}
static int g_failures = 0;
static int g_checks = 0;
struct Registrar {
    Registrar(const char* n, std::function<void()> f) { registry().push_back({n, std::move(f)}); }
};
#define TEST(name)                                  \
    static void test_##name();                      \
    static Registrar reg_##name(#name, test_##name); \
    static void test_##name()
#define CHECK(cond)                                                                         \
    do {                                                                                    \
        ++g_checks;                                                                         \
        if (!(cond)) {                                                                      \
            ++g_failures;                                                                   \
            std::printf("    FAIL %s:%d  %s\n", __FILE__, __LINE__, #cond);                 \
        }                                                                                   \
    } while (0)
#define CHECK_EQ(a, b)                                                                      \
    do {                                                                                    \
        ++g_checks;                                                                         \
        auto va = (a);                                                                      \
        auto vb = (b);                                                                      \
        if (!(va == vb)) {                                                                  \
            ++g_failures;                                                                   \
            std::ostringstream o;                                                           \
            o << va << " != " << vb;                                                        \
            std::printf("    FAIL %s:%d  %s == %s  (%s)\n", __FILE__, __LINE__, #a, #b, o.str().c_str()); \
        }                                                                                   \
    } while (0)

// ------------------------------------------------------------------ helpers
static int64_t T(const char* s) {
    int64_t v = 0;
    parseTimestamp(s, v);
    return v;
}
static const int64_t T0 = T("2026-10-05 10:00:00");  // a Monday, inside business hours

static LoginEvent ev(int64_t ts, const char* user, const char* ip, bool ok) {
    LoginEvent e;
    e.ts = ts;
    e.user = user;
    e.ip = ip;
    e.success = ok;
    e.hasIp4 = parseIpv4(ip, e.ip4);
    return e;
}
static std::vector<Alert> analyze(std::vector<LoginEvent> events, const Config& cfg = Config{}) {
    return analyzeEvents(events, cfg).alerts;
}
static size_t countRule(const std::vector<Alert>& a, const std::string& rule) {
    return static_cast<size_t>(std::count_if(a.begin(), a.end(), [&](const Alert& x) { return x.rule == rule; }));
}
static const Alert* firstRule(const std::vector<Alert>& a, const std::string& rule) {
    for (const auto& x : a) if (x.rule == rule) return &x;
    return nullptr;
}
// Only brute-force enabled: isolates a rule from the others in boundary tests.
static Config only(const char* rule) {
    Config c;
    c.bruteForce.enabled = c.passwordSpraying.enabled = c.distributedAttack.enabled = false;
    c.successAfterFailures.enabled = c.offHours.enabled = c.blacklistRule.enabled = false;
    c.patterns.clear();
    std::string r = rule;
    if (r == "brute") c.bruteForce.enabled = true;
    if (r == "spray") c.passwordSpraying.enabled = true;
    if (r == "dist") c.distributedAttack.enabled = true;
    if (r == "sa") c.successAfterFailures.enabled = true;
    if (r == "off") c.offHours.enabled = true;
    if (r == "bl") c.blacklistRule.enabled = true;
    return c;
}

// ================================================================== util / parsing
TEST(timestamp_parsing) {
    int64_t t = 0;
    CHECK(parseTimestamp("2024-01-01 00:00:00", t));
    CHECK_EQ(t, 1704067200);
    CHECK(parseTimestamp("2024-01-01T00:00:00Z", t));
    CHECK_EQ(t, 1704067200);
    CHECK(parseTimestamp("2024-01-01T05:30:00+05:30", t));
    CHECK_EQ(t, 1704067200);
    CHECK(parseTimestamp("2024-01-01 00:00:00.123", t));
    CHECK_EQ(t, 1704067200);
    CHECK(parseTimestamp("1704067200", t));
    CHECK_EQ(t, 1704067200);
    CHECK(parseTimestamp("  2024-02-29 12:00:00  ", t));  // leap day
    CHECK(!parseTimestamp("2023-02-29 12:00:00", t));     // not a leap year
    CHECK(!parseTimestamp("1900-02-29 12:00:00", t));
    CHECK(!parseTimestamp("2024-13-01 00:00:00", t));
    CHECK(!parseTimestamp("2024-04-31 00:00:00", t));
    CHECK(!parseTimestamp("2024-01-01 24:00:00", t));
    CHECK(!parseTimestamp("2024-01-01 00:60:00", t));
    CHECK(!parseTimestamp("2024-01-01 00:00:61", t));
    CHECK(!parseTimestamp("2024-01-01", t));
    CHECK(!parseTimestamp("yesterday", t));
    CHECK(!parseTimestamp("", t));
    CHECK(!parseTimestamp("12345", t));  // too short for epoch seconds
    CHECK(!parseTimestamp("2024-01-01 00:00:00 junk", t));
}

TEST(timestamp_roundtrip_and_hour) {
    for (const char* s : {"1970-01-01 00:00:00", "2000-02-29 23:59:59", "2026-10-05 10:00:00", "2099-12-31 12:34:56"}) {
        int64_t t = 0;
        CHECK(parseTimestamp(s, t));
        CHECK_EQ(formatTimestamp(t), std::string(s));
    }
    CHECK_EQ(hourOfDay(T("2026-10-05 03:59:59")), 3);
    CHECK_EQ(hourOfDay(T("2026-10-05 23:00:00")), 23);
}

TEST(ip_parsing) {
    uint32_t v = 0;
    CHECK(parseIpv4("1.2.3.4", v));
    CHECK_EQ(v, 0x01020304u);
    CHECK_EQ(ipv4ToString(v), std::string("1.2.3.4"));
    CHECK(parseIpv4("255.255.255.255", v));
    CHECK(parseIpv4("0.0.0.0", v));
    for (const char* bad : {"256.1.1.1", "1.2.3", "1.2.3.4.5", "01.2.3.4", "1.2.3.", "a.b.c.d", "", "1..2.3", "1.2.3.4 "}) {
        CHECK(!parseIpv4(bad, v));
    }
    bool has4 = true;
    CHECK(isValidIp("2001:db8::1", nullptr, &has4));
    CHECK(!has4);
    CHECK(!isValidIp("hello", nullptr, nullptr));
    CHECK(!isValidIp("12:34", nullptr, nullptr));
}

TEST(csv_splitting) {
    std::vector<std::string> f;
    CHECK(splitCsvLine("a, b ,c", f));
    CHECK_EQ(f.size(), size_t{3});
    CHECK_EQ(f[1], std::string("b"));
    CHECK(splitCsvLine("\"x,y\",\"he said \"\"hi\"\"\",z", f));
    CHECK_EQ(f.size(), size_t{3});
    CHECK_EQ(f[0], std::string("x,y"));
    CHECK_EQ(f[1], std::string("he said \"hi\""));
    CHECK(!splitCsvLine("\"unterminated,a", f));
    CHECK(splitCsvLine("", f));
    CHECK_EQ(f.size(), size_t{1});
}

TEST(log_parser_handles_messy_input) {
    std::string text =
        "\xEF\xBB\xBFtimestamp,username,ip,status\r\n"
        "# a comment\r\n"
        "\r\n"
        "2026-10-05 10:00:00,Alice,10.0.0.1,SUCCESS\r\n"
        "2026-10-05 10:00:01,bob,10.0.0.2,failed\r\n"
        "2026-10-05 10:00:02,carol,10.0.0.3,0\r\n"
        "garbage line\r\n"
        "2026-13-05 10:00:00,dave,10.0.0.4,SUCCESS\r\n"
        "2026-10-05 10:00:00,eve,999.0.0.1,SUCCESS\r\n"
        "2026-10-05 10:00:00,,10.0.0.1,SUCCESS\r\n"
        "2026-10-05 10:00:00,frank,10.0.0.1,MAYBE\r\n"
        "2026-10-05 10:00:03,\"gina\",2001:db8::5,ok\r\n";
    std::istringstream in(text);
    std::vector<LoginEvent> out;
    ParseReport r = parseLogStream(in, out);
    CHECK_EQ(out.size(), size_t{4});
    CHECK_EQ(r.parsed, size_t{4});
    CHECK_EQ(r.malformed, size_t{5});
    CHECK_EQ(r.skipped, size_t{3});  // header, comment, blank
    CHECK_EQ(out[0].user, std::string("alice"));  // lower-cased
    CHECK(out[0].success);
    CHECK(!out[1].success);
    CHECK(!out[2].success);
    CHECK(out[3].success && !out[3].hasIp4);
    CHECK(!r.samples.empty());
}

TEST(log_parser_without_header_and_empty_input) {
    std::istringstream a("2026-10-05 10:00:00,a,1.1.1.1,SUCCESS\n");
    std::vector<LoginEvent> out;
    CHECK_EQ(parseLogStream(a, out).parsed, size_t{1});
    std::istringstream b("");
    out.clear();
    ParseReport r = parseLogStream(b, out);
    CHECK_EQ(r.parsed, size_t{0});
    CHECK_EQ(r.malformed, size_t{0});
}

// ================================================================== data structures
TEST(dsu_basics_and_chains) {
    DisjointSets d;
    for (int i = 0; i < 10; ++i) d.add();
    CHECK(d.unite(0, 1));
    CHECK(d.unite(1, 2));
    CHECK(!d.unite(0, 2));
    CHECK(d.connected(0, 2));
    CHECK(!d.connected(0, 3));
    CHECK_EQ(d.setSize(2), 3);
    // a long chain must not blow the stack and must compress
    DisjointSets big;
    const int n = 200000;
    for (int i = 0; i < n; ++i) big.add();
    for (int i = 1; i < n; ++i) big.unite(i - 1, i);
    CHECK(big.connected(0, n - 1));
    CHECK_EQ(big.setSize(12345), n);
}

TEST(cidr_trie_longest_prefix) {
    CidrTrie t;
    CHECK(t.insert("203.0.113.0/24"));
    CHECK(t.insert("203.0.113.7"));  // /32 inside the /24
    CHECK(t.insert("10.0.0.0/8"));
    CHECK(!t.insert("1.2.3.4/33"));
    CHECK(!t.insert("1.2.3/24"));
    CHECK(!t.insert("1.2.3.4/"));
    CHECK(!t.insert("nonsense"));
    uint32_t ip = 0;
    parseIpv4("203.0.113.99", ip);
    CHECK(t.match(ip) >= 0);
    CHECK_EQ(t.label(t.match(ip)), std::string("203.0.113.0/24"));
    parseIpv4("203.0.113.7", ip);
    CHECK_EQ(t.label(t.match(ip)), std::string("203.0.113.7"));  // longest prefix wins
    parseIpv4("203.0.114.1", ip);
    CHECK_EQ(t.match(ip), -1);
    parseIpv4("10.255.255.255", ip);
    CHECK(t.match(ip) >= 0);
    CidrTrie all;
    CHECK(all.insert("0.0.0.0/0"));
    parseIpv4("8.8.8.8", ip);
    CHECK(all.match(ip) >= 0);
}

TEST(sliding_window_boundaries_are_inclusive) {
    TimeWindow w;
    for (int64_t t : {0, 100, 200}) w.push(t);
    w.expire(200 - 200);  // cutoff 0: event at t=0 is exactly on the edge and stays
    CHECK_EQ(w.size(), size_t{3});
    w.expire(201 - 200);  // cutoff 1: t=0 drops
    CHECK_EQ(w.size(), size_t{2});

    SlidingDistinct d;
    d.add(0, "a");
    d.add(1, "a");
    d.add(2, "b");
    CHECK_EQ(d.distinct(), size_t{2});
    CHECK_EQ(d.total(), size_t{3});
    d.expire(2);  // both "a" entries expire
    CHECK_EQ(d.distinct(), size_t{1});
    CHECK_EQ(d.total(), size_t{1});
}

TEST(topk_matches_full_sort) {
    std::mt19937_64 rng(1234);
    for (int round = 0; round < 50; ++round) {
        std::vector<int> v(static_cast<size_t>(rng() % 300));
        for (auto& x : v) x = static_cast<int>(rng() % 1000);
        const size_t k = static_cast<size_t>(rng() % 20);
        auto better = [](int a, int b) { return a > b; };
        std::vector<int> expected = v;
        std::sort(expected.begin(), expected.end(), better);
        if (expected.size() > k) expected.resize(k);
        CHECK(topK(v, k, better) == expected);
    }
}

TEST(rank_entities_aggregates_and_orders) {
    std::vector<std::pair<std::string, int>> in = {{"a", 10}, {"b", 50}, {"a", 45}, {"c", 55}, {"b", 1}};
    auto r = rankEntities(in, 2);
    CHECK_EQ(r.size(), size_t{2});
    CHECK_EQ(r[0].key, std::string("c"));  // total 55 ties with "a", but its max score (55) is higher
    CHECK_EQ(r[0].totalScore, int64_t{55});
    CHECK_EQ(r[1].key, std::string("a"));  // total 55, max 45
    CHECK_EQ(r[1].alerts, 2);
}

// ================================================================== detection rules
TEST(brute_force_threshold_and_window_boundary) {
    Config c = only("brute");  // 5 failures within 300 s
    // exactly on the boundary: t = 0,75,150,225,300 -> all inside a 300 s window
    std::vector<LoginEvent> a;
    for (int i = 0; i < 5; ++i) a.push_back(ev(T0 + i * 75, "alice", "9.9.9.9", false));
    CHECK_EQ(countRule(analyze(a, c), "brute_force"), size_t{1});
    // one second too slow: 0,76,152,228,304
    std::vector<LoginEvent> b;
    for (int i = 0; i < 5; ++i) b.push_back(ev(T0 + i * 76, "alice", "9.9.9.9", false));
    CHECK_EQ(analyze(b, c).size(), size_t{0});
    // four failures never fire
    std::vector<LoginEvent> d;
    for (int i = 0; i < 4; ++i) d.push_back(ev(T0 + i, "alice", "9.9.9.9", false));
    CHECK_EQ(analyze(d, c).size(), size_t{0});
}

TEST(brute_force_is_per_user_and_ip) {
    Config c = only("brute");
    std::vector<LoginEvent> e;
    for (int i = 0; i < 10; ++i) e.push_back(ev(T0 + i, i % 2 ? "alice" : "bob", "9.9.9.9", false));  // 5 each? 5 and 5
    CHECK_EQ(countRule(analyze(e, c), "brute_force"), size_t{2});
    std::vector<LoginEvent> f;
    for (int i = 0; i < 8; ++i) f.push_back(ev(T0 + i, "alice", i % 2 ? "1.1.1.1" : "2.2.2.2", false));  // 4 per IP
    CHECK_EQ(analyze(f, c).size(), size_t{0});
}

TEST(brute_force_long_attack_is_one_incident_with_peak_and_total) {
    Config c = only("brute");
    std::vector<LoginEvent> e;
    for (int i = 0; i < 200; ++i) e.push_back(ev(T0 + i * 3, "alice", "9.9.9.9", false));  // 600 s of failures
    auto alerts = analyze(e, c);
    CHECK_EQ(alerts.size(), size_t{1});
    CHECK_EQ(alerts[0].events, 200);
    CHECK(alerts[0].count >= 100 && alerts[0].count <= 101);  // ~100 failures fit in a 300 s window
    CHECK_EQ(alerts[0].endTs, T0 + 199 * 3);
}

TEST(brute_force_two_separate_incidents) {
    Config c = only("brute");
    std::vector<LoginEvent> e;
    for (int i = 0; i < 6; ++i) e.push_back(ev(T0 + i, "alice", "9.9.9.9", false));
    for (int i = 0; i < 6; ++i) e.push_back(ev(T0 + 5000 + i, "alice", "9.9.9.9", false));
    CHECK_EQ(countRule(analyze(e, c), "brute_force"), size_t{2});
}

TEST(unsorted_input_gives_same_result_as_sorted) {
    Config c;
    std::vector<LoginEvent> e;
    for (int i = 0; i < 30; ++i) e.push_back(ev(T0 + i * 4, "alice", "9.9.9.9", false));
    e.push_back(ev(T0 + 200, "alice", "9.9.9.9", true));
    auto sortedAlerts = analyze(e, c);
    std::mt19937_64 rng(5);
    std::shuffle(e.begin(), e.end(), rng);
    auto shuffled = analyze(e, c);
    CHECK_EQ(sortedAlerts.size(), shuffled.size());
    for (size_t i = 0; i < std::min(sortedAlerts.size(), shuffled.size()); ++i) {
        CHECK_EQ(sortedAlerts[i].rule, shuffled[i].rule);
        CHECK_EQ(sortedAlerts[i].score, shuffled[i].score);
        CHECK_EQ(sortedAlerts[i].ts, shuffled[i].ts);
    }
}

TEST(password_spraying_counts_distinct_users) {
    Config c = only("spray");  // 6 distinct users in 600 s
    std::vector<LoginEvent> a;
    for (int i = 0; i < 6; ++i) a.push_back(ev(T0 + i * 10, ("user" + std::to_string(i)).c_str(), "8.8.8.8", false));
    auto r = analyze(a, c);
    CHECK_EQ(r.size(), size_t{1});
    CHECK(r[0].user.empty());
    CHECK_EQ(r[0].ip, std::string("8.8.8.8"));
    // 20 attempts but only 5 distinct users: no alert
    std::vector<LoginEvent> b;
    for (int i = 0; i < 20; ++i) b.push_back(ev(T0 + i, ("user" + std::to_string(i % 5)).c_str(), "8.8.8.8", false));
    CHECK_EQ(analyze(b, c).size(), size_t{0});
    // distinct users spread beyond the window never accumulate
    std::vector<LoginEvent> d;
    for (int i = 0; i < 6; ++i) d.push_back(ev(T0 + i * 700, ("user" + std::to_string(i)).c_str(), "8.8.8.8", false));
    CHECK_EQ(analyze(d, c).size(), size_t{0});
}

TEST(distributed_attack_counts_distinct_ips) {
    Config c = only("dist");  // 4 distinct IPs in 600 s
    std::vector<LoginEvent> a;
    for (int i = 0; i < 4; ++i) a.push_back(ev(T0 + i * 30, "alice", ("5.5.5." + std::to_string(i + 1)).c_str(), false));
    auto r = analyze(a, c);
    CHECK_EQ(r.size(), size_t{1});
    CHECK_EQ(r[0].user, std::string("alice"));
    CHECK(r[0].ip.empty());
    std::vector<LoginEvent> b;
    for (int i = 0; i < 12; ++i) b.push_back(ev(T0 + i, "alice", ("5.5.5." + std::to_string(i % 3)).c_str(), false));
    CHECK_EQ(analyze(b, c).size(), size_t{0});
}

TEST(success_after_failures) {
    Config c = only("sa");  // >= 4 failures within 600 s, then success
    std::vector<LoginEvent> a;
    for (int i = 0; i < 4; ++i) a.push_back(ev(T0 + i * 10, "alice", "7.7.7.7", false));
    a.push_back(ev(T0 + 60, "alice", "7.7.7.7", true));
    auto r = analyze(a, c);
    CHECK_EQ(r.size(), size_t{1});
    CHECK_EQ(r[0].count, 4);
    CHECK(r[0].successEvent);
    // ordinary typo: 3 failures then success
    std::vector<LoginEvent> b;
    for (int i = 0; i < 3; ++i) b.push_back(ev(T0 + i * 10, "alice", "7.7.7.7", false));
    b.push_back(ev(T0 + 60, "alice", "7.7.7.7", true));
    CHECK_EQ(analyze(b, c).size(), size_t{0});
    // failures too old
    std::vector<LoginEvent> d;
    for (int i = 0; i < 5; ++i) d.push_back(ev(T0 + i, "alice", "7.7.7.7", false));
    d.push_back(ev(T0 + 700, "alice", "7.7.7.7", true));
    CHECK_EQ(analyze(d, c).size(), size_t{0});
    // a success resets the streak: fail x3, ok, fail x3, ok -> never 4 in a row
    std::vector<LoginEvent> f;
    int64_t t = T0;
    for (int round = 0; round < 2; ++round) {
        for (int i = 0; i < 3; ++i) f.push_back(ev(t++, "alice", "7.7.7.7", false));
        f.push_back(ev(t++, "alice", "7.7.7.7", true));
    }
    CHECK_EQ(analyze(f, c).size(), size_t{0});
}

TEST(off_hours_and_wraparound) {
    Config c = only("off");  // business hours 07:00-20:00
    std::vector<LoginEvent> e = {ev(T("2026-10-05 03:00:00"), "alice", "1.1.1.1", true),
                                 ev(T("2026-10-05 03:10:00"), "bob", "1.1.1.1", false),   // failures are ignored
                                 ev(T("2026-10-05 12:00:00"), "carol", "1.1.1.1", true),  // business hours
                                 ev(T("2026-10-05 20:00:00"), "dave", "1.1.1.1", true),   // end is exclusive
                                 ev(T("2026-10-05 07:00:00"), "erin", "1.1.1.1", true)};  // start is inclusive
    auto r = analyze(e, c);
    CHECK_EQ(r.size(), size_t{2});  // alice, dave
    // night-shift configuration 22 -> 6
    Config night = only("off");
    night.offHours.startHour = 22;
    night.offHours.endHour = 6;
    std::vector<LoginEvent> n = {ev(T("2026-10-05 23:00:00"), "a", "1.1.1.1", true), ev(T("2026-10-05 05:59:00"), "b", "1.1.1.1", true),
                                 ev(T("2026-10-05 12:00:00"), "c", "1.1.1.1", true)};
    auto nr = analyze(n, night);
    CHECK_EQ(nr.size(), size_t{1});
    CHECK_EQ(nr[0].user, std::string("c"));
}

TEST(off_hours_dedup_per_user_and_ip) {
    Config c = only("off");
    std::vector<LoginEvent> e = {ev(T("2026-10-05 03:00:00"), "alice", "1.1.1.1", true),
                                 ev(T("2026-10-05 04:00:00"), "alice", "1.1.1.1", true),   // same user+ip inside cooldown: suppressed
                                 ev(T("2026-10-05 05:00:00"), "alice", "2.2.2.2", true),   // NEW ip: reported
                                 ev(T("2026-10-06 04:00:00"), "alice", "1.1.1.1", true)};  // after 24 h: reported
    CHECK_EQ(analyze(e, c).size(), size_t{3});
}

TEST(blacklist_sessions_and_success_alerts) {
    Config c = only("bl");
    std::vector<LoginEvent> e = {ev(T0, "u1", "203.0.113.50", false), ev(T0 + 60, "u2", "203.0.113.50", false),
                                 ev(T0 + 120, "alice", "203.0.113.50", true), ev(T0 + 200, "u3", "8.8.8.8", false),
                                 ev(T0 + 20000, "u4", "203.0.113.50", false)};  // new session after the gap
    auto r = analyze(e, c);
    CHECK_EQ(r.size(), size_t{3});  // failure session #1, success (alice), failure session #2
    CHECK_EQ(r[0].events, 2);
    CHECK(r[1].successEvent);
    CHECK_EQ(r[1].user, std::string("alice"));
    CHECK_EQ(r[0].extra, std::string("203.0.113.0/24"));
}

TEST(blacklist_ignores_ipv6_and_empty_list) {
    Config c = only("bl");
    std::vector<LoginEvent> e = {ev(T0, "a", "2001:db8::1", false)};
    CHECK_EQ(analyze(e, c).size(), size_t{0});
    c.blacklist.clear();
    std::vector<LoginEvent> f = {ev(T0, "a", "203.0.113.5", false)};
    CHECK_EQ(analyze(f, c).size(), size_t{0});
}

TEST(custom_pattern_regex_and_outcome) {
    Config c;
    c.bruteForce.enabled = c.passwordSpraying.enabled = c.distributedAttack.enabled = false;
    c.successAfterFailures.enabled = c.offHours.enabled = c.blacklistRule.enabled = false;
    c.patterns = {CustomPattern{"svc", "^svc_", CustomPattern::Outcome::Failure, 3, 300, 40}};
    std::vector<LoginEvent> e;
    for (int i = 0; i < 3; ++i) e.push_back(ev(T0 + i, "svc_backup", "1.1.1.1", false));
    for (int i = 0; i < 10; ++i) e.push_back(ev(T0 + i, "alice", "1.1.1.1", false));      // no match
    for (int i = 0; i < 10; ++i) e.push_back(ev(T0 + i, "svc_ok", "1.1.1.1", true));      // wrong outcome
    auto r = analyze(e, c);
    CHECK_EQ(r.size(), size_t{1});
    CHECK_EQ(r[0].rule, std::string("custom:svc"));
    CHECK_EQ(r[0].user, std::string("svc_backup"));
}

TEST(engine_is_reusable_and_deterministic) {
    Engine eng{Config{}};
    std::vector<LoginEvent> e;
    for (int i = 0; i < 10; ++i) e.push_back(ev(T0 + i, "alice", "9.9.9.9", false));
    auto a = eng.run(e);
    auto b = eng.run(e);
    CHECK_EQ(a.size(), b.size());
    CHECK(!a.empty());
}

TEST(memory_sweep_does_not_change_results) {
    // > 65536 events forces the periodic sweep of expired windows; results must match.
    Config c = only("brute");
    std::vector<LoginEvent> e;
    for (int i = 0; i < 70000; ++i) e.push_back(ev(T0 + i * 10, ("u" + std::to_string(i % 500)).c_str(), "9.9.9.9", false));
    // an attack late in the stream, after sweeps have run
    const int64_t late = T0 + 70000LL * 10 + 1000;
    for (int i = 0; i < 6; ++i) e.push_back(ev(late + i, "victim", "6.6.6.6", false));
    auto r = analyze(e, c);
    CHECK_EQ(countRule(r, "brute_force"), size_t{1});
    CHECK_EQ(r.back().user, std::string("victim"));
}

// ================================================================== scoring
TEST(severity_bands_at_exact_boundaries) {
    ScoringConfig s;
    CHECK(severityForScore(0, s) == Severity::Low);
    CHECK(severityForScore(29, s) == Severity::Low);
    CHECK(severityForScore(30, s) == Severity::Medium);
    CHECK(severityForScore(59, s) == Severity::Medium);
    CHECK(severityForScore(60, s) == Severity::High);
    CHECK(severityForScore(79, s) == Severity::High);
    CHECK(severityForScore(80, s) == Severity::Critical);
    CHECK(severityForScore(100, s) == Severity::Critical);
    Severity v;
    CHECK(parseSeverity(" HIGH ", v) && v == Severity::High);
    CHECK(!parseSeverity("urgent", v));
}

TEST(score_factors_sum_and_are_capped) {
    Config c;
    std::vector<LoginEvent> e;
    // heavy brute force against admin from a blacklisted IP, then a successful login
    for (int i = 0; i < 300; ++i) e.push_back(ev(T0 + i, "admin", "203.0.113.9", false));
    e.push_back(ev(T0 + 310, "admin", "203.0.113.9", true));
    auto alerts = analyze(e, c);
    CHECK(!alerts.empty());
    for (const Alert& a : alerts) {
        int sum = 0;
        for (const auto& f : a.factors) sum += f.points;
        CHECK_EQ(a.score, std::min(100, std::max(0, sum)));
        CHECK(a.score >= 0 && a.score <= 100);
        CHECK(!a.factors.empty());
    }
    const Alert* bf = firstRule(alerts, "brute_force");
    CHECK(bf != nullptr);
    if (bf) {
        CHECK(bf->severity == Severity::Critical);
        bool volume = false, bl = false, priv = false;
        for (const auto& f : bf->factors) {
            volume |= f.name == "volume";
            bl |= f.name == "blacklisted_ip";
            priv |= f.name == "privileged_account";
        }
        CHECK(volume && bl && priv);
    }
}

TEST(campaigns_link_alerts_via_shared_entities_but_not_private_ips) {
    Config c;
    std::vector<LoginEvent> e;
    // attacker 45.1.1.1 brute-forces alice and then succeeds -> two rule types, one campaign
    for (int i = 0; i < 8; ++i) e.push_back(ev(T0 + i, "alice", "45.1.1.1", false));
    e.push_back(ev(T0 + 20, "alice", "45.1.1.1", true));
    // unrelated attack on bob from another IP
    for (int i = 0; i < 6; ++i) e.push_back(ev(T0 + 5000 + i, "bob", "45.2.2.2", false));
    auto alerts = analyze(e, c);
    const Alert* a = firstRule(alerts, "brute_force");
    const Alert* s = firstRule(alerts, "success_after_failures");
    CHECK(a && s);
    if (a && s) {
        CHECK_EQ(a->clusterId, s->clusterId);
        bool boosted = false;
        for (const auto& f : a->factors) boosted |= f.name == "campaign_correlation";
        CHECK(boosted);
    }
    int bobCluster = -1;
    for (const Alert& x : alerts) if (x.user == "bob") bobCluster = x.clusterId;
    CHECK(bobCluster != -1 && bobCluster != a->clusterId);

    // Two different users failing behind the same office NAT (10.x) must NOT be merged.
    std::vector<LoginEvent> n;
    for (int i = 0; i < 6; ++i) n.push_back(ev(T0 + i, "carl", "10.0.0.1", false));
    for (int i = 0; i < 6; ++i) n.push_back(ev(T0 + 100 + i, "dana", "10.0.0.1", false));
    auto na = analyze(n, c);
    CHECK_EQ(na.size(), size_t{2});
    if (na.size() == 2) CHECK(na[0].clusterId != na[1].clusterId);
}

TEST(campaigns_are_time_bounded) {
    Config c;
    std::vector<LoginEvent> e;
    for (int i = 0; i < 6; ++i) e.push_back(ev(T0 + i, "alice", "45.1.1.1", false));
    for (int i = 0; i < 6; ++i) e.push_back(ev(T0 + 5 * 86400 + i, "alice", "45.9.9.9", false));  // five days later
    auto alerts = analyze(e, c);
    CHECK_EQ(alerts.size(), size_t{2});
    if (alerts.size() == 2) CHECK(alerts[0].clusterId != alerts[1].clusterId);
}

// ================================================================== configuration
TEST(config_defaults_are_valid_and_roundtrip) {
    Config d;
    json j = configToJson(d);
    Config again = parseConfig(j);
    CHECK_EQ(again.bruteForce.threshold, d.bruteForce.threshold);
    CHECK_EQ(again.patterns.size(), d.patterns.size());
    CHECK_EQ(again.blacklist.size(), d.blacklist.size());
    CHECK(again.warnings.empty());
}

TEST(config_validation_rejects_bad_values) {
    auto bad = [](const char* text) {
        try {
            parseConfig(json::parse(text));
            return false;
        } catch (const ConfigError&) {
            return true;
        }
    };
    CHECK(bad(R"({"rules":{"brute_force":{"max_failures":0}}})"));
    CHECK(bad(R"({"rules":{"brute_force":{"window_seconds":-5}}})"));
    CHECK(bad(R"({"rules":{"brute_force":{"weight":101}}})"));
    CHECK(bad(R"({"rules":{"brute_force":{"max_failures":"five"}}})"));
    CHECK(bad(R"({"rules":{"brute_force":{"enabled":1}}})"));
    CHECK(bad(R"({"rules":{"brute_force":5}})"));
    CHECK(bad(R"({"blacklist":["300.1.1.1"]})"));
    CHECK(bad(R"({"blacklist":"1.2.3.4"})"));
    CHECK(bad(R"({"business_hours":{"start":9,"end":9}})"));
    CHECK(bad(R"({"business_hours":{"start":25}})"));
    CHECK(bad(R"({"severity":{"medium":70,"high":60,"critical":80}})"));
    CHECK(bad(R"({"custom_patterns":[{"name":"x","username_regex":"("}]})"));
    CHECK(bad(R"({"custom_patterns":[{"name":"x"}]})"));
    CHECK(bad(R"({"custom_patterns":[{"name":"a b","username_regex":"x"}]})"));
    CHECK(bad(R"({"custom_patterns":[{"name":"x","username_regex":"a"},{"name":"x","username_regex":"b"}]})"));
    CHECK(bad(R"({"custom_patterns":[{"name":"x","username_regex":"a","outcome":"maybe"}]})"));
    CHECK(bad(R"([1,2,3])"));
}

TEST(config_overrides_and_unknown_keys_warn) {
    Config c = parseConfig(json::parse(R"({
        "rules": {"brute_force": {"max_failures": 3, "window_seconds": 60, "typo_key": 1}},
        "blacklist": [],
        "custom_patterns": [],
        "surprise": true })"));
    CHECK_EQ(c.bruteForce.threshold, 3);
    CHECK_EQ(c.bruteForce.windowSeconds, 60);
    CHECK(c.blacklist.empty());
    CHECK(c.patterns.empty());
    CHECK_EQ(c.warnings.size(), size_t{2});
    // the new threshold is honoured by the engine
    std::vector<LoginEvent> e;
    for (int i = 0; i < 3; ++i) e.push_back(ev(T0 + i, "alice", "9.9.9.9", false));
    CHECK_EQ(countRule(analyze(e, c), "brute_force"), size_t{1});
}

TEST(config_file_allows_comments) {
    const char* path = "lg_test_config.json";
    {
        std::ofstream f(path);
        f << "{ // comment\n \"rules\": { /* block */ \"brute_force\": {\"max_failures\": 9} } }\n";
    }
    Config c = loadConfigFile(path);
    CHECK_EQ(c.bruteForce.threshold, 9);
    std::remove(path);
    bool threw = false;
    try { loadConfigFile("does_not_exist.json"); } catch (const ConfigError&) { threw = true; }
    CHECK(threw);
}

// ================================================================== storage + API
static std::unique_ptr<Database> makeDb(const std::vector<Alert>& alerts, const std::vector<LoginEvent>& events) {
    auto db = std::make_unique<Database>(":memory:", false);
    db->load(events, alerts, json{{"source", "test.csv"}, {"config", configToJson(Config{})}});
    return db;
}

static std::vector<LoginEvent> attackEvents() {
    std::vector<LoginEvent> e;
    for (int i = 0; i < 30; ++i) e.push_back(ev(T0 + i * 5, "alice", "45.1.1.1", false));
    e.push_back(ev(T0 + 200, "alice", "45.1.1.1", true));
    for (int i = 0; i < 8; ++i) e.push_back(ev(T0 + 1000 + i * 10, ("u" + std::to_string(i)).c_str(), "45.2.2.2", false));
    e.push_back(ev(T("2026-10-05 03:00:00"), "zed", "1.1.1.1", true));
    for (int i = 0; i < 20; ++i) e.push_back(ev(T0 + 3000 + i * 60, "normal", "10.0.0.1", true));
    return e;
}

TEST(storage_roundtrip_filters_and_injection_safety) {
    auto events = attackEvents();
    auto res = analyzeEvents(events, Config{});
    auto dbp = makeDb(res.alerts, events);
    Database& db = *dbp;
    db.requireValidSchema();

    json sum = db.summary();
    CHECK_EQ(sum["events"]["total"].get<int64_t>(), static_cast<int64_t>(events.size()));
    CHECK_EQ(sum["alerts"]["total"].get<int64_t>(), static_cast<int64_t>(res.alerts.size()));

    AlertFilter f;
    json all = db.alerts(f);
    CHECK_EQ(all["total"].get<size_t>(), res.alerts.size());
    // default order: highest score first
    int prev = 101;
    for (const json& a : all["items"]) {
        CHECK(a["score"].get<int>() <= prev);
        prev = a["score"].get<int>();
    }
    f.rules = {"brute_force"};
    CHECK_EQ(db.alerts(f)["total"].get<size_t>(), countRule(res.alerts, "brute_force"));
    f = AlertFilter{};
    f.severities = {Severity::Critical, Severity::High};
    for (const json& a : db.alerts(f)["items"]) CHECK(a["severity"].get<int>() >= 2);
    f = AlertFilter{};
    f.limit = 1;
    f.offset = 1;
    CHECK_EQ(db.alerts(f)["items"].size(), size_t{1});
    CHECK_EQ(db.alerts(f)["offset"].get<int>(), 1);

    // hostile strings are data, never SQL
    f = AlertFilter{};
    f.search = "'; DROP TABLE alerts; --";
    CHECK_EQ(db.alerts(f)["total"].get<int>(), 0);
    f.search = "%";
    CHECK_EQ(db.alerts(f)["total"].get<int>(), 0);  // LIKE wildcards are escaped
    f = AlertFilter{};
    f.user = "x' OR '1'='1";
    CHECK_EQ(db.alerts(f)["total"].get<int>(), 0);
    f = AlertFilter{};
    CHECK_EQ(db.alerts(f)["total"].get<size_t>(), res.alerts.size());  // table intact
    f.sort = "score; DROP TABLE alerts";
    bool threw = false;
    try { db.alerts(f); } catch (const DbError&) { threw = true; }
    CHECK(threw);

    // detail view
    json d = db.alertDetail(1);
    CHECK(!d.is_null());
    CHECK(!d["factors"].empty());
    CHECK(db.alertDetail(99999).is_null());
    // aggregates
    CHECK_EQ(db.hourOfDay().size(), size_t{24});
    CHECK(!db.timeline(3600)["buckets"].empty());
    CHECK(!db.topRisk(true, 5).empty());
    CHECK(db.topIps(3).size() <= 3);
    CHECK(db.topUsers(3).size() <= 3);
    CHECK(!db.ruleStats().empty());
    CHECK(!db.config().empty());
}

TEST(storage_rejects_foreign_database) {
    Database db(":memory:", false);
    bool threw = false;
    try { db.requireValidSchema(); } catch (const DbError&) { threw = true; }
    CHECK(threw);
}

TEST(api_end_to_end_over_http) {
    auto events = attackEvents();
    auto res = analyzeEvents(events, Config{});
    auto dbp = makeDb(res.alerts, events);
    Database& db = *dbp;

    httplib::Server svr;
    registerApi(svr, db, "");
    const int port = svr.bind_to_any_port("127.0.0.1");
    CHECK(port > 0);
    std::thread th([&] { svr.listen_after_bind(); });
    svr.wait_until_ready();
    httplib::Client cli("127.0.0.1", port);
    cli.set_connection_timeout(3);
    cli.set_read_timeout(5);

    auto get = [&](const std::string& path) { return cli.Get(path); };
    auto r = get("/api/health");
    CHECK(r && r->status == 200);
    r = get("/api/summary");
    CHECK(r && r->status == 200);
    if (r) CHECK(json::parse(r->body)["events"]["total"].get<size_t>() == events.size());
    r = get("/api/alerts?severity=high,critical&limit=2");
    CHECK(r && r->status == 200);
    if (r) CHECK(json::parse(r->body)["items"].size() <= 2);
    r = get("/api/alerts/1");
    CHECK(r && r->status == 200);
    r = get("/api/alerts/424242");
    CHECK(r && r->status == 404);
    for (const char* bad : {"/api/alerts?limit=abc", "/api/alerts?severity=nope", "/api/alerts?sort=bogus",
                            "/api/alerts?min_score=90&max_score=10", "/api/timeline?bucket=7", "/api/top-risk?by=x",
                            "/api/alerts?from=garbage"}) {
        r = get(bad);
        CHECK(r && r->status == 400);
        if (r) CHECK(json::parse(r->body).contains("error"));
    }
    r = get("/api/alerts?from=2026-10-05&to=2026-10-05");  // bare dates are accepted
    CHECK(r && r->status == 200);
    r = get("/api/nope");
    CHECK(r && r->status == 404);
    // security headers
    r = get("/api/health");
    CHECK(r && r->has_header("Content-Security-Policy") && r->has_header("X-Content-Type-Options"));
    // hostile query is harmless and the server keeps working
    r = get("/api/alerts?q=%27%3B%20DROP%20TABLE%20alerts%3B--");
    CHECK(r && r->status == 200);
    r = get("/api/alerts?limit=1");
    CHECK(r && r->status == 200);

    svr.stop();
    th.join();
}

// ================================================================== end-to-end against ground truth
TEST(generated_logs_every_attack_detected_across_seeds) {
    for (uint64_t seed : {1u, 2u, 3u, 7u, 11u, 42u, 99u, 1234u}) {
        GenParams gp;
        gp.seed = seed;
        gp.targetEvents = 60000;
        gp.users = 300;
        gp.days = 5;
        GenResult g = generateLogs(gp);
        auto res = analyzeEvents(g.events, Config{});
        EvalReport rep = evaluateAlerts(res.alerts, g.truth);
        if (rep.detected != rep.attacks || rep.unexplainedHighPlus != 0) std::printf("%s", formatEvalReport(rep).c_str());
        CHECK_EQ(rep.detected, rep.attacks);
        CHECK_EQ(rep.unexplainedHighPlus, size_t{0});  // no high/critical false alarms on benign traffic
        CHECK(rep.attacks >= 20);
    }
}

TEST(generator_is_deterministic_and_csv_roundtrips) {
    GenParams gp;
    gp.seed = 5;
    gp.targetEvents = 5000;
    gp.users = 40;
    gp.days = 2;
    GenResult a = generateLogs(gp), b = generateLogs(gp);
    CHECK_EQ(a.events.size(), b.events.size());
    CHECK_EQ(a.truth.size(), b.truth.size());
    CHECK(std::is_sorted(a.events.begin(), a.events.end(), [](const LoginEvent& x, const LoginEvent& y) { return x.ts < y.ts; }));
    const char* path = "lg_test_roundtrip.csv";
    std::string err;
    CHECK(writeLogCsv(path, a.events, err));
    std::vector<LoginEvent> back;
    ParseReport rep;
    CHECK(parseLogFile(path, back, rep, err));
    CHECK_EQ(rep.malformed, size_t{0});
    CHECK_EQ(back.size(), a.events.size());
    for (size_t i = 0; i < std::min<size_t>(back.size(), 200); ++i) {
        CHECK_EQ(back[i].ts, a.events[i].ts);
        CHECK_EQ(back[i].user, a.events[i].user);
        CHECK_EQ(back[i].success, a.events[i].success);
    }
    std::remove(path);
    const char* tp = "lg_test_truth.json";
    CHECK(writeTruthJson(tp, a.truth, err));
    std::vector<TruthAttack> t2;
    CHECK(loadTruthJson(tp, t2, err));
    CHECK_EQ(t2.size(), a.truth.size());
    std::remove(tp);
}

TEST(tiny_user_counts_do_not_hang_the_generator) {
    GenParams gp;
    gp.users = 5;
    gp.targetEvents = 1000;
    gp.days = 1;
    GenResult g = generateLogs(gp);
    CHECK(!g.events.empty());
}

// ------------------------------------------------------------------ runner
int main(int argc, char** argv) {
    const std::string filter = argc > 1 ? argv[1] : "";
    int ran = 0, failedTests = 0;
    for (const TestCase& t : registry()) {
        if (!filter.empty() && std::string(t.name).find(filter) == std::string::npos) continue;
        const int before = g_failures;
        try {
            t.fn();
        } catch (const std::exception& e) {
            ++g_failures;
            std::printf("    EXCEPTION: %s\n", e.what());
        }
        ++ran;
        const bool ok = g_failures == before;
        if (!ok) ++failedTests;
        std::printf("[%s] %s\n", ok ? " ok " : "FAIL", t.name);
    }
    std::printf("\n%d tests, %d checks, %d failed check(s)\n", ran, g_checks, g_failures);
    return g_failures == 0 ? 0 : 1;
}
