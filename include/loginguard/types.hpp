#pragma once
// Core data types shared by every module.

#include <cstdint>
#include <string>
#include <vector>

namespace lg {

// One authentication attempt parsed from a log line.
struct LoginEvent {
    int64_t ts = 0;      // seconds since the Unix epoch (log timestamps are treated as UTC)
    std::string user;    // lower-cased username
    std::string ip;      // textual IP address (IPv4 or IPv6)
    bool success = false;
    uint32_t ip4 = 0;    // numeric form, valid only when hasIp4 is true
    bool hasIp4 = false;
};

enum class Severity : int { Low = 0, Medium = 1, High = 2, Critical = 3 };

const char* severityName(Severity s);
// Case-insensitive. Returns false when `text` is not a severity name.
bool parseSeverity(const std::string& text, Severity& out);

struct ScoreFactor {
    std::string name;
    int points = 0;
};

// One detected incident. A single incident may span many log events
// (e.g. a brute-force run of 200 failures is ONE alert whose `count` is the peak).
struct Alert {
    int64_t id = 0;            // assigned after final ordering (1-based)
    int64_t ts = 0;            // when the rule first fired
    int64_t endTs = 0;         // timestamp of the last event that kept the incident alive
    int64_t windowStart = 0;   // start of the context window used for drill-down
    std::string rule;          // e.g. "brute_force", "custom:privileged_account_failures"
    std::string user;          // empty when the rule is IP-centric
    std::string ip;            // empty when the rule is account-centric
    int count = 0;             // peak count inside the window (failures / distinct users / distinct IPs)
    int events = 0;            // total log events that contributed to the incident
    int threshold = 0;         // rule threshold, 0 for rules without one
    int windowSeconds = 0;     // rule window, 0 for rules without one
    int baseWeight = 0;        // weight of the rule that produced the alert
    bool successEvent = false; // true when the triggering event was a successful login
    std::string extra;         // rule-specific text (e.g. matched CIDR)
    std::string detail;        // human-readable explanation
    int score = 0;             // 0..100, filled by the Scorer
    Severity severity = Severity::Low;
    int clusterId = 0;         // campaign id (shared by alerts linked through users/IPs)
    std::vector<ScoreFactor> factors;
};

}  // namespace lg
