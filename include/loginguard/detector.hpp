#pragma once
// Streaming detection engine.
//
// Events are processed once, in timestamp order. Per-key sliding windows give
// O(1) amortised work per event; memory is bounded by a periodic sweep of
// windows that have fully expired.
//
// Rule families
//  * threshold rules (brute force, spraying, distributed, custom patterns):
//      one alert per *incident*. While the condition keeps holding the alert is
//      extended (peak count / end time grow); when it stops holding the next
//      trigger opens a NEW alert.
//  * point rules (success-after-failures, off-hours, blacklist): one alert per
//      key per cooldown (or, for the blacklist, per activity session).

#include <regex>
#include <string>
#include <unordered_map>
#include <vector>

#include "loginguard/cidr_trie.hpp"
#include "loginguard/config.hpp"
#include "loginguard/sliding_window.hpp"
#include "loginguard/types.hpp"

namespace lg {

// Rule identifiers as they appear in alerts / the database / the API.
namespace rules {
extern const std::string kBruteForce;
extern const std::string kPasswordSpraying;
extern const std::string kDistributedAttack;
extern const std::string kSuccessAfterFailures;
extern const std::string kOffHours;
extern const std::string kBlacklistedIp;
extern const std::string kCustomPrefix;  // "custom:"
}  // namespace rules

class Engine {
public:
    explicit Engine(Config cfg);  // throws ConfigError on an invalid blacklist entry / regex

    // Sorts `events` by timestamp (stable) if needed, then detects.
    // Returned alerts are unscored (see Scorer) and ordered by trigger time.
    // The engine can be reused: every call starts from a clean state.
    std::vector<Alert> run(std::vector<LoginEvent>& events);

    const Config& config() const { return cfg_; }

private:
    struct PatternState {
        CustomPattern cfg;
        std::regex re;
        std::unordered_map<std::string, TimeWindow> perUser;
    };

    void reset();
    void process(const LoginEvent& e);
    void onFailure(const LoginEvent& e);
    void onSuccess(const LoginEvent& e);
    void checkBlacklist(const LoginEvent& e);
    void checkPatterns(const LoginEvent& e);
    bool matchesPattern(const std::string& user, size_t patternIndex);

    // Threshold rules: open / extend / close an incident for (rule, entityKey).
    void evalThreshold(const std::string& rule, const std::string& entityKey, bool conditionHolds,
                       size_t count, const LoginEvent& e, int threshold, int window, int weight,
                       const std::string& user, const std::string& ip);

    // Point rules: at most one alert per (rule, entityKey) per cooldown. With
    // `extend` the cooldown is a *gap*: continued activity grows the same alert.
    void firePoint(const std::string& rule, const std::string& entityKey, const LoginEvent& e, int count,
                   int cooldown, bool extend, int weight, int window, const std::string& extra,
                   const std::string& user, const std::string& ip);

    void gc(int64_t now);
    void finalizeDetails();
    std::string describe(const Alert& a) const;
    bool isBusinessHour(int hour) const;

    Config cfg_;
    CidrTrie blacklist_;
    std::vector<PatternState> patterns_;
    // user -> per-pattern regex result (-1 unknown, 0 no, 1 yes); avoids re-running regexes per event
    std::unordered_map<std::string, std::vector<signed char>> patternCache_;

    // per-key sliding windows
    std::unordered_map<std::string, TimeWindow> bf_;          // "user\x1fip" -> failure times
    std::unordered_map<std::string, TimeWindow> sa_;          // "user\x1fip" -> failure times (own window)
    std::unordered_map<std::string, SlidingDistinct> spray_;  // ip   -> distinct usernames failing
    std::unordered_map<std::string, SlidingDistinct> dist_;   // user -> distinct IPs failing

    std::unordered_map<std::string, size_t> open_;  // open threshold incidents -> alert index
    std::unordered_map<std::string, size_t> last_;  // latest point alert per key -> alert index
    std::vector<Alert> alerts_;
    size_t processed_ = 0;
};

}  // namespace lg
