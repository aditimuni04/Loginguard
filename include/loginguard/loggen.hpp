#pragma once
// Synthetic authentication-log generator with GROUND TRUTH.
//
// Produces realistic background traffic (office NAT IPs shared by many users,
// home/mobile IPs, weekday/weekend rhythm, occasional typo-and-retry failures)
// and injects labelled attacks so detection quality can be measured:
//   brute force (+ account compromise), password spraying, distributed attack,
//   blacklisted-range activity, off-hours account takeover, privileged-account attack.
// Output is deterministic for a given seed on a given platform.

#include <cstdint>
#include <string>
#include <vector>

#include "loginguard/types.hpp"

namespace lg {

struct GenParams {
    uint64_t seed = 42;
    int users = 500;
    int days = 7;
    int64_t targetEvents = 100000;  // approximate total number of events
    int64_t startTs = 0;            // 0 => 2026-10-01 00:00:00 (UTC)
};

// An injected attack. `rule`, `user`, `ip` are the keys an alert must carry to
// count as detecting it (empty = wildcard); `actor` is informational only.
struct TruthAttack {
    std::string type;
    std::string rule;
    std::string user;
    std::string ip;
    std::string actor;
    int64_t start = 0;
    int64_t end = 0;
};

struct GenResult {
    std::vector<LoginEvent> events;  // sorted by time
    std::vector<TruthAttack> truth;  // sorted by start time
};

GenResult generateLogs(const GenParams& params);

bool writeLogCsv(const std::string& path, const std::vector<LoginEvent>& events, std::string& error);

}  // namespace lg
