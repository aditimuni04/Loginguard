#pragma once
// End-to-end analysis: detect -> score/correlate -> order & number alerts.

#include <vector>

#include "loginguard/config.hpp"
#include "loginguard/types.hpp"

namespace lg {

struct AnalysisResult {
    std::vector<Alert> alerts;  // chronological, ids 1..N assigned
    double detectMs = 0;
    double scoreMs = 0;
};

// Sorts `events` by time in place (stable). Throws ConfigError for an invalid config.
AnalysisResult analyzeEvents(std::vector<LoginEvent>& events, const Config& cfg);

}  // namespace lg
