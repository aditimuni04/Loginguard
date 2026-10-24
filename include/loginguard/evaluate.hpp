#pragma once
// Measures detection quality against the generator's ground truth.

#include <map>
#include <string>
#include <utility>
#include <vector>

#include "loginguard/loggen.hpp"
#include "loginguard/types.hpp"

namespace lg {

struct EvalReport {
    size_t attacks = 0;
    size_t detected = 0;
    std::map<std::string, std::pair<size_t, size_t>> perType;  // type -> (detected, total)
    std::vector<TruthAttack> missed;

    size_t alerts = 0;
    size_t explained = 0;     // alerts that overlap an injected attack (same IP/user, same time)
    size_t unexplained = 0;   // everything else (background noise, benign anomalies)
    size_t unexplainedMediumPlus = 0;
    size_t unexplainedHighPlus = 0;
    std::vector<Alert> topUnexplained;  // up to 5 highest-scoring unrelated alerts, for inspection

    double recall() const { return attacks == 0 ? 1.0 : static_cast<double>(detected) / static_cast<double>(attacks); }
};

EvalReport evaluateAlerts(const std::vector<Alert>& alerts, const std::vector<TruthAttack>& truth);
std::string formatEvalReport(const EvalReport& r);

bool writeTruthJson(const std::string& path, const std::vector<TruthAttack>& truth, std::string& error);
bool loadTruthJson(const std::string& path, std::vector<TruthAttack>& truth, std::string& error);

}  // namespace lg
