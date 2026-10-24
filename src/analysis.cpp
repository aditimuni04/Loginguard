#include "loginguard/analysis.hpp"

#include <algorithm>
#include <chrono>

#include "loginguard/detector.hpp"
#include "loginguard/scorer.hpp"

namespace lg {

AnalysisResult analyzeEvents(std::vector<LoginEvent>& events, const Config& cfg) {
    using Clock = std::chrono::steady_clock;
    auto ms = [](Clock::time_point a, Clock::time_point b) {
        return std::chrono::duration<double, std::milli>(b - a).count();
    };

    AnalysisResult res;
    Engine engine(cfg);
    Scorer scorer(cfg);

    auto t0 = Clock::now();
    res.alerts = engine.run(events);
    auto t1 = Clock::now();
    scorer.score(res.alerts);
    auto t2 = Clock::now();

    // The engine emits alerts in trigger order already; make that explicit and
    // deterministic (ties broken by rule name) before numbering them.
    std::stable_sort(res.alerts.begin(), res.alerts.end(), [](const Alert& a, const Alert& b) {
        if (a.ts != b.ts) return a.ts < b.ts;
        return a.rule < b.rule;
    });
    int64_t id = 1;
    for (Alert& a : res.alerts) a.id = id++;

    res.detectMs = ms(t0, t1);
    res.scoreMs = ms(t1, t2);
    return res;
}

}  // namespace lg
