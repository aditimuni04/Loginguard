#include "loginguard/evaluate.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstdio>
#include <fstream>

namespace lg {

namespace {

constexpr int64_t kSlackSeconds = 120;

bool overlaps(int64_t a0, int64_t a1, int64_t b0, int64_t b1) { return a0 <= b1 && b0 <= a1; }

// Strict: the alert must come from the rule the attack is meant to trigger.
bool detects(const Alert& a, const TruthAttack& t) {
    return a.rule == t.rule && (t.user.empty() || a.user == t.user) && (t.ip.empty() || a.ip == t.ip) &&
           overlaps(a.ts, a.endTs, t.start - kSlackSeconds, t.end + kSlackSeconds);
}

// Loose: the alert is about the same actor at the same time (any rule).
bool relatesTo(const Alert& a, const TruthAttack& t) {
    const bool sameActor = (!t.ip.empty() && a.ip == t.ip) || (!t.user.empty() && a.user == t.user) ||
                           (!t.actor.empty() && a.ip == t.actor);
    return sameActor && overlaps(a.ts, a.endTs, t.start - kSlackSeconds, t.end + kSlackSeconds);
}

}  // namespace

EvalReport evaluateAlerts(const std::vector<Alert>& alerts, const std::vector<TruthAttack>& truth) {
    EvalReport r;
    r.attacks = truth.size();
    r.alerts = alerts.size();
    for (const TruthAttack& t : truth) {
        bool found = false;
        for (const Alert& a : alerts) {
            if (detects(a, t)) {
                found = true;
                break;
            }
        }
        auto& slot = r.perType[t.type];
        ++slot.second;
        if (found) {
            ++slot.first;
            ++r.detected;
        } else {
            r.missed.push_back(t);
        }
    }
    for (const Alert& a : alerts) {
        bool related = false;
        for (const TruthAttack& t : truth) {
            if (relatesTo(a, t)) {
                related = true;
                break;
            }
        }
        if (related) {
            ++r.explained;
        } else {
            ++r.unexplained;
            if (a.severity >= Severity::Medium) ++r.unexplainedMediumPlus;
            if (a.severity >= Severity::High) ++r.unexplainedHighPlus;
            r.topUnexplained.push_back(a);
        }
    }
    std::stable_sort(r.topUnexplained.begin(), r.topUnexplained.end(),
                     [](const Alert& x, const Alert& y) { return x.score > y.score; });
    if (r.topUnexplained.size() > 5) r.topUnexplained.resize(5);
    return r;
}

std::string formatEvalReport(const EvalReport& r) {
    std::string s;
    char buf[160];
    std::snprintf(buf, sizeof buf, "Detection recall: %zu/%zu injected attacks (%.1f%%)\n", r.detected, r.attacks,
                  r.recall() * 100.0);
    s += buf;
    for (const auto& [type, dt] : r.perType) {
        std::snprintf(buf, sizeof buf, "  %-24s %zu/%zu\n", type.c_str(), dt.first, dt.second);
        s += buf;
    }
    std::snprintf(buf, sizeof buf,
                  "Alerts: %zu total, %zu tied to injected attacks, %zu unrelated (%zu medium+, %zu high+)\n", r.alerts,
                  r.explained, r.unexplained, r.unexplainedMediumPlus, r.unexplainedHighPlus);
    s += buf;
    for (const auto& m : r.missed) {
        s += "  MISSED: " + m.type + " user='" + m.user + "' ip='" + m.ip + "'\n";
    }
    if (!r.topUnexplained.empty()) {
        s += "Highest-scoring alerts not tied to an injected attack:\n";
        for (const auto& a : r.topUnexplained) {
            std::snprintf(buf, sizeof buf, "  score %3d %-8s ", a.score, severityName(a.severity));
            s += buf + a.rule + ": " + a.detail + "\n";
        }
    }
    return s;
}

bool writeTruthJson(const std::string& path, const std::vector<TruthAttack>& truth, std::string& error) {
    nlohmann::json arr = nlohmann::json::array();
    for (const auto& t : truth) {
        arr.push_back({{"type", t.type},
                       {"rule", t.rule},
                       {"user", t.user},
                       {"ip", t.ip},
                       {"actor", t.actor},
                       {"start", t.start},
                       {"end", t.end}});
    }
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) {
        error = "cannot write '" + path + "'";
        return false;
    }
    f << arr.dump(2) << "\n";
    if (!f) {
        error = "write error on '" + path + "'";
        return false;
    }
    return true;
}

bool loadTruthJson(const std::string& path, std::vector<TruthAttack>& truth, std::string& error) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        error = "cannot open '" + path + "'";
        return false;
    }
    try {
        nlohmann::json arr = nlohmann::json::parse(f);
        if (!arr.is_array()) {
            error = "truth file must contain a JSON array";
            return false;
        }
        for (const auto& o : arr) {
            TruthAttack t;
            t.type = o.at("type").get<std::string>();
            t.rule = o.at("rule").get<std::string>();
            t.user = o.value("user", "");
            t.ip = o.value("ip", "");
            t.actor = o.value("actor", "");
            t.start = o.at("start").get<int64_t>();
            t.end = o.at("end").get<int64_t>();
            truth.push_back(std::move(t));
        }
    } catch (const nlohmann::json::exception& e) {
        error = std::string("invalid truth file: ") + e.what();
        return false;
    }
    return true;
}

}  // namespace lg
