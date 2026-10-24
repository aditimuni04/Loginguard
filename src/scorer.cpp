#include "loginguard/scorer.hpp"

#include <algorithm>
#include <set>
#include <unordered_map>

#include "loginguard/detector.hpp"
#include "loginguard/dsu.hpp"
#include "loginguard/util.hpp"

namespace lg {

// ---------------------------------------------------------------- severity helpers

const char* severityName(Severity s) {
    switch (s) {
        case Severity::Low: return "low";
        case Severity::Medium: return "medium";
        case Severity::High: return "high";
        case Severity::Critical: return "critical";
    }
    return "low";
}

bool parseSeverity(const std::string& text, Severity& out) {
    const std::string t = toLower(trim(text));
    if (t == "low") out = Severity::Low;
    else if (t == "medium") out = Severity::Medium;
    else if (t == "high") out = Severity::High;
    else if (t == "critical") out = Severity::Critical;
    else return false;
    return true;
}

Severity severityForScore(int score, const ScoringConfig& cfg) {
    if (score >= cfg.criticalMin) return Severity::Critical;
    if (score >= cfg.highMin) return Severity::High;
    if (score >= cfg.mediumMin) return Severity::Medium;
    return Severity::Low;
}

// ---------------------------------------------------------------- scorer

Scorer::Scorer(const Config& cfg) : cfg_(cfg.scoring) {
    for (const auto& entry : cfg.blacklist) {
        if (!blacklist_.insert(entry)) throw ConfigError("invalid blacklist entry '" + entry + "'");
    }
    for (const auto& entry : cfg_.campaignIgnoreCidrs) {
        if (!campaignIgnore_.insert(entry)) throw ConfigError("invalid campaign_ignore_cidrs entry '" + entry + "'");
    }
    if (!cfg_.privilegedRegex.empty()) {
        try {
            privileged_ = std::regex(cfg_.privilegedRegex, std::regex::ECMAScript | std::regex::icase);
        } catch (const std::regex_error& e) {
            throw ConfigError(std::string("invalid scoring.privileged_regex: ") + e.what());
        }
    }
}

bool Scorer::ipIsBlacklisted(const std::string& ip) const {
    if (blacklist_.empty()) return false;
    uint32_t v = 0;
    return parseIpv4(ip, v) && blacklist_.match(v) >= 0;
}

bool Scorer::ipIsIgnoredForCampaigns(const std::string& ip) const {
    if (campaignIgnore_.empty()) return false;
    uint32_t v = 0;
    return parseIpv4(ip, v) && campaignIgnore_.match(v) >= 0;
}

void Scorer::score(std::vector<Alert>& alerts) const {
    // ---- 1) per-alert factors -------------------------------------------------
    for (Alert& a : alerts) {
        a.factors.clear();
        a.factors.push_back({"base:" + a.rule, a.baseWeight});

        if (a.threshold > 0 && a.count > a.threshold && cfg_.volumeStep > 0) {
            const long extra = std::min<long>(cfg_.volumeCap, static_cast<long>(a.count - a.threshold) * cfg_.volumeStep);
            if (extra > 0) a.factors.push_back({"volume", static_cast<int>(extra)});
        }
        if (a.rule != rules::kBlacklistedIp && cfg_.blacklistBonus > 0 && !a.ip.empty() && ipIsBlacklisted(a.ip)) {
            a.factors.push_back({"blacklisted_ip", cfg_.blacklistBonus});
        }
        if (a.rule == rules::kBlacklistedIp && a.successEvent && cfg_.blacklistSuccessBonus > 0) {
            a.factors.push_back({"successful_login_from_blacklist", cfg_.blacklistSuccessBonus});
        }
        if (privileged_ && cfg_.privilegedBonus > 0 && !a.user.empty() && std::regex_search(a.user, *privileged_)) {
            a.factors.push_back({"privileged_account", cfg_.privilegedBonus});
        }
    }

    // ---- 2) campaign correlation with Union-Find --------------------------------
    // Nodes are IPs and usernames. An alert that mentions both links them; alerts
    // sharing any node end up in one set => one campaign. Time-aware: a node that
    // has been quiet for longer than campaignWindowSeconds is a NEW node, so an
    // alert on Monday and an unrelated one on Friday never merge.
    std::vector<size_t> order(alerts.size());
    for (size_t i = 0; i < order.size(); ++i) order[i] = i;
    std::stable_sort(order.begin(), order.end(), [&](size_t x, size_t y) { return alerts[x].ts < alerts[y].ts; });

    struct NodeState {
        int id = 0;
        int64_t lastTs = 0;
    };
    DisjointSets dsu;
    std::unordered_map<std::string, NodeState> nodes;
    auto node = [&](const std::string& key, const Alert& a) {
        auto [it, inserted] = nodes.try_emplace(key);
        NodeState& st = it->second;
        if (inserted || a.ts - st.lastTs > cfg_.campaignWindowSeconds) {
            st.id = dsu.add();
            st.lastTs = a.endTs;
        } else {
            st.lastTs = std::max(st.lastTs, a.endTs);
        }
        return st.id;
    };
    std::vector<int> anchor(alerts.size(), -1);
    for (size_t i : order) {
        const Alert& a = alerts[i];
        int ipNode = (a.ip.empty() || ipIsIgnoredForCampaigns(a.ip)) ? -1 : node("ip:" + a.ip, a);
        int userNode = a.user.empty() ? -1 : node("user:" + a.user, a);
        if (ipNode >= 0 && userNode >= 0) dsu.unite(ipNode, userNode);
        anchor[i] = ipNode >= 0 ? ipNode : userNode;
    }

    std::unordered_map<int, int> rootToCluster;
    std::vector<std::set<std::string>> clusterRules;
    for (size_t i : order) {
        Alert& a = alerts[i];
        if (anchor[i] < 0) {  // defensive: an alert with neither user nor IP is its own campaign
            clusterRules.emplace_back();
            a.clusterId = static_cast<int>(clusterRules.size());
            clusterRules.back().insert(a.rule);
            continue;
        }
        const int root = dsu.find(anchor[i]);
        auto it = rootToCluster.find(root);
        if (it == rootToCluster.end()) {
            clusterRules.emplace_back();
            it = rootToCluster.emplace(root, static_cast<int>(clusterRules.size())).first;
        }
        a.clusterId = it->second;
        clusterRules[static_cast<size_t>(it->second - 1)].insert(a.rule);
    }

    // ---- 3) campaign bonus, final score and severity ----------------------------
    for (Alert& a : alerts) {
        const size_t distinctRules = clusterRules[static_cast<size_t>(a.clusterId - 1)].size();
        if (distinctRules > 1 && cfg_.campaignBonusPerRule > 0) {
            const int bonus = std::min(cfg_.campaignBonusMax, cfg_.campaignBonusPerRule * static_cast<int>(distinctRules - 1));
            if (bonus > 0) a.factors.push_back({"campaign_correlation", bonus});
        }
        int total = 0;
        for (const auto& f : a.factors) total += f.points;
        a.score = std::clamp(total, 0, 100);
        a.severity = severityForScore(a.score, cfg_);
    }
}

}  // namespace lg
