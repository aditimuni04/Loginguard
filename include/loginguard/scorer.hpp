#pragma once
// Risk scoring + campaign correlation.
//
// score = clamp( base rule weight
//              + volume            (how far above the threshold the activity went)
//              + blacklisted_ip    (attacker IP is on the blacklist)
//              + privileged_account(admin/root/... targeted)
//              + campaign bonus    (alerts of several rule types share an IP/user) , 0, 100 )
// Every contribution is kept in Alert::factors, so a score is always explainable.

#include <optional>
#include <regex>
#include <vector>

#include "loginguard/cidr_trie.hpp"
#include "loginguard/config.hpp"
#include "loginguard/types.hpp"

namespace lg {

Severity severityForScore(int score, const ScoringConfig& cfg);

class Scorer {
public:
    explicit Scorer(const Config& cfg);

    // Fills score, severity, factors and clusterId for every alert.
    // Alerts should be in chronological order (cluster ids follow first appearance).
    void score(std::vector<Alert>& alerts) const;

private:
    bool ipIsBlacklisted(const std::string& ip) const;
    bool ipIsIgnoredForCampaigns(const std::string& ip) const;

    ScoringConfig cfg_;
    CidrTrie blacklist_;
    CidrTrie campaignIgnore_;
    std::optional<std::regex> privileged_;
};

}  // namespace lg
