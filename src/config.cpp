#include "loginguard/config.hpp"

#include <nlohmann/json.hpp>

#include <cctype>
#include <fstream>
#include <initializer_list>
#include <regex>
#include <set>
#include <string_view>
#include <type_traits>

#include "loginguard/util.hpp"

#include "loginguard/cidr_trie.hpp"

namespace lg {

using json = nlohmann::json;

namespace {

constexpr int kMaxWindowSeconds = 30 * 86400;
constexpr int kMaxThreshold = 1000000;

const json& emptyObject() {
    static const json e = json::object();
    return e;
}

const json& section(const json& parent, const char* key, std::string_view parentPath) {
    auto it = parent.find(key);
    if (it == parent.end() || it->is_null()) return emptyObject();
    if (!it->is_object()) {
        throw ConfigError("config: '" + std::string(parentPath) + (parentPath.empty() ? "" : ".") + key +
                          "' must be an object");
    }
    return *it;
}

void warnUnknown(const json& obj, std::initializer_list<const char*> allowed, const std::string& path,
                 std::vector<std::string>& warnings) {
    std::set<std::string> ok(allowed.begin(), allowed.end());
    for (auto it = obj.begin(); it != obj.end(); ++it) {
        if (!ok.count(it.key())) {
            warnings.push_back("unknown config key '" + (path.empty() ? "" : path + ".") + it.key() +
                               "' (ignored)");
        }
    }
}

template <typename T>
T get(const json& obj, const char* key, T def, const std::string& path) {
    auto it = obj.find(key);
    if (it == obj.end() || it->is_null()) return def;
    const std::string full = "config: '" + (path.empty() ? "" : path + ".") + key + "'";
    if constexpr (std::is_same_v<T, int>) {
        if (!it->is_number_integer()) throw ConfigError(full + " must be an integer");
    } else if constexpr (std::is_same_v<T, bool>) {
        if (!it->is_boolean()) throw ConfigError(full + " must be true or false");
    } else if constexpr (std::is_same_v<T, std::string>) {
        if (!it->is_string()) throw ConfigError(full + " must be a string");
    }
    try {
        return it->get<T>();
    } catch (const json::exception&) {
        throw ConfigError(full + " has the wrong type or is out of range");
    }
}

void requireRange(int value, int lo, int hi, const std::string& what) {
    if (value < lo || value > hi) {
        throw ConfigError("config: '" + what + "' must be between " + std::to_string(lo) + " and " +
                          std::to_string(hi) + " (got " + std::to_string(value) + ")");
    }
}

void validateRegex(const std::string& pattern, const std::string& what) {
    try {
        std::regex re(pattern);
        (void)re;
    } catch (const std::regex_error& e) {
        throw ConfigError("config: '" + what + "' is not a valid regular expression: " + e.what());
    }
}

void parseThresholdRule(const json& rules, const char* name, const char* thresholdKey, ThresholdRule& r,
                        std::vector<std::string>& warnings) {
    const std::string path = std::string("rules.") + name;
    const json& o = section(rules, name, "rules");
    warnUnknown(o, {"enabled", thresholdKey, "window_seconds", "weight"}, path, warnings);
    r.enabled = get<bool>(o, "enabled", r.enabled, path);
    r.threshold = get<int>(o, thresholdKey, r.threshold, path);
    r.windowSeconds = get<int>(o, "window_seconds", r.windowSeconds, path);
    r.weight = get<int>(o, "weight", r.weight, path);
    requireRange(r.threshold, 1, kMaxThreshold, path + "." + thresholdKey);
    requireRange(r.windowSeconds, 1, kMaxWindowSeconds, path + ".window_seconds");
    requireRange(r.weight, 0, 100, path + ".weight");
}

}  // namespace

Config parseConfig(const json& doc) {
    if (!doc.is_object()) throw ConfigError("config: top level must be a JSON object");
    Config cfg;
    auto& warn = cfg.warnings;
    warnUnknown(doc, {"business_hours", "rules", "blacklist", "custom_patterns", "scoring", "severity"}, "", warn);

    // ---- rules
    const json& rules = section(doc, "rules", "");
    warnUnknown(rules,
                {"brute_force", "password_spraying", "distributed_attack", "success_after_failures",
                 "off_hours_login", "blacklisted_ip"},
                "rules", warn);
    parseThresholdRule(rules, "brute_force", "max_failures", cfg.bruteForce, warn);
    parseThresholdRule(rules, "password_spraying", "distinct_users", cfg.passwordSpraying, warn);
    parseThresholdRule(rules, "distributed_attack", "distinct_ips", cfg.distributedAttack, warn);

    {
        const std::string path = "rules.success_after_failures";
        const json& o = section(rules, "success_after_failures", "rules");
        warnUnknown(o, {"enabled", "min_failures", "window_seconds", "cooldown_seconds", "weight"}, path, warn);
        auto& r = cfg.successAfterFailures;
        r.enabled = get<bool>(o, "enabled", r.enabled, path);
        r.minFailures = get<int>(o, "min_failures", r.minFailures, path);
        r.windowSeconds = get<int>(o, "window_seconds", r.windowSeconds, path);
        r.cooldownSeconds = get<int>(o, "cooldown_seconds", r.cooldownSeconds, path);
        r.weight = get<int>(o, "weight", r.weight, path);
        requireRange(r.minFailures, 1, kMaxThreshold, path + ".min_failures");
        requireRange(r.windowSeconds, 1, kMaxWindowSeconds, path + ".window_seconds");
        requireRange(r.cooldownSeconds, 0, kMaxWindowSeconds, path + ".cooldown_seconds");
        requireRange(r.weight, 0, 100, path + ".weight");
    }
    {
        const std::string path = "rules.off_hours_login";
        const json& o = section(rules, "off_hours_login", "rules");
        warnUnknown(o, {"enabled", "cooldown_seconds", "weight"}, path, warn);
        auto& r = cfg.offHours;
        r.enabled = get<bool>(o, "enabled", r.enabled, path);
        r.cooldownSeconds = get<int>(o, "cooldown_seconds", r.cooldownSeconds, path);
        r.weight = get<int>(o, "weight", r.weight, path);
        requireRange(r.cooldownSeconds, 0, kMaxWindowSeconds, path + ".cooldown_seconds");
        requireRange(r.weight, 0, 100, path + ".weight");
    }
    {
        const std::string path = "rules.blacklisted_ip";
        const json& o = section(rules, "blacklisted_ip", "rules");
        warnUnknown(o, {"enabled", "gap_seconds", "weight"}, path, warn);
        auto& r = cfg.blacklistRule;
        r.enabled = get<bool>(o, "enabled", r.enabled, path);
        r.gapSeconds = get<int>(o, "gap_seconds", r.gapSeconds, path);
        r.weight = get<int>(o, "weight", r.weight, path);
        requireRange(r.gapSeconds, 0, kMaxWindowSeconds, path + ".gap_seconds");
        requireRange(r.weight, 0, 100, path + ".weight");
    }

    // ---- business hours
    {
        const json& o = section(doc, "business_hours", "");
        warnUnknown(o, {"start", "end"}, "business_hours", warn);
        cfg.offHours.startHour = get<int>(o, "start", cfg.offHours.startHour, "business_hours");
        cfg.offHours.endHour = get<int>(o, "end", cfg.offHours.endHour, "business_hours");
        requireRange(cfg.offHours.startHour, 0, 23, "business_hours.start");
        requireRange(cfg.offHours.endHour, 0, 23, "business_hours.end");
        if (cfg.offHours.startHour == cfg.offHours.endHour) {
            throw ConfigError("config: 'business_hours.start' and 'business_hours.end' must differ");
        }
    }

    // ---- blacklist
    if (doc.contains("blacklist") && !doc["blacklist"].is_null()) {
        const json& arr = doc["blacklist"];
        if (!arr.is_array()) throw ConfigError("config: 'blacklist' must be an array of CIDR strings");
        cfg.blacklist.clear();
        CidrTrie probe;
        for (const auto& item : arr) {
            if (!item.is_string()) throw ConfigError("config: every 'blacklist' entry must be a string");
            std::string s = item.get<std::string>();
            if (!probe.insert(s)) {
                throw ConfigError("config: invalid blacklist entry '" + s + "' (expected a.b.c.d or a.b.c.d/len)");
            }
            cfg.blacklist.push_back(trim(s));
        }
    }

    // ---- custom patterns
    if (doc.contains("custom_patterns") && !doc["custom_patterns"].is_null()) {
        const json& arr = doc["custom_patterns"];
        if (!arr.is_array()) throw ConfigError("config: 'custom_patterns' must be an array");
        cfg.patterns.clear();
        std::set<std::string> names;
        size_t idx = 0;
        for (const auto& o : arr) {
            const std::string path = "custom_patterns[" + std::to_string(idx++) + "]";
            if (!o.is_object()) throw ConfigError("config: '" + path + "' must be an object");
            warnUnknown(o, {"name", "username_regex", "outcome", "threshold", "window_seconds", "weight"}, path,
                        warn);
            CustomPattern p;
            p.name = get<std::string>(o, "name", "", path);
            p.usernameRegex = get<std::string>(o, "username_regex", "", path);
            std::string outcome = get<std::string>(o, "outcome", "failure", path);
            p.threshold = get<int>(o, "threshold", p.threshold, path);
            p.windowSeconds = get<int>(o, "window_seconds", p.windowSeconds, path);
            p.weight = get<int>(o, "weight", p.weight, path);

            if (p.name.empty()) throw ConfigError("config: '" + path + ".name' is required");
            for (char c : p.name) {
                if (!(std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '-')) {
                    throw ConfigError("config: '" + path + ".name' may only contain letters, digits, '_' and '-'");
                }
            }
            if (!names.insert(p.name).second) throw ConfigError("config: duplicate pattern name '" + p.name + "'");
            if (p.usernameRegex.empty()) throw ConfigError("config: '" + path + ".username_regex' is required");
            validateRegex(p.usernameRegex, path + ".username_regex");
            if (outcome == "failure") p.outcome = CustomPattern::Outcome::Failure;
            else if (outcome == "success") p.outcome = CustomPattern::Outcome::Success;
            else if (outcome == "any") p.outcome = CustomPattern::Outcome::Any;
            else throw ConfigError("config: '" + path + ".outcome' must be \"failure\", \"success\" or \"any\"");
            requireRange(p.threshold, 1, kMaxThreshold, path + ".threshold");
            requireRange(p.windowSeconds, 1, kMaxWindowSeconds, path + ".window_seconds");
            requireRange(p.weight, 0, 100, path + ".weight");
            cfg.patterns.push_back(std::move(p));
        }
    }

    // ---- scoring
    {
        const json& o = section(doc, "scoring", "");
        warnUnknown(o,
                    {"privileged_regex", "privileged_bonus", "blacklist_bonus", "blacklist_success_bonus",
                     "volume_step", "volume_cap", "campaign_bonus_per_rule", "campaign_bonus_max",
                     "campaign_window_seconds", "campaign_ignore_cidrs"},
                    "scoring", warn);
        auto& s = cfg.scoring;
        s.privilegedRegex = get<std::string>(o, "privileged_regex", s.privilegedRegex, "scoring");
        s.privilegedBonus = get<int>(o, "privileged_bonus", s.privilegedBonus, "scoring");
        s.blacklistBonus = get<int>(o, "blacklist_bonus", s.blacklistBonus, "scoring");
        s.blacklistSuccessBonus = get<int>(o, "blacklist_success_bonus", s.blacklistSuccessBonus, "scoring");
        s.volumeStep = get<int>(o, "volume_step", s.volumeStep, "scoring");
        s.volumeCap = get<int>(o, "volume_cap", s.volumeCap, "scoring");
        s.campaignBonusPerRule = get<int>(o, "campaign_bonus_per_rule", s.campaignBonusPerRule, "scoring");
        s.campaignBonusMax = get<int>(o, "campaign_bonus_max", s.campaignBonusMax, "scoring");
        s.campaignWindowSeconds = get<int>(o, "campaign_window_seconds", s.campaignWindowSeconds, "scoring");
        requireRange(s.campaignWindowSeconds, 1, kMaxWindowSeconds, "scoring.campaign_window_seconds");
        if (o.contains("campaign_ignore_cidrs") && !o["campaign_ignore_cidrs"].is_null()) {
            const json& arr = o["campaign_ignore_cidrs"];
            if (!arr.is_array()) throw ConfigError("config: 'scoring.campaign_ignore_cidrs' must be an array");
            s.campaignIgnoreCidrs.clear();
            CidrTrie probe;
            for (const auto& item : arr) {
                if (!item.is_string()) throw ConfigError("config: every 'scoring.campaign_ignore_cidrs' entry must be a string");
                std::string entry = item.get<std::string>();
                if (!probe.insert(entry)) {
                    throw ConfigError("config: invalid 'scoring.campaign_ignore_cidrs' entry '" + entry + "'");
                }
                s.campaignIgnoreCidrs.push_back(trim(entry));
            }
        }
        if (!s.privilegedRegex.empty()) validateRegex(s.privilegedRegex, "scoring.privileged_regex");
        requireRange(s.privilegedBonus, 0, 100, "scoring.privileged_bonus");
        requireRange(s.blacklistBonus, 0, 100, "scoring.blacklist_bonus");
        requireRange(s.blacklistSuccessBonus, 0, 100, "scoring.blacklist_success_bonus");
        requireRange(s.volumeStep, 0, 100, "scoring.volume_step");
        requireRange(s.volumeCap, 0, 100, "scoring.volume_cap");
        requireRange(s.campaignBonusPerRule, 0, 100, "scoring.campaign_bonus_per_rule");
        requireRange(s.campaignBonusMax, 0, 100, "scoring.campaign_bonus_max");
    }

    // ---- severity bands
    {
        const json& o = section(doc, "severity", "");
        warnUnknown(o, {"medium", "high", "critical"}, "severity", warn);
        auto& s = cfg.scoring;
        s.mediumMin = get<int>(o, "medium", s.mediumMin, "severity");
        s.highMin = get<int>(o, "high", s.highMin, "severity");
        s.criticalMin = get<int>(o, "critical", s.criticalMin, "severity");
        if (!(0 < s.mediumMin && s.mediumMin < s.highMin && s.highMin < s.criticalMin && s.criticalMin <= 100)) {
            throw ConfigError("config: severity bands must satisfy 0 < medium < high < critical <= 100");
        }
    }
    return cfg;
}

Config loadConfigFile(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw ConfigError("config: cannot open '" + path + "'");
    json doc;
    try {
        doc = json::parse(in, nullptr, /*allow_exceptions=*/true, /*ignore_comments=*/true);
    } catch (const json::parse_error& e) {
        throw ConfigError(std::string("config: invalid JSON in '") + path + "': " + e.what());
    }
    return parseConfig(doc);
}

json configToJson(const Config& c) {
    json j;
    j["business_hours"] = {{"start", c.offHours.startHour}, {"end", c.offHours.endHour}};
    j["rules"]["brute_force"] = {{"enabled", c.bruteForce.enabled},
                                 {"max_failures", c.bruteForce.threshold},
                                 {"window_seconds", c.bruteForce.windowSeconds},
                                 {"weight", c.bruteForce.weight}};
    j["rules"]["password_spraying"] = {{"enabled", c.passwordSpraying.enabled},
                                       {"distinct_users", c.passwordSpraying.threshold},
                                       {"window_seconds", c.passwordSpraying.windowSeconds},
                                       {"weight", c.passwordSpraying.weight}};
    j["rules"]["distributed_attack"] = {{"enabled", c.distributedAttack.enabled},
                                        {"distinct_ips", c.distributedAttack.threshold},
                                        {"window_seconds", c.distributedAttack.windowSeconds},
                                        {"weight", c.distributedAttack.weight}};
    j["rules"]["success_after_failures"] = {{"enabled", c.successAfterFailures.enabled},
                                            {"min_failures", c.successAfterFailures.minFailures},
                                            {"window_seconds", c.successAfterFailures.windowSeconds},
                                            {"cooldown_seconds", c.successAfterFailures.cooldownSeconds},
                                            {"weight", c.successAfterFailures.weight}};
    j["rules"]["off_hours_login"] = {{"enabled", c.offHours.enabled},
                                     {"cooldown_seconds", c.offHours.cooldownSeconds},
                                     {"weight", c.offHours.weight}};
    j["rules"]["blacklisted_ip"] = {{"enabled", c.blacklistRule.enabled},
                                    {"gap_seconds", c.blacklistRule.gapSeconds},
                                    {"weight", c.blacklistRule.weight}};
    j["blacklist"] = c.blacklist;
    j["custom_patterns"] = json::array();
    for (const auto& p : c.patterns) {
        const char* outcome = p.outcome == CustomPattern::Outcome::Failure   ? "failure"
                              : p.outcome == CustomPattern::Outcome::Success ? "success"
                                                                             : "any";
        j["custom_patterns"].push_back({{"name", p.name},
                                        {"username_regex", p.usernameRegex},
                                        {"outcome", outcome},
                                        {"threshold", p.threshold},
                                        {"window_seconds", p.windowSeconds},
                                        {"weight", p.weight}});
    }
    const auto& s = c.scoring;
    j["scoring"] = {{"privileged_regex", s.privilegedRegex},
                    {"privileged_bonus", s.privilegedBonus},
                    {"blacklist_bonus", s.blacklistBonus},
                    {"blacklist_success_bonus", s.blacklistSuccessBonus},
                    {"volume_step", s.volumeStep},
                    {"volume_cap", s.volumeCap},
                    {"campaign_bonus_per_rule", s.campaignBonusPerRule},
                    {"campaign_bonus_max", s.campaignBonusMax},
                    {"campaign_window_seconds", s.campaignWindowSeconds},
                    {"campaign_ignore_cidrs", s.campaignIgnoreCidrs}};
    j["severity"] = {{"medium", s.mediumMin}, {"high", s.highMin}, {"critical", s.criticalMin}};
    return j;
}

}  // namespace lg
