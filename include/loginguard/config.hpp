#pragma once
// Detection / scoring configuration. Every threshold is configurable via a JSON
// file (comments allowed). `Config{}` is a complete, valid default configuration.

#include <nlohmann/json_fwd.hpp>

#include <stdexcept>
#include <string>
#include <vector>

namespace lg {

class ConfigError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Rules that fire when a count inside a sliding window reaches a threshold.
struct ThresholdRule {
    bool enabled = true;
    int threshold = 0;
    int windowSeconds = 0;
    int weight = 0;
};

struct SuccessAfterFailuresRule {
    bool enabled = true;
    int minFailures = 4;
    int windowSeconds = 600;
    int cooldownSeconds = 600;
    int weight = 45;  // ambiguous alone (forgotten password), strong together with a brute-force alert
};

struct OffHoursRule {
    bool enabled = true;
    int startHour = 7;  // business hours are [startHour, endHour); wrap-around allowed (22 -> 6)
    int endHour = 20;
    int cooldownSeconds = 86400;
    int weight = 15;
};

struct BlacklistRule {
    bool enabled = true;
    int gapSeconds = 3600;  // activity separated by less than this belongs to one alert
    int weight = 35;
};

// User-defined "high-risk pattern": usernames matching a regex that produce
// >= threshold events of a given outcome within a window.
struct CustomPattern {
    enum class Outcome { Failure, Success, Any };
    std::string name;
    std::string usernameRegex;  // matched with regex_search (use ^ and $ to anchor)
    Outcome outcome = Outcome::Failure;
    int threshold = 3;
    int windowSeconds = 300;
    int weight = 50;
};

struct ScoringConfig {
    std::string privilegedRegex = "^(admin|root|administrator)$";  // "" disables the bonus
    int privilegedBonus = 10;
    int blacklistBonus = 10;         // alert involves a blacklisted IP (rule != blacklisted_ip)
    int blacklistSuccessBonus = 25;  // successful login from a blacklisted IP
    int volumeStep = 2;              // +step points per unit above the threshold ...
    int volumeCap = 20;              // ... capped here
    int campaignBonusPerRule = 5;    // per extra distinct rule inside the same campaign ...
    int campaignBonusMax = 15;       // ... capped here
    int campaignWindowSeconds = 86400;  // an IP/user quiet for longer than this starts a NEW campaign
    // Shared egress addresses (office NAT, VPN, loopback) are NOT attacker identities: linking
    // alerts through them would glue unrelated users into one giant "campaign".
    std::vector<std::string> campaignIgnoreCidrs = {"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                                                    "127.0.0.0/8", "169.254.0.0/16"};
    int mediumMin = 30;
    int highMin = 60;
    int criticalMin = 80;
};

struct Config {
    ThresholdRule bruteForce{true, 5, 300, 40};        // threshold = failures per (user, ip)
    ThresholdRule passwordSpraying{true, 6, 600, 50};  // threshold = distinct usernames per ip
    ThresholdRule distributedAttack{true, 4, 600, 45}; // threshold = distinct ips per username
    SuccessAfterFailuresRule successAfterFailures;
    OffHoursRule offHours;
    BlacklistRule blacklistRule;
    std::vector<std::string> blacklist = {"203.0.113.0/24", "198.51.100.0/24", "192.0.2.77"};
    std::vector<CustomPattern> patterns = {
        CustomPattern{"privileged_account_failures", "^(admin|root|administrator)$",
                      CustomPattern::Outcome::Failure, 3, 300, 55}};
    ScoringConfig scoring;

    std::vector<std::string> warnings;  // e.g. unknown keys; filled by parseConfig
};

// Throws ConfigError with a precise message on invalid input.
Config parseConfig(const nlohmann::json& doc);
Config loadConfigFile(const std::string& path);
nlohmann::json configToJson(const Config& cfg);

}  // namespace lg
