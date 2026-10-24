#include "loginguard/detector.hpp"

#include <algorithm>
#include <cstdio>

#include "loginguard/util.hpp"

namespace lg {

namespace rules {
const std::string kBruteForce = "brute_force";
const std::string kPasswordSpraying = "password_spraying";
const std::string kDistributedAttack = "distributed_attack";
const std::string kSuccessAfterFailures = "success_after_failures";
const std::string kOffHours = "off_hours_login";
const std::string kBlacklistedIp = "blacklisted_ip";
const std::string kCustomPrefix = "custom:";
}  // namespace rules

namespace {

constexpr int kContextSeconds = 3600;       // drill-down context for rules without a window
constexpr size_t kGcEveryEvents = 1 << 16;  // sweep expired windows every 65536 events
constexpr size_t kMaxPatternCache = 1000000;

std::string joinKey(const std::string& a, const std::string& b) {
    std::string k;
    k.reserve(a.size() + b.size() + 1);
    k += a;
    k += '\x1f';
    k += b;
    return k;
}

}  // namespace

Engine::Engine(Config cfg) : cfg_(std::move(cfg)) {
    for (const auto& entry : cfg_.blacklist) {
        if (!blacklist_.insert(entry)) throw ConfigError("invalid blacklist entry '" + entry + "'");
    }
    for (const auto& p : cfg_.patterns) {
        PatternState st;
        st.cfg = p;
        try {
            st.re = std::regex(p.usernameRegex, std::regex::ECMAScript | std::regex::icase);
        } catch (const std::regex_error& e) {
            throw ConfigError("invalid username_regex in pattern '" + p.name + "': " + e.what());
        }
        patterns_.push_back(std::move(st));
    }
}

void Engine::reset() {
    bf_.clear();
    sa_.clear();
    spray_.clear();
    dist_.clear();
    open_.clear();
    last_.clear();
    alerts_.clear();
    patternCache_.clear();
    for (auto& p : patterns_) p.perUser.clear();
    processed_ = 0;
}

bool Engine::isBusinessHour(int h) const {
    const int s = cfg_.offHours.startHour, e = cfg_.offHours.endHour;
    return s < e ? (h >= s && h < e) : (h >= s || h < e);
}

std::vector<Alert> Engine::run(std::vector<LoginEvent>& events) {
    reset();
    auto byTime = [](const LoginEvent& a, const LoginEvent& b) { return a.ts < b.ts; };
    if (!std::is_sorted(events.begin(), events.end(), byTime)) {
        std::stable_sort(events.begin(), events.end(), byTime);
    }
    for (const LoginEvent& e : events) process(e);
    finalizeDetails();
    std::vector<Alert> out = std::move(alerts_);
    alerts_.clear();
    return out;
}

void Engine::process(const LoginEvent& e) {
    if ((++processed_ & (kGcEveryEvents - 1)) == 0) gc(e.ts);
    if (e.success) onSuccess(e);
    else onFailure(e);
    checkBlacklist(e);
    checkPatterns(e);
}

void Engine::onFailure(const LoginEvent& e) {
    const std::string userIp = joinKey(e.user, e.ip);

    const auto& bf = cfg_.bruteForce;
    if (bf.enabled) {
        TimeWindow& w = bf_[userIp];
        w.expire(e.ts - bf.windowSeconds);
        w.push(e.ts);
        evalThreshold(rules::kBruteForce, userIp, w.size() >= static_cast<size_t>(bf.threshold), w.size(), e,
                      bf.threshold, bf.windowSeconds, bf.weight, e.user, e.ip);
    }

    const auto& sa = cfg_.successAfterFailures;
    if (sa.enabled) {
        TimeWindow& w = sa_[userIp];
        w.expire(e.ts - sa.windowSeconds);
        w.push(e.ts);
    }

    const auto& sp = cfg_.passwordSpraying;
    if (sp.enabled) {
        SlidingDistinct& d = spray_[e.ip];
        d.expire(e.ts - sp.windowSeconds);
        d.add(e.ts, e.user);
        evalThreshold(rules::kPasswordSpraying, e.ip, d.distinct() >= static_cast<size_t>(sp.threshold),
                      d.distinct(), e, sp.threshold, sp.windowSeconds, sp.weight, "", e.ip);
    }

    const auto& di = cfg_.distributedAttack;
    if (di.enabled) {
        SlidingDistinct& d = dist_[e.user];
        d.expire(e.ts - di.windowSeconds);
        d.add(e.ts, e.ip);
        evalThreshold(rules::kDistributedAttack, e.user, d.distinct() >= static_cast<size_t>(di.threshold),
                      d.distinct(), e, di.threshold, di.windowSeconds, di.weight, e.user, "");
    }
}

void Engine::onSuccess(const LoginEvent& e) {
    const auto& sa = cfg_.successAfterFailures;
    if (sa.enabled) {
        const std::string userIp = joinKey(e.user, e.ip);
        auto it = sa_.find(userIp);
        if (it != sa_.end()) {
            it->second.expire(e.ts - sa.windowSeconds);
            const size_t n = it->second.size();
            if (n >= static_cast<size_t>(sa.minFailures)) {
                firePoint(rules::kSuccessAfterFailures, userIp, e, static_cast<int>(n), sa.cooldownSeconds,
                          /*extend=*/false, sa.weight, sa.windowSeconds, "", e.user, e.ip);
            }
            sa_.erase(it);  // a success ends the failure streak
        }
    }

    const auto& oh = cfg_.offHours;
    if (oh.enabled && !isBusinessHour(hourOfDay(e.ts))) {
        // Keyed on (user, ip): a habitual night-time login from the same place is reported once per
        // cooldown, but a night-time login from a NEW IP is always reported.
        firePoint(rules::kOffHours, joinKey(e.user, e.ip), e, 1, oh.cooldownSeconds, /*extend=*/false, oh.weight, 0,
                  "", e.user, e.ip);
    }
}

void Engine::checkBlacklist(const LoginEvent& e) {
    const auto& bl = cfg_.blacklistRule;
    if (!bl.enabled || blacklist_.empty() || !e.hasIp4) return;
    const int idx = blacklist_.match(e.ip4);
    if (idx < 0) return;
    // Failures from one IP form a session; each successful login (a likely
    // compromise) gets its own alert tied to the account.
    std::string key = e.ip;
    key += e.success ? "|S|" + e.user : "|F";
    firePoint(rules::kBlacklistedIp, key, e, 1, bl.gapSeconds, /*extend=*/true, bl.weight, 0, blacklist_.label(idx),
              e.success ? e.user : std::string(), e.ip);
}

bool Engine::matchesPattern(const std::string& user, size_t i) {
    if (patternCache_.size() > kMaxPatternCache) patternCache_.clear();  // bound memory under random-username floods
    std::vector<signed char>& cache = patternCache_[user];
    if (cache.empty()) cache.assign(patterns_.size(), -1);
    signed char& c = cache[i];
    if (c < 0) c = std::regex_search(user, patterns_[i].re) ? 1 : 0;
    return c == 1;
}

void Engine::checkPatterns(const LoginEvent& e) {
    for (size_t i = 0; i < patterns_.size(); ++i) {
        PatternState& p = patterns_[i];
        const auto outcome = p.cfg.outcome;
        if (outcome == CustomPattern::Outcome::Failure && e.success) continue;
        if (outcome == CustomPattern::Outcome::Success && !e.success) continue;
        if (!matchesPattern(e.user, i)) continue;
        TimeWindow& w = p.perUser[e.user];
        w.expire(e.ts - p.cfg.windowSeconds);
        w.push(e.ts);
        evalThreshold(rules::kCustomPrefix + p.cfg.name, e.user, w.size() >= static_cast<size_t>(p.cfg.threshold),
                      w.size(), e, p.cfg.threshold, p.cfg.windowSeconds, p.cfg.weight, e.user, "");
    }
}

void Engine::evalThreshold(const std::string& rule, const std::string& entityKey, bool holds, size_t count,
                           const LoginEvent& e, int threshold, int window, int weight, const std::string& user,
                           const std::string& ip) {
    const std::string key = joinKey(rule, entityKey);
    auto it = open_.find(key);
    if (!holds) {
        if (it != open_.end()) open_.erase(it);  // incident over
        return;
    }
    if (it != open_.end()) {
        Alert& a = alerts_[it->second];
        if (e.ts - a.endTs <= window) {  // still the same incident: extend it
            a.count = std::max(a.count, static_cast<int>(count));
            a.events += 1;
            a.endTs = e.ts;
            return;
        }
        // Stale entry (only possible when the threshold is 1): start a new incident below.
    }
    Alert a;
    a.ts = e.ts;
    a.endTs = e.ts;
    a.windowStart = e.ts - window;
    a.rule = rule;
    a.user = user;
    a.ip = ip;
    a.count = static_cast<int>(count);
    a.events = static_cast<int>(count);
    a.threshold = threshold;
    a.windowSeconds = window;
    a.baseWeight = weight;
    a.successEvent = e.success;
    alerts_.push_back(std::move(a));
    open_[key] = alerts_.size() - 1;
}

void Engine::firePoint(const std::string& rule, const std::string& entityKey, const LoginEvent& e, int count,
                       int cooldown, bool extend, int weight, int window, const std::string& extra,
                       const std::string& user, const std::string& ip) {
    const std::string key = joinKey(rule, entityKey);
    auto it = last_.find(key);
    if (it != last_.end()) {
        Alert& a = alerts_[it->second];
        if (extend) {
            if (e.ts - a.endTs <= cooldown) {  // same activity session
                a.endTs = e.ts;
                a.count += count;
                a.events += count;
                return;
            }
        } else if (e.ts - a.ts < cooldown) {  // duplicate inside the cooldown
            return;
        }
    }
    Alert a;
    a.ts = e.ts;
    a.endTs = e.ts;
    a.windowStart = e.ts - (window > 0 ? window : kContextSeconds);
    a.rule = rule;
    a.user = user;
    a.ip = ip;
    a.count = count;
    a.events = count;
    a.threshold = 0;
    a.windowSeconds = window;
    a.baseWeight = weight;
    a.successEvent = e.success;
    a.extra = extra;
    alerts_.push_back(std::move(a));
    last_[key] = alerts_.size() - 1;
}

void Engine::gc(int64_t now) {
    // A window whose newest event is older than `now - window` is fully expired,
    // so dropping it is equivalent to expiring all of its elements.
    auto sweep = [now](auto& m, int window) {
        const int64_t cutoff = now - window;
        for (auto it = m.begin(); it != m.end();) {
            if (it->second.newest() < cutoff) it = m.erase(it);
            else ++it;
        }
    };
    sweep(bf_, cfg_.bruteForce.windowSeconds);
    sweep(sa_, cfg_.successAfterFailures.windowSeconds);
    sweep(spray_, cfg_.passwordSpraying.windowSeconds);
    sweep(dist_, cfg_.distributedAttack.windowSeconds);
    for (auto& p : patterns_) sweep(p.perUser, p.cfg.windowSeconds);
}

std::string Engine::describe(const Alert& a) const {
    char buf[64];
    const std::string& r = a.rule;
    std::string s;
    if (r == rules::kBruteForce) {
        s = std::to_string(a.events) + " failed logins for '" + a.user + "' from " + a.ip + " (peak " +
            std::to_string(a.count) + " within " + std::to_string(a.windowSeconds) + "s, threshold " +
            std::to_string(a.threshold) + ")";
    } else if (r == rules::kPasswordSpraying) {
        s = "IP " + a.ip + " failed against " + std::to_string(a.count) + " distinct accounts within " +
            std::to_string(a.windowSeconds) + "s (threshold " + std::to_string(a.threshold) + "); " +
            std::to_string(a.events) + " failed attempts in total";
    } else if (r == rules::kDistributedAttack) {
        s = "Account '" + a.user + "' failed from " + std::to_string(a.count) + " distinct IPs within " +
            std::to_string(a.windowSeconds) + "s (threshold " + std::to_string(a.threshold) + "); " +
            std::to_string(a.events) + " failed attempts in total";
    } else if (r == rules::kSuccessAfterFailures) {
        s = "Successful login for '" + a.user + "' from " + a.ip + " after " + std::to_string(a.count) +
            " failed attempts in the previous " + std::to_string(a.windowSeconds) + "s";
    } else if (r == rules::kOffHours) {
        std::snprintf(buf, sizeof buf, "%02d:00-%02d:00", cfg_.offHours.startHour, cfg_.offHours.endHour);
        s = "Successful login for '" + a.user + "' from " + a.ip + " at " + formatTimestamp(a.ts).substr(11, 5) +
            ", outside business hours (" + buf + ")";
    } else if (r == rules::kBlacklistedIp) {
        s = std::to_string(a.events) + (a.successEvent ? " successful" : " failed") + " login attempt" +
            (a.events == 1 ? "" : "s") + " from " + a.ip + ", inside blacklisted range " + a.extra;
        if (a.successEvent && !a.user.empty()) s += " (account '" + a.user + "')";
    } else if (r.compare(0, rules::kCustomPrefix.size(), rules::kCustomPrefix) == 0) {
        const std::string name = r.substr(rules::kCustomPrefix.size());
        const char* outcome = "login";
        for (const auto& p : cfg_.patterns) {
            if (p.name == name) {
                outcome = p.outcome == CustomPattern::Outcome::Failure   ? "failed login"
                          : p.outcome == CustomPattern::Outcome::Success ? "successful login"
                                                                         : "login";
            }
        }
        s = std::to_string(a.events) + " " + outcome + " events for '" + a.user + "' matching pattern '" + name +
            "' (peak " + std::to_string(a.count) + " within " + std::to_string(a.windowSeconds) + "s, threshold " +
            std::to_string(a.threshold) + ")";
    } else {
        s = r;
    }
    return s;
}

void Engine::finalizeDetails() {
    for (Alert& a : alerts_) a.detail = describe(a);
}

}  // namespace lg
