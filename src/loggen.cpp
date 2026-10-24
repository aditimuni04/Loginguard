#include "loginguard/loggen.hpp"

#include <algorithm>
#include <cmath>
#include <fstream>
#include <map>
#include <random>
#include <set>


#include "loginguard/util.hpp"

namespace lg {

namespace {

// std::mt19937_64's output sequence is fixed by the standard, unlike the
// <random> distributions, so we derive everything from raw output ourselves.
class Rng {
public:
    explicit Rng(uint64_t seed) : eng_(seed) {}
    uint64_t next() { return eng_(); }
    int64_t range(int64_t lo, int64_t hi) {  // inclusive
        if (hi <= lo) return lo;
        return lo + static_cast<int64_t>(next() % static_cast<uint64_t>(hi - lo + 1));
    }
    double unit() { return static_cast<double>(next() >> 11) * (1.0 / 9007199254740992.0); }
    bool chance(double p) { return unit() < p; }
    template <typename T>
    const T& pick(const std::vector<T>& v) {
        return v[static_cast<size_t>(range(0, static_cast<int64_t>(v.size()) - 1))];
    }

private:
    std::mt19937_64 eng_;
};

const std::vector<std::string> kFirst = {
    "aarav", "aditi", "alice", "amit",  "ananya", "arjun", "bob",   "carlos", "chen",  "deepa",  "diego",
    "emma",  "farah", "grace", "hiro",  "isha",   "ivan",  "jack",  "kavya",  "kiran", "liam",   "maya",
    "mohan", "nadia", "neha",  "noah",  "olivia", "omar",  "priya", "rahul",  "raj",   "rohan",  "sara",
    "sofia", "tara",  "uma",   "vikram", "wei",   "yuki",  "zoya",  "ethan",  "lucas", "mia",    "nina",
    "oscar", "paula", "quinn", "ravi",  "sam",    "tina",  "victor", "willa", "xavier", "yara",   "zane"};
const std::vector<std::string> kLast = {
    "sharma", "patel",  "singh",  "kumar",  "gupta",  "reddy",   "iyer",   "nair",   "mehta",  "shah",
    "smith",  "johnson", "brown", "garcia", "miller", "davis",   "lopez",  "wilson", "moore",  "taylor",
    "chen",   "wang",   "li",     "kim",    "tanaka", "sato",    "silva",  "costa",  "rossi",  "muller",
    "novak",  "kowalski", "ivanov", "haddad", "khan",  "ali",     "das",    "bose",   "rao",    "joshi"};

constexpr int kBusinessStart = 8;   // normal users log in between 08:00 and 20:00
constexpr int kBusinessEnd = 20;

struct UserProfile {
    std::string name;
    std::string primaryIp;
    std::string mobileIp;
    double activity = 1.0;  // relative login frequency
    bool privileged = false;
};

std::string randomPublicIp(Rng& r, const std::vector<int>& firstOctets) {
    return std::to_string(firstOctets[static_cast<size_t>(r.range(0, static_cast<int64_t>(firstOctets.size()) - 1))]) +
           "." + std::to_string(r.range(1, 254)) + "." + std::to_string(r.range(1, 254)) + "." +
           std::to_string(r.range(1, 254));
}

LoginEvent makeEvent(int64_t ts, const std::string& user, const std::string& ip, bool success) {
    LoginEvent e;
    e.ts = ts;
    e.user = user;
    e.ip = ip;
    e.success = success;
    e.hasIp4 = parseIpv4(ip, e.ip4);
    return e;
}

int64_t offHoursSecond(Rng& r) {
    // business hours (config default) are 07:00-20:00, so off-hours = 20:00-06:59
    static const int hours[] = {20, 21, 22, 23, 0, 1, 2, 3, 4, 5, 6};
    int h = hours[r.range(0, 10)];
    return h * 3600 + r.range(0, 3599);
}

}  // namespace

GenResult generateLogs(const GenParams& params) {
    GenParams p = params;
    p.users = std::max(5, p.users);
    p.days = std::max(1, p.days);
    p.targetEvents = std::max<int64_t>(1000, p.targetEvents);
    if (p.startTs == 0) parseTimestamp("2026-10-01 00:00:00", p.startTs);
    p.startTs -= p.startTs % 86400;  // align to midnight so hour-of-day maths stays simple

    Rng rng(p.seed);
    GenResult out;
    auto& ev = out.events;

    // ------------------------------------------------------------ users and IPs
    const int offices = std::max(2, static_cast<int>(std::ceil(0.7 * p.users / 40.0)));
    std::vector<std::string> officeIps;
    for (int k = 0; k < offices; ++k) {
        officeIps.push_back("10." + std::to_string(k / 250) + "." + std::to_string(k % 250 + 1) + ".1");
    }
    const std::vector<int> homePrefixes = {49, 59, 103, 106, 117, 122, 157, 182};
    const std::vector<int> attackerPrefixes = {45, 91, 141, 185, 194, 212};

    std::vector<UserProfile> users;
    std::set<std::string> taken = {"admin", "root", "svc_backup"};
    for (int i = 0; i < p.users; ++i) {
        std::string base = rng.pick(kFirst) + "." + rng.pick(kLast);
        std::string name = base;
        for (int n = 2; taken.count(name); ++n) name = base + std::to_string(n);
        taken.insert(name);
        UserProfile u;
        u.name = name;
        u.primaryIp = rng.chance(0.7) ? rng.pick(officeIps) : randomPublicIp(rng, homePrefixes);
        u.mobileIp = randomPublicIp(rng, homePrefixes);
        u.activity = 0.5 + rng.unit();
        users.push_back(std::move(u));
    }
    const size_t regularCount = users.size();
    auto addSpecial = [&](const char* name, const std::string& ip, double activity) {
        UserProfile u;
        u.name = name;
        u.primaryIp = ip;
        u.mobileIp = ip;
        u.activity = activity;
        u.privileged = true;
        users.push_back(std::move(u));
    };
    addSpecial("admin", officeIps[0], 0.05);
    addSpecial("root", officeIps[0], 0.01);

    // ------------------------------------------------------------ background traffic
    std::vector<double> dayFactor(static_cast<size_t>(p.days));
    double factorSum = 0;
    for (int d = 0; d < p.days; ++d) {
        const int64_t dow = ((p.startTs / 86400 + d) + 4) % 7;  // 1970-01-01 was a Thursday; 0 = Sunday
        dayFactor[static_cast<size_t>(d)] = (dow == 0 || dow == 6) ? 0.25 : 1.0;
        factorSum += dayFactor[static_cast<size_t>(d)];
    }
    // ~2.6% extra events come from failed attempts; attacks add a little more.
    const double loginsPerUserDay = (static_cast<double>(p.targetEvents) * 0.96 / 1.026) /
                                    (static_cast<double>(p.users) * factorSum);

    ev.reserve(static_cast<size_t>(p.targetEvents) + 4096);

    for (const UserProfile& u : users) {
        for (int d = 0; d < p.days; ++d) {
            const double expected = loginsPerUserDay * u.activity * dayFactor[static_cast<size_t>(d)];
            int n = static_cast<int>(std::floor(expected));
            if (rng.chance(expected - std::floor(expected))) ++n;
            for (int k = 0; k < n; ++k) {
                int64_t t = p.startTs + static_cast<int64_t>(d) * 86400;
                const bool offHours = !u.privileged && rng.chance(0.001);
                if (offHours) {
                    t += offHoursSecond(rng);
                } else {
                    t += rng.range(kBusinessStart * 3600, kBusinessEnd * 3600 - 1);
                }
                const std::string& ip = rng.chance(0.9) ? u.primaryIp : u.mobileIp;

                // Typo-and-retry: 0..3 failures before the success (<= 2 for privileged
                // accounts so that ordinary behaviour never looks like an attack on them).
                int failures = 0;
                if (rng.chance(0.02)) {
                    const double r = rng.unit();
                    failures = r < 0.75 ? 1 : (r < 0.95 ? 2 : 3);
                    if (u.privileged) failures = std::min(failures, 2);
                }
                const bool gaveUp = failures > 0 && rng.chance(0.03);
                int64_t cursor = t;
                for (int f = 0; f < failures; ++f) {
                    ev.push_back(makeEvent(cursor, u.name, ip, false));
                    cursor += rng.range(4, 40);
                }
                if (!gaveUp) ev.push_back(makeEvent(cursor, u.name, ip, true));
            }
        }
    }
    // svc_backup: a service account that logs in every day at noon.
    for (int d = 0; d < p.days; ++d) {
        ev.push_back(makeEvent(p.startTs + static_cast<int64_t>(d) * 86400 + 12 * 3600, "svc_backup", "10.9.0.5", true));
    }

    // ------------------------------------------------------------ attacks
    const int64_t horizon = static_cast<int64_t>(p.days) * 86400;
    const int scale = std::max(1, p.users / 500);
    std::set<std::string> usedAttackerIps;
    auto attackerIp = [&]() {
        for (;;) {
            std::string ip = randomPublicIp(rng, attackerPrefixes);
            if (usedAttackerIps.insert(ip).second) return ip;
        }
    };
    auto startTime = [&](int64_t maxDuration) {
        return p.startTs + rng.range(0, std::max<int64_t>(0, horizon - maxDuration - 1));
    };
    auto regularUser = [&]() -> const std::string& {
        return users[static_cast<size_t>(rng.range(0, static_cast<int64_t>(regularCount) - 1))].name;
    };
    auto anyUser = [&]() -> const std::string& {
        return users[static_cast<size_t>(rng.range(0, static_cast<int64_t>(users.size()) - 1))].name;
    };
    auto addTruth = [&](const char* type, const std::string& rule, const std::string& user, const std::string& ip,
                        const std::string& actor, int64_t start, int64_t end) {
        TruthAttack t;
        t.type = type;
        t.rule = rule;
        t.user = user;
        t.ip = ip;
        t.actor = actor;
        t.start = start;
        t.end = end;
        out.truth.push_back(std::move(t));
    };

    // 1) brute force, sometimes ending in a successful login (account compromise)
    for (int i = 0; i < std::max(1, p.days) * scale; ++i) {
        const std::string ip = attackerIp();
        const std::string victim = rng.chance(0.1) ? "admin" : regularUser();
        const int n = static_cast<int>(rng.range(12, 150));
        const int64_t base = rng.range(1, 45);  // slow attacks are still caught: 4 gaps <= 4 * 1.5 * 45 < 300s
        int64_t t = startTime(n * base * 2 + 600);
        const int64_t first = t;
        for (int k = 0; k < n; ++k) {
            ev.push_back(makeEvent(t, victim, ip, false));
            if (k + 1 < n) t += rng.range(std::max<int64_t>(1, base / 2), base * 3 / 2);
        }
        addTruth("brute_force", "brute_force", victim, ip, ip, first, t);
        if (rng.chance(0.35)) {
            const int64_t ts = t + rng.range(2, 10);
            ev.push_back(makeEvent(ts, victim, ip, true));
            addTruth("compromised_account", "success_after_failures", victim, ip, ip, t, ts);
        }
    }

    // 2) password spraying: few attempts per account, many accounts, one IP
    for (int i = 0; i < std::max(1, p.days / 2) * scale; ++i) {
        const std::string ip = attackerIp();
        const int64_t pool = static_cast<int64_t>(users.size());
        const int nUsers = static_cast<int>(rng.range(std::min<int64_t>(15, pool), std::min<int64_t>(60, pool)));
        std::set<std::string> chosen;
        while (static_cast<int>(chosen.size()) < nUsers) chosen.insert(anyUser());
        std::vector<std::string> order(chosen.begin(), chosen.end());
        for (size_t k = order.size() - 1; k > 0; --k) {  // Fisher-Yates with our own RNG (platform independent)
            std::swap(order[k], order[static_cast<size_t>(rng.range(0, static_cast<int64_t>(k)))]);
        }
        int64_t t = startTime(nUsers * 2 * 25 + 600);
        const int64_t first = t;
        int64_t last = t;
        for (int pass = 0; pass < 2; ++pass) {
            for (size_t k = 0; k < order.size(); ++k) {
                if (pass == 1 && (k % 2 == 1)) continue;  // second attempt for half of the accounts
                ev.push_back(makeEvent(t, order[k], ip, false));
                last = t;
                t += rng.range(3, 25);
            }
        }
        addTruth("password_spraying", "password_spraying", "", ip, ip, first, last);
    }

    // 3) distributed attack: many IPs, one account, a couple of tries each
    for (int i = 0; i < std::max(1, p.days / 2) * scale; ++i) {
        const std::string victim = rng.chance(0.3) ? "admin" : regularUser();
        const int bots = static_cast<int>(rng.range(8, 25));
        const int64_t t0 = startTime(1200);
        for (int b = 0; b < bots; ++b) {
            const std::string ip = attackerIp();
            const int tries = static_cast<int>(rng.range(1, 2));
            for (int k = 0; k < tries; ++k) ev.push_back(makeEvent(t0 + rng.range(0, 540), victim, ip, false));
        }
        addTruth("distributed_attack", "distributed_attack", victim, "", std::to_string(bots) + " IPs", t0, t0 + 540);
    }

    // 4) activity from blacklisted ranges (matches the default config blacklist)
    for (int i = 0; i < std::max(1, p.days) * scale; ++i) {
        std::string ip;
        switch (rng.range(0, 2)) {
            case 0: ip = "203.0.113." + std::to_string(rng.range(1, 254)); break;
            case 1: ip = "198.51.100." + std::to_string(rng.range(1, 254)); break;
            default: ip = "192.0.2.77"; break;
        }
        const int n = static_cast<int>(rng.range(3, 15));
        int64_t t = startTime(n * 120 + 600);
        const int64_t first = t;
        for (int k = 0; k < n; ++k) {
            const bool ok = rng.chance(0.2);
            ev.push_back(makeEvent(t, ok ? regularUser() : anyUser(), ip, ok));
            if (k + 1 < n) t += rng.range(10, 120);
        }
        addTruth("blacklisted_ip", "blacklisted_ip", "", ip, ip, first, t);
    }

    // 5) off-hours takeover: a lone successful login at night from a new IP
    for (int i = 0; i < std::max(1, p.days) * scale; ++i) {
        const std::string victim = regularUser();
        const int64_t t = p.startTs + rng.range(0, p.days - 1) * 86400 + offHoursSecond(rng);
        const std::string ip = attackerIp();
        ev.push_back(makeEvent(t, victim, ip, true));
        addTruth("off_hours_login", "off_hours_login", victim, ip, ip, t, t);
    }

    // 6) attack on a privileged account: few failures, caught by the custom pattern
    for (int i = 0; i < std::max(1, p.days) * scale; ++i) {
        const std::string ip = attackerIp();
        const std::string victim = rng.chance(0.3) ? "root" : "admin";
        const int n = static_cast<int>(rng.range(3, 4));
        int64_t t = startTime(600);
        const int64_t first = t;
        for (int k = 0; k < n; ++k) {
            ev.push_back(makeEvent(t, victim, ip, false));
            if (k + 1 < n) t += rng.range(10, 50);
        }
        addTruth("privileged_attack", "custom:privileged_account_failures", victim, "", ip, first, t);
    }

    std::stable_sort(ev.begin(), ev.end(), [](const LoginEvent& a, const LoginEvent& b) { return a.ts < b.ts; });
    std::stable_sort(out.truth.begin(), out.truth.end(),
                     [](const TruthAttack& a, const TruthAttack& b) { return a.start < b.start; });
    return out;
}

bool writeLogCsv(const std::string& path, const std::vector<LoginEvent>& events, std::string& error) {
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f) {
        error = "cannot write '" + path + "'";
        return false;
    }
    std::string buffer;
    buffer.reserve(1 << 20);
    buffer += "timestamp,username,ip,status\n";
    for (const LoginEvent& e : events) {
        buffer += formatTimestamp(e.ts);
        buffer += ',';
        buffer += e.user;
        buffer += ',';
        buffer += e.ip;
        buffer += e.success ? ",SUCCESS\n" : ",FAILURE\n";
        if (buffer.size() >= (1 << 20) - 256) {
            f.write(buffer.data(), static_cast<std::streamsize>(buffer.size()));
            buffer.clear();
        }
    }
    f.write(buffer.data(), static_cast<std::streamsize>(buffer.size()));
    f.flush();
    if (!f) {
        error = "write error on '" + path + "'";
        return false;
    }
    return true;
}

}  // namespace lg
