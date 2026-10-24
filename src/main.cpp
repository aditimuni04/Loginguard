// LoginGuard - authentication log analyzer, brute-force / anomaly detector and dashboard.

#include <nlohmann/json.hpp>

#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <filesystem>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "loginguard/analysis.hpp"
#include "loginguard/api.hpp"
#include "loginguard/config.hpp"
#include "loginguard/evaluate.hpp"
#include "loginguard/loggen.hpp"
#include "loginguard/parser.hpp"
#include "loginguard/storage.hpp"
#include "loginguard/topk.hpp"
#include "loginguard/util.hpp"

#ifndef LG_VERSION
#define LG_VERSION "1.0.0"
#endif

namespace fs = std::filesystem;
using namespace lg;
using Clock = std::chrono::steady_clock;

namespace {

double elapsedMs(Clock::time_point a, Clock::time_point b) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

std::string withCommas(int64_t v) {
    std::string s = std::to_string(v < 0 ? -v : v), out;
    for (size_t i = 0; i < s.size(); ++i) {
        if (i && (s.size() - i) % 3 == 0) out += ',';
        out += s[i];
    }
    return v < 0 ? "-" + out : out;
}

void usage() {
    std::printf(
        "LoginGuard %s - detect brute-force and suspicious logins in authentication logs\n"
        "\n"
        "Usage: loginguard <command> [options]\n"
        "\n"
        "Commands\n"
        "  generate   Create a synthetic log with labelled attacks (ground truth)\n"
        "               --out FILE (data/sample_logs.csv)  --events N (100000)  --users N (500)\n"
        "               --days N (7)  --seed N (42)  --start YYYY-MM-DD (2026-10-01)\n"
        "  analyze    Detect, score and store results in SQLite\n"
        "               --logs FILE  [--config FILE (config.json if present)]  [--db FILE (loginguard.db)]\n"
        "               [--truth FILE]  (prints detection recall; auto-detected next to the log)\n"
        "  serve      Start the web dashboard on an analysed database\n"
        "               [--db FILE]  [--port N (8080)]  [--host H (127.0.0.1)]  [--web DIR]\n"
        "  run        analyze + serve in one step (accepts the options of both)\n"
        "  evaluate   Analyse in memory and compare with a ground-truth file\n"
        "               --logs FILE --truth FILE [--config FILE]\n"
        "  bench      Generate, parse and analyse N events and print throughput\n"
        "               [--events N (1000000)] [--users N (5000)] [--days N (14)] [--seed N]\n"
        "  version | help\n"
        "\n"
        "Log format: CSV with columns  timestamp,username,ip,status  (status SUCCESS|FAILURE)\n",
        LG_VERSION);
}

// ------------------------------------------------------------------ argument parsing

struct Args {
    std::string command;
    std::map<std::string, std::string> opts;
    std::string get(const std::string& k, const std::string& def = "") const {
        auto it = opts.find(k);
        return it == opts.end() ? def : it->second;
    }
    bool has(const std::string& k) const { return opts.count(k) > 0; }
};

bool parseArgs(int argc, char** argv, const std::set<std::string>& allowed, Args& args, std::string& err) {
    for (int i = 2; i < argc; ++i) {
        std::string a = argv[i];
        if (a.rfind("--", 0) != 0 || a.size() < 3) {
            err = "unexpected argument '" + a + "'";
            return false;
        }
        std::string key = a.substr(2), value;
        size_t eq = key.find('=');
        if (eq != std::string::npos) {
            value = key.substr(eq + 1);
            key = key.substr(0, eq);
        } else if (i + 1 < argc) {
            value = argv[++i];
        } else {
            err = "option '--" + key + "' needs a value";
            return false;
        }
        if (!allowed.count(key)) {
            err = "unknown option '--" + key + "' for command '" + args.command + "'";
            return false;
        }
        args.opts[key] = value;
    }
    return true;
}

bool toInt(const std::string& s, int64_t lo, int64_t hi, int64_t& out) {
    if (s.empty() || s.size() > 18) return false;
    size_t i = 0;
    bool neg = false;
    if (s[0] == '-') {
        neg = true;
        i = 1;
    }
    if (i >= s.size()) return false;
    int64_t v = 0;
    for (; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') return false;
        v = v * 10 + (s[i] - '0');
    }
    if (neg) v = -v;
    if (v < lo || v > hi) return false;
    out = v;
    return true;
}

bool intOption(const Args& a, const char* name, int64_t def, int64_t lo, int64_t hi, int64_t& out) {
    if (!a.has(name)) {
        out = def;
        return true;
    }
    if (!toInt(a.get(name), lo, hi, out)) {
        std::fprintf(stderr, "error: --%s must be an integer between %lld and %lld\n", name, static_cast<long long>(lo),
                     static_cast<long long>(hi));
        return false;
    }
    return true;
}

// ------------------------------------------------------------------ shared pipeline

bool loadConfig(const std::string& explicitPath, Config& cfg, std::string& usedPath) {
    usedPath.clear();
    try {
        if (!explicitPath.empty()) {
            cfg = loadConfigFile(explicitPath);
            usedPath = explicitPath;
        } else if (fs::exists("config.json")) {
            cfg = loadConfigFile("config.json");
            usedPath = "config.json";
        } else {
            cfg = Config{};
            usedPath = "(built-in defaults)";
        }
    } catch (const ConfigError& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return false;
    }
    for (const auto& w : cfg.warnings) std::fprintf(stderr, "warning: %s\n", w.c_str());
    return true;
}

struct Pipeline {
    Config cfg;
    std::string configPath;
    std::vector<LoginEvent> events;
    ParseReport parse;
    AnalysisResult result;
    double parseMs = 0;
};

// Returns 0 on success, otherwise a process exit code.
int runPipeline(const std::string& logPath, const std::string& configPath, Pipeline& p) {
    if (!loadConfig(configPath, p.cfg, p.configPath)) return 1;
    std::string err;
    auto t0 = Clock::now();
    if (!parseLogFile(logPath, p.events, p.parse, err)) {
        std::fprintf(stderr, "error: %s\n", err.c_str());
        return 1;
    }
    p.parseMs = elapsedMs(t0, Clock::now());
    if (p.parse.malformed > 0) {
        std::fprintf(stderr, "warning: skipped %s malformed line(s); first problems:\n", withCommas(static_cast<int64_t>(p.parse.malformed)).c_str());
        for (const auto& s : p.parse.samples) std::fprintf(stderr, "  %s\n", s.c_str());
    }
    if (p.events.empty()) {
        std::fprintf(stderr, "error: '%s' contains no valid login events (expected: timestamp,username,ip,status)\n",
                     logPath.c_str());
        return 2;
    }
    try {
        p.result = analyzeEvents(p.events, p.cfg);
    } catch (const ConfigError& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
    return 0;
}

void printSummary(const Pipeline& p) {
    int bySev[4] = {0, 0, 0, 0};
    std::map<std::string, int> byRule;
    std::vector<std::pair<std::string, int>> ipScores;
    for (const Alert& a : p.result.alerts) {
        ++bySev[static_cast<int>(a.severity)];
        ++byRule[a.rule];
        if (!a.ip.empty()) ipScores.emplace_back(a.ip, a.score);
    }
    int64_t ok = 0;
    for (const auto& e : p.events) ok += e.success ? 1 : 0;
    const double totalMs = p.parseMs + p.result.detectMs + p.result.scoreMs;

    std::printf("Config            : %s\n", p.configPath.c_str());
    std::printf("Events analysed   : %s  (%s successful, %s failed)\n", withCommas(static_cast<int64_t>(p.events.size())).c_str(),
                withCommas(ok).c_str(), withCommas(static_cast<int64_t>(p.events.size()) - ok).c_str());
    std::printf("Time range        : %s  ->  %s (UTC)\n", formatTimestamp(p.events.front().ts).c_str(),
                formatTimestamp(p.events.back().ts).c_str());
    std::printf("Alerts            : %s  (critical %d, high %d, medium %d, low %d)\n",
                withCommas(static_cast<int64_t>(p.result.alerts.size())).c_str(), bySev[3], bySev[2], bySev[1], bySev[0]);
    for (const auto& [rule, n] : byRule) std::printf("  %-36s %d\n", rule.c_str(), n);

    auto top = rankEntities(ipScores, 5);
    if (!top.empty()) {
        std::printf("Riskiest IPs      :\n");
        for (const auto& e : top) {
            std::printf("  %-18s total risk %4lld   alerts %-3d  max score %d\n", e.key.c_str(),
                        static_cast<long long>(e.totalScore), e.alerts, e.maxScore);
        }
    }
    std::printf("Timing            : parse %.0f ms, detect %.0f ms, score %.0f ms  (%s events/s)\n", p.parseMs,
                p.result.detectMs, p.result.scoreMs,
                withCommas(totalMs > 0 ? static_cast<int64_t>(static_cast<double>(p.events.size()) / (totalMs / 1000.0)) : 0).c_str());
}

std::string defaultTruthPath(const std::string& logPath) {
    fs::path p(logPath);
    p.replace_extension(".truth.json");
    return p.string();
}

void maybeEvaluate(const Pipeline& p, const std::string& truthPath, bool required) {
    std::vector<TruthAttack> truth;
    std::string err;
    if (!fs::exists(truthPath)) {
        if (required) std::fprintf(stderr, "warning: truth file '%s' not found\n", truthPath.c_str());
        return;
    }
    if (!loadTruthJson(truthPath, truth, err)) {
        std::fprintf(stderr, "warning: %s\n", err.c_str());
        return;
    }
    std::printf("\nGround-truth evaluation (%s)\n%s", truthPath.c_str(),
                formatEvalReport(evaluateAlerts(p.result.alerts, truth)).c_str());
}

// Runs the analysis and writes the database. Returns an exit code.
int analyzeToDb(const std::string& logPath, const std::string& configPath, const std::string& dbPath,
                const std::string& truthPath, bool truthRequired) {
    Pipeline p;
    if (int rc = runPipeline(logPath, configPath, p)) return rc;

    const auto t0 = Clock::now();
    try {
        std::error_code ec;
        fs::path parent = fs::path(dbPath).parent_path();
        if (!parent.empty()) fs::create_directories(parent, ec);
        fs::remove(dbPath, ec);
        fs::remove(dbPath + "-journal", ec);

        const double totalMs = p.parseMs + p.result.detectMs + p.result.scoreMs;
        nlohmann::json info = {{"source", fs::path(logPath).filename().string()},
                               {"analyzed_at", formatTimestamp(static_cast<int64_t>(std::time(nullptr)))},
                               {"total_lines", p.parse.totalLines},
                               {"malformed_lines", p.parse.malformed},
                               {"parse_ms", p.parseMs},
                               {"detect_ms", p.result.detectMs},
                               {"score_ms", p.result.scoreMs},
                               {"events_per_sec",
                                totalMs > 0 ? static_cast<double>(p.events.size()) / (totalMs / 1000.0) : 0.0},
                               {"config", configToJson(p.cfg)}};
        Database db(dbPath, /*readOnly=*/false);
        db.load(p.events, p.result.alerts, info);
    } catch (const std::exception& e) {
        std::error_code ec;
        fs::remove(dbPath, ec);  // never leave a half-written database behind
        std::fprintf(stderr, "error: could not write database: %s\n", e.what());
        return 1;
    }
    printSummary(p);
    std::printf("Database          : %s (written in %.0f ms)\n", dbPath.c_str(), elapsedMs(t0, Clock::now()));
    maybeEvaluate(p, truthPath.empty() ? defaultTruthPath(logPath) : truthPath, !truthPath.empty());
    return 0;
}

int serveDb(const std::string& dbPath, const ServerOptions& opt, const std::string& exePath) {
    try {
        if (!fs::exists(dbPath)) {
            std::fprintf(stderr, "error: database '%s' not found - run `loginguard analyze` first\n", dbPath.c_str());
            return 1;
        }
        Database db(dbPath, /*readOnly=*/true);
        db.requireValidSchema();
        ServerOptions o = opt;
        o.webDir = findWebDir(opt.webDir, exePath);
        if (o.webDir.empty()) {
            std::fprintf(stderr,
                         "warning: dashboard folder (web/index.html) not found - only the JSON API is available.\n"
                         "         Run from the project root or pass --web DIR.\n");
        }
        return runServer(db, o);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "error: %s\n", e.what());
        return 1;
    }
}

void onSignal(int) { requestStop(); }

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        usage();
        return 2;
    }
    Args args;
    args.command = argv[1];
    const std::string& cmd = args.command;
    if (cmd == "help" || cmd == "--help" || cmd == "-h") {
        usage();
        return 0;
    }
    if (cmd == "version" || cmd == "--version") {
        std::printf("loginguard %s\n", LG_VERSION);
        return 0;
    }

    static const std::map<std::string, std::set<std::string>> kAllowed = {
        {"generate", {"out", "events", "users", "days", "seed", "start"}},
        {"analyze", {"logs", "config", "db", "truth"}},
        {"serve", {"db", "port", "host", "web"}},
        {"run", {"logs", "config", "db", "truth", "port", "host", "web"}},
        {"evaluate", {"logs", "truth", "config"}},
        {"bench", {"events", "users", "days", "seed", "config"}}};
    auto allowed = kAllowed.find(cmd);
    if (allowed == kAllowed.end()) {
        std::fprintf(stderr, "error: unknown command '%s'\n\n", cmd.c_str());
        usage();
        return 2;
    }
    std::string err;
    if (!parseArgs(argc, argv, allowed->second, args, err)) {
        std::fprintf(stderr, "error: %s\n(see `loginguard help`)\n", err.c_str());
        return 2;
    }
    std::signal(SIGINT, onSignal);
    std::signal(SIGTERM, onSignal);

    // ---------------------------------------------------------------- generate
    if (cmd == "generate") {
        GenParams gp;
        int64_t seed, events, users, days;
        if (!intOption(args, "seed", 42, 0, INT64_MAX / 2, seed) || !intOption(args, "events", 100000, 1000, 50000000, events) ||
            !intOption(args, "users", 500, 5, 1000000, users) || !intOption(args, "days", 7, 1, 365, days)) {
            return 2;
        }
        gp.seed = static_cast<uint64_t>(seed);
        gp.targetEvents = events;
        gp.users = static_cast<int>(users);
        gp.days = static_cast<int>(days);
        if (args.has("start")) {
            int64_t ts = 0;
            if (!parseTimestamp(args.get("start") + (args.get("start").size() == 10 ? " 00:00:00" : ""), ts)) {
                std::fprintf(stderr, "error: --start must look like YYYY-MM-DD\n");
                return 2;
            }
            gp.startTs = ts;
        }
        const std::string out = args.get("out", "data/sample_logs.csv");
        std::error_code ec;
        fs::path parent = fs::path(out).parent_path();
        if (!parent.empty()) fs::create_directories(parent, ec);

        auto t0 = Clock::now();
        GenResult g = generateLogs(gp);
        if (!writeLogCsv(out, g.events, err)) {
            std::fprintf(stderr, "error: %s\n", err.c_str());
            return 1;
        }
        const std::string truthPath = defaultTruthPath(out);
        if (!writeTruthJson(truthPath, g.truth, err)) {
            std::fprintf(stderr, "error: %s\n", err.c_str());
            return 1;
        }
        std::map<std::string, int> byType;
        for (const auto& t : g.truth) ++byType[t.type];
        std::printf("Wrote %s events to %s  (%.0f ms)\n", withCommas(static_cast<int64_t>(g.events.size())).c_str(), out.c_str(),
                    elapsedMs(t0, Clock::now()));
        std::printf("Wrote %zu labelled attacks to %s\n", g.truth.size(), truthPath.c_str());
        for (const auto& [type, n] : byType) std::printf("  %-24s %d\n", type.c_str(), n);
        return 0;
    }

    // ---------------------------------------------------------------- analyze / run / evaluate
    if (cmd == "analyze" || cmd == "run" || cmd == "evaluate") {
        if (!args.has("logs")) {
            std::fprintf(stderr, "error: --logs FILE is required\n");
            return 2;
        }
        if (cmd == "evaluate") {
            if (!args.has("truth")) {
                std::fprintf(stderr, "error: --truth FILE is required\n");
                return 2;
            }
            Pipeline p;
            if (int rc = runPipeline(args.get("logs"), args.get("config"), p)) return rc;
            printSummary(p);
            maybeEvaluate(p, args.get("truth"), true);
            return 0;
        }
        const std::string db = args.get("db", "loginguard.db");
        int rc = analyzeToDb(args.get("logs"), args.get("config"), db, args.get("truth"), args.has("truth"));
        if (rc != 0 || cmd == "analyze") return rc;
        // fall through to serving for `run`
        ServerOptions opt;
        int64_t port;
        if (!intOption(args, "port", 8080, 1, 65535, port)) return 2;
        opt.port = static_cast<int>(port);
        opt.host = args.get("host", "127.0.0.1");
        opt.webDir = args.get("web");
        std::printf("\n");
        return serveDb(db, opt, argv[0]);
    }

    // ---------------------------------------------------------------- serve
    if (cmd == "serve") {
        ServerOptions opt;
        int64_t port;
        if (!intOption(args, "port", 8080, 1, 65535, port)) return 2;
        opt.port = static_cast<int>(port);
        opt.host = args.get("host", "127.0.0.1");
        opt.webDir = args.get("web");
        return serveDb(args.get("db", "loginguard.db"), opt, argv[0]);
    }

    // ---------------------------------------------------------------- bench
    if (cmd == "bench") {
        int64_t events, users, days, seed;
        if (!intOption(args, "events", 1000000, 1000, 50000000, events) || !intOption(args, "users", 5000, 5, 1000000, users) ||
            !intOption(args, "days", 14, 1, 365, days) || !intOption(args, "seed", 7, 0, INT64_MAX / 2, seed)) {
            return 2;
        }
        Config cfg;
        std::string used;
        if (!loadConfig(args.get("config"), cfg, used)) return 1;

        GenParams gp;
        gp.seed = static_cast<uint64_t>(seed);
        gp.targetEvents = events;
        gp.users = static_cast<int>(users);
        gp.days = static_cast<int>(days);
        auto t0 = Clock::now();
        GenResult g = generateLogs(gp);
        const double genMs = elapsedMs(t0, Clock::now());

        const std::string tmp = (fs::temp_directory_path() / "loginguard_bench.csv").string();
        if (!writeLogCsv(tmp, g.events, err)) {
            std::fprintf(stderr, "error: %s\n", err.c_str());
            return 1;
        }
        std::vector<LoginEvent> parsed;
        ParseReport rep;
        t0 = Clock::now();
        if (!parseLogFile(tmp, parsed, rep, err)) {
            std::fprintf(stderr, "error: %s\n", err.c_str());
            return 1;
        }
        const double parseMs = elapsedMs(t0, Clock::now());
        const auto bytes = static_cast<double>(fs::file_size(tmp));
        std::error_code ec;
        fs::remove(tmp, ec);

        AnalysisResult res;
        try {
            res = analyzeEvents(parsed, cfg);
        } catch (const ConfigError& e) {
            std::fprintf(stderr, "error: %s\n", e.what());
            return 1;
        }
        const EvalReport ev = evaluateAlerts(res.alerts, g.truth);
        const double n = static_cast<double>(parsed.size());
        std::printf("Events            : %s over %lld days, %lld users (%.0f MB CSV)\n", withCommas(static_cast<int64_t>(parsed.size())).c_str(),
                    static_cast<long long>(days), static_cast<long long>(users), bytes / 1e6);
        std::printf("Generate          : %.0f ms\n", genMs);
        std::printf("Parse CSV         : %.0f ms  (%s lines/s)\n", parseMs, withCommas(static_cast<int64_t>(n / (parseMs / 1000.0))).c_str());
        std::printf("Detect            : %.0f ms  (%s events/s)\n", res.detectMs, withCommas(static_cast<int64_t>(n / (res.detectMs / 1000.0))).c_str());
        std::printf("Score + correlate : %.0f ms\n", res.scoreMs);
        std::printf("Alerts            : %zu\n", res.alerts.size());
        std::printf("%s", formatEvalReport(ev).c_str());
        return 0;
    }
    return 2;
}
