#include "loginguard/api.hpp"

#include <httplib/httplib.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <set>
#include <thread>

#include "loginguard/storage.hpp"
#include "loginguard/util.hpp"

namespace lg {

using json = nlohmann::json;

namespace {

class BadRequest : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};
class NotFound : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

std::atomic<bool> g_stop{false};

// ---------------------------------------------------------------- parameter parsing

int64_t parseInt(const std::string& text, const std::string& name, int64_t lo, int64_t hi) {
    if (text.empty() || text.size() > 18) throw BadRequest("'" + name + "' must be an integer");
    size_t i = 0;
    bool neg = false;
    if (text[0] == '-') {
        neg = true;
        i = 1;
        if (text.size() == 1) throw BadRequest("'" + name + "' must be an integer");
    }
    int64_t v = 0;
    for (; i < text.size(); ++i) {
        if (text[i] < '0' || text[i] > '9') throw BadRequest("'" + name + "' must be an integer");
        v = v * 10 + (text[i] - '0');
    }
    if (neg) v = -v;
    if (v < lo || v > hi) {
        throw BadRequest("'" + name + "' must be between " + std::to_string(lo) + " and " + std::to_string(hi));
    }
    return v;
}

int intParam(const httplib::Request& req, const char* name, int def, int lo, int hi) {
    if (!req.has_param(name)) return def;
    return static_cast<int>(parseInt(req.get_param_value(name), name, lo, hi));
}

std::vector<std::string> listParam(const httplib::Request& req, const char* name, size_t maxItems, size_t maxLen) {
    std::vector<std::string> out;
    if (!req.has_param(name)) return out;
    const std::string raw = req.get_param_value(name);
    size_t start = 0;
    while (start <= raw.size()) {
        size_t comma = raw.find(',', start);
        if (comma == std::string::npos) comma = raw.size();
        std::string item = trim(raw.substr(start, comma - start));
        if (!item.empty()) {
            if (item.size() > maxLen) throw BadRequest(std::string("'") + name + "' contains an overly long value");
            out.push_back(std::move(item));
        }
        start = comma + 1;
    }
    if (out.size() > maxItems) throw BadRequest(std::string("'") + name + "' has too many values");
    return out;
}

std::string textParam(const httplib::Request& req, const char* name, size_t maxLen) {
    if (!req.has_param(name)) return "";
    std::string v = trim(req.get_param_value(name));
    if (v.size() > maxLen) throw BadRequest(std::string("'") + name + "' is too long");
    return v;
}

// Accepts epoch seconds, "YYYY-MM-DD HH:MM:SS" or a bare "YYYY-MM-DD". A bare date means the
// start of that day, or - for an upper bound (`endOfDay`) - its last second.
int64_t timeParam(const httplib::Request& req, const char* name, bool& present, bool endOfDay) {
    present = req.has_param(name) && !req.get_param_value(name).empty();
    if (!present) return 0;
    std::string text = trim(req.get_param_value(name));
    const bool dateOnly = text.size() == 10 && text[4] == '-' && text[7] == '-';
    if (dateOnly) text += endOfDay ? " 23:59:59" : " 00:00:00";
    int64_t ts = 0;
    if (!parseTimestamp(text, ts)) {
        throw BadRequest(std::string("'") + name + "' must be epoch seconds or YYYY-MM-DD[ HH:MM:SS]");
    }
    return ts;
}

AlertFilter parseAlertFilter(const httplib::Request& req) {
    AlertFilter f;
    for (const auto& item : listParam(req, "severity", 4, 16)) {
        Severity s;
        if (!parseSeverity(item, s)) throw BadRequest("unknown severity '" + item + "'");
        f.severities.push_back(s);
    }
    f.rules = listParam(req, "rule", 20, 100);
    f.user = toLower(textParam(req, "user", 128));
    f.ip = textParam(req, "ip", 64);
    f.search = textParam(req, "q", 100);
    f.minScore = intParam(req, "min_score", 0, 0, 100);
    f.maxScore = intParam(req, "max_score", 100, 0, 100);
    if (f.minScore > f.maxScore) throw BadRequest("'min_score' must not exceed 'max_score'");
    bool has = false;
    int64_t t = timeParam(req, "from", has, /*endOfDay=*/false);
    if (has) f.from = t;
    t = timeParam(req, "to", has, /*endOfDay=*/true);
    if (has) f.to = t;
    if (f.from && f.to && *f.from > *f.to) throw BadRequest("'from' must not be later than 'to'");
    if (req.has_param("cluster")) f.cluster = intParam(req, "cluster", 1, 1, 2000000000);

    f.sort = req.has_param("sort") ? req.get_param_value("sort") : "score";
    static const std::set<std::string> kSorts = {"score", "severity", "ts",       "count", "events",
                                                 "rule",  "ip",       "username", "id"};
    if (!kSorts.count(f.sort)) throw BadRequest("unsupported 'sort' column");
    const std::string order = req.has_param("order") ? toLower(req.get_param_value("order")) : "desc";
    if (order != "asc" && order != "desc") throw BadRequest("'order' must be asc or desc");
    f.descending = order == "desc";
    f.limit = intParam(req, "limit", 50, 1, 500);
    f.offset = intParam(req, "offset", 0, 0, 10000000);
    return f;
}

// ---------------------------------------------------------------- responses

void sendJson(httplib::Response& res, const json& body, int status = 200) {
    res.status = status;
    res.set_content(body.dump(), "application/json; charset=utf-8");
}

void sendError(httplib::Response& res, int status, const std::string& message) {
    sendJson(res, {{"error", message}}, status);
}

// Wraps a handler returning JSON so that every failure becomes a clean JSON error.
template <typename Fn>
httplib::Server::Handler guarded(Fn fn) {
    return [fn](const httplib::Request& req, httplib::Response& res) {
        try {
            sendJson(res, fn(req));
        } catch (const BadRequest& e) {
            sendError(res, 400, e.what());
        } catch (const NotFound& e) {
            sendError(res, 404, e.what());
        } catch (const std::exception& e) {
            std::fprintf(stderr, "[api] %s %s failed: %s\n", req.method.c_str(), req.path.c_str(), e.what());
            sendError(res, 500, "internal server error");
        }
    };
}

}  // namespace

// ---------------------------------------------------------------- routes

void registerApi(httplib::Server& svr, Database& db, const std::string& webDir) {
    svr.Get("/api/health", guarded([](const httplib::Request&) { return json{{"status", "ok"}}; }));
    svr.Get("/api/summary", guarded([&db](const httplib::Request&) { return db.summary(); }));
    svr.Get("/api/timeline", guarded([&db](const httplib::Request& req) {
                const int64_t bucket = req.has_param("bucket") ? parseInt(req.get_param_value("bucket"), "bucket", 3600, 7 * 86400) : 3600;
                if (bucket % 3600 != 0) throw BadRequest("'bucket' must be a multiple of 3600 seconds");
                return db.timeline(bucket);
            }));
    svr.Get("/api/hour-of-day", guarded([&db](const httplib::Request&) { return db.hourOfDay(); }));
    svr.Get("/api/alerts", guarded([&db](const httplib::Request& req) { return db.alerts(parseAlertFilter(req)); }));
    svr.Get(R"(/api/alerts/(\d{1,15}))", guarded([&db](const httplib::Request& req) {
                json detail = db.alertDetail(parseInt(req.matches[1], "id", 1, 999999999999999LL));
                if (detail.is_null()) throw NotFound("alert not found");
                return detail;
            }));
    svr.Get("/api/rules", guarded([&db](const httplib::Request&) { return db.ruleStats(); }));
    svr.Get("/api/top-ips", guarded([&db](const httplib::Request& req) { return db.topIps(intParam(req, "limit", 10, 1, 100)); }));
    svr.Get("/api/top-users", guarded([&db](const httplib::Request& req) { return db.topUsers(intParam(req, "limit", 10, 1, 100)); }));
    svr.Get("/api/top-risk", guarded([&db](const httplib::Request& req) {
                const std::string by = req.has_param("by") ? toLower(req.get_param_value("by")) : "ip";
                if (by != "ip" && by != "user") throw BadRequest("'by' must be ip or user");
                return db.topRisk(by == "ip", intParam(req, "limit", 10, 1, 100));
            }));
    svr.Get("/api/campaigns", guarded([&db](const httplib::Request& req) {
                return db.clusters(intParam(req, "min_alerts", 2, 1, 1000000), intParam(req, "limit", 10, 1, 100));
            }));
    svr.Get("/api/config", guarded([&db](const httplib::Request&) { return db.config(); }));

    svr.set_error_handler([](const httplib::Request& req, httplib::Response& res) {
        if (!res.body.empty()) return;  // a handler already produced a body
        if (req.path.rfind("/api/", 0) == 0) {
            sendError(res, res.status, res.status == 404 ? "no such endpoint" : "request failed");
        } else {
            res.set_content("Not found", "text/plain; charset=utf-8");
        }
    });
    svr.set_exception_handler([](const httplib::Request&, httplib::Response& res, std::exception_ptr) {
        sendError(res, 500, "internal server error");
    });
    svr.set_post_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        res.set_header("X-Content-Type-Options", "nosniff");
        res.set_header("X-Frame-Options", "DENY");
        res.set_header("Referrer-Policy", "no-referrer");
        // The dashboard is fully self-contained: no external scripts, styles, fonts or frames.
        res.set_header("Content-Security-Policy",
                       "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                       "connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'");
        res.set_header("Cache-Control", req.path.rfind("/api/", 0) == 0 ? "no-store" : "no-cache");
    });
    svr.set_payload_max_length(64 * 1024);
    svr.set_read_timeout(10, 0);
    svr.set_write_timeout(10, 0);

    if (!webDir.empty()) svr.set_mount_point("/", webDir);
}

std::string findWebDir(const std::string& explicitPath, const std::string& exePath) {
    namespace fs = std::filesystem;
    std::vector<fs::path> candidates;
    if (!explicitPath.empty()) {
        candidates.emplace_back(explicitPath);
    } else {
        candidates.emplace_back("web");
        candidates.emplace_back("../web");
        std::error_code ec;
        fs::path exeDir = fs::absolute(fs::path(exePath), ec).parent_path();
        if (!ec) {
            candidates.push_back(exeDir / "web");
            candidates.push_back(exeDir / ".." / "web");
            candidates.push_back(exeDir / ".." / ".." / "web");
        }
    }
    for (const fs::path& c : candidates) {
        std::error_code ec;
        if (fs::exists(c / "index.html", ec)) {
            fs::path canon = fs::weakly_canonical(c, ec);
            return ec ? c.string() : canon.string();
        }
    }
    return "";
}

void requestStop() { g_stop.store(true); }

int runServer(Database& db, const ServerOptions& opt) {
    g_stop.store(false);
    httplib::Server svr;
    registerApi(svr, db, opt.webDir);

    if (!svr.bind_to_port(opt.host, opt.port)) {
        std::fprintf(stderr, "error: cannot listen on %s:%d (port already in use? try --port)\n", opt.host.c_str(),
                     opt.port);
        return 1;
    }
    std::printf("Dashboard: http://%s:%d/   (Ctrl+C to stop)\n", opt.host == "0.0.0.0" ? "localhost" : opt.host.c_str(),
                opt.port);
    if (opt.host == "0.0.0.0") {
        std::printf("warning: listening on all interfaces - the API has no authentication\n");
    }
    std::fflush(stdout);

    std::atomic<bool> finished{false};
    std::thread server([&svr, &finished] {
        svr.listen_after_bind();
        finished.store(true);
    });
    while (!g_stop.load() && !finished.load()) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    const bool stoppedOnRequest = g_stop.load();
    // stop() is a no-op until the accept loop is running, so keep asking until the thread exits.
    while (!finished.load()) {
        svr.stop();
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    server.join();
    if (!stoppedOnRequest) {
        std::fprintf(stderr, "error: the server stopped unexpectedly\n");
        return 1;
    }
    std::printf("\nServer stopped.\n");
    return 0;
}

}  // namespace lg
