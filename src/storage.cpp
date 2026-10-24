#include "loginguard/storage.hpp"

#include <sqlite3.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <map>

#include "loginguard/topk.hpp"
#include "loginguard/util.hpp"

namespace lg {

using json = nlohmann::json;

namespace {

constexpr const char* kSchemaVersion = "1";
constexpr int kMaxRelatedEvents = 200;

// ------------------------------------------------------------------ RAII statement

class Stmt {
public:
    Stmt(sqlite3* db, const std::string& sql) : db_(db) {
        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &s_, nullptr) != SQLITE_OK) {
            throw DbError(std::string("SQL prepare failed: ") + sqlite3_errmsg(db));
        }
    }
    ~Stmt() { sqlite3_finalize(s_); }
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;

    void bind(int idx, int64_t v) { check(sqlite3_bind_int64(s_, idx, v)); }
    void bind(int idx, const std::string& v) {
        check(sqlite3_bind_text(s_, idx, v.c_str(), static_cast<int>(v.size()), SQLITE_TRANSIENT));
    }
    bool step() {
        int rc = sqlite3_step(s_);
        if (rc == SQLITE_ROW) return true;
        if (rc == SQLITE_DONE) return false;
        throw DbError(std::string("SQL step failed: ") + sqlite3_errmsg(db_));
    }
    void reset() { sqlite3_reset(s_); }
    sqlite3_stmt* raw() { return s_; }

private:
    void check(int rc) {
        if (rc != SQLITE_OK) throw DbError(std::string("SQL bind failed: ") + sqlite3_errmsg(db_));
    }
    sqlite3* db_;
    sqlite3_stmt* s_ = nullptr;
};

std::string placeholders(size_t n) {
    std::string s;
    for (size_t i = 0; i < n; ++i) s += i ? ",?" : "?";
    return s;
}

// Escapes %, _ and \ so user input is matched literally by LIKE ... ESCAPE '\'.
std::string likePattern(const std::string& text) {
    std::string out = "%";
    for (char c : text) {
        if (c == '%' || c == '_' || c == '\\') out += '\\';
        out += c;
    }
    out += '%';
    return out;
}

void decorateAlert(json& row) {
    row["severity_label"] = severityName(static_cast<Severity>(row.at("severity").get<int>()));
    row["ts_text"] = formatTimestamp(row.at("ts").get<int64_t>());
    if (row.contains("end_ts")) row["end_ts_text"] = formatTimestamp(row.at("end_ts").get<int64_t>());
}

const char* kAlertColumns =
    "id, ts, end_ts, window_start, rule, username, ip, count, events, score, severity, cluster_id, detail";

}  // namespace

// ------------------------------------------------------------------ lifecycle

Database::Database(const std::string& path, bool readOnly) {
    int flags = readOnly ? SQLITE_OPEN_READONLY : (SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE);
    if (sqlite3_open_v2(path.c_str(), &db_, flags | SQLITE_OPEN_FULLMUTEX, nullptr) != SQLITE_OK) {
        std::string msg = db_ ? sqlite3_errmsg(db_) : "out of memory";
        if (db_) sqlite3_close(db_);
        db_ = nullptr;
        throw DbError("cannot open database '" + path + "': " + msg);
    }
    sqlite3_busy_timeout(db_, 5000);
}

Database::~Database() {
    if (db_) sqlite3_close(db_);
}

void Database::exec(const std::string& sql) {
    char* err = nullptr;
    if (sqlite3_exec(db_, sql.c_str(), nullptr, nullptr, &err) != SQLITE_OK) {
        std::string msg = err ? err : "unknown error";
        sqlite3_free(err);
        throw DbError("SQL error: " + msg);
    }
}

json Database::query(const std::string& sql, const std::vector<Param>& params) {
    Stmt st(db_, sql);
    int idx = 1;
    for (const Param& p : params) {
        if (std::holds_alternative<int64_t>(p)) st.bind(idx++, std::get<int64_t>(p));
        else st.bind(idx++, std::get<std::string>(p));
    }
    json rows = json::array();
    sqlite3_stmt* s = st.raw();
    const int cols = sqlite3_column_count(s);
    while (st.step()) {
        json row = json::object();
        for (int c = 0; c < cols; ++c) {
            const char* name = sqlite3_column_name(s, c);
            switch (sqlite3_column_type(s, c)) {
                case SQLITE_INTEGER: row[name] = static_cast<int64_t>(sqlite3_column_int64(s, c)); break;
                case SQLITE_FLOAT: row[name] = sqlite3_column_double(s, c); break;
                case SQLITE_TEXT:
                    row[name] = std::string(reinterpret_cast<const char*>(sqlite3_column_text(s, c)),
                                            static_cast<size_t>(sqlite3_column_bytes(s, c)));
                    break;
                default: row[name] = nullptr; break;
            }
        }
        rows.push_back(std::move(row));
    }
    return rows;
}

int64_t Database::scalar(const std::string& sql, const std::vector<Param>& params) {
    json rows = query(sql, params);
    if (rows.empty() || rows[0].empty()) return 0;
    auto first = rows[0].begin();  // single-column result: take its first (only) value
    return first.value().is_number() ? first.value().get<int64_t>() : 0;
}

void Database::setMeta(const std::string& key, const json& value) {
    Stmt st(db_, "INSERT OR REPLACE INTO meta(key, value) VALUES(?, ?)");
    st.bind(1, key);
    st.bind(2, value.dump());
    st.step();
}

// ------------------------------------------------------------------ writing

void Database::load(const std::vector<LoginEvent>& events, const std::vector<Alert>& alerts, const json& runInfo) {
    std::lock_guard<std::mutex> lock(mu_);
    // Fast bulk load, but keep an in-memory journal so a failure can still ROLLBACK cleanly.
    exec("PRAGMA journal_mode=MEMORY; PRAGMA synchronous=OFF; PRAGMA temp_store=MEMORY; PRAGMA cache_size=-65536;");
    exec(
        "DROP TABLE IF EXISTS score_factors; DROP TABLE IF EXISTS alerts; DROP TABLE IF EXISTS events;"
        "DROP TABLE IF EXISTS hourly_stats; DROP TABLE IF EXISTS ip_stats; DROP TABLE IF EXISTS user_stats;"
        "DROP TABLE IF EXISTS meta;");
    exec("BEGIN");
    try {
        exec(
            "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT NOT NULL);"
            "CREATE TABLE events("
            "  id INTEGER PRIMARY KEY,"
            "  ts INTEGER NOT NULL,"
            "  username TEXT NOT NULL,"
            "  ip TEXT NOT NULL,"
            "  success INTEGER NOT NULL CHECK(success IN (0,1)));"
            "CREATE TABLE alerts("
            "  id INTEGER PRIMARY KEY,"
            "  ts INTEGER NOT NULL,"
            "  end_ts INTEGER NOT NULL,"
            "  window_start INTEGER NOT NULL,"
            "  rule TEXT NOT NULL,"
            "  username TEXT NOT NULL DEFAULT '',"
            "  ip TEXT NOT NULL DEFAULT '',"
            "  count INTEGER NOT NULL,"
            "  events INTEGER NOT NULL,"
            "  score INTEGER NOT NULL CHECK(score BETWEEN 0 AND 100),"
            "  severity INTEGER NOT NULL CHECK(severity BETWEEN 0 AND 3),"
            "  cluster_id INTEGER NOT NULL,"
            "  detail TEXT NOT NULL);"
            "CREATE TABLE score_factors("
            "  alert_id INTEGER NOT NULL REFERENCES alerts(id),"
            "  factor TEXT NOT NULL,"
            "  points INTEGER NOT NULL);"
            "CREATE TABLE hourly_stats(bucket INTEGER PRIMARY KEY, ok INTEGER NOT NULL, fail INTEGER NOT NULL);"
            "CREATE TABLE ip_stats(ip TEXT PRIMARY KEY, failures INTEGER NOT NULL, successes INTEGER NOT NULL,"
            "  users_targeted INTEGER NOT NULL, first_ts INTEGER NOT NULL, last_ts INTEGER NOT NULL);"
            "CREATE TABLE user_stats(username TEXT PRIMARY KEY, failures INTEGER NOT NULL, successes INTEGER NOT NULL,"
            "  ips_used INTEGER NOT NULL, first_ts INTEGER NOT NULL, last_ts INTEGER NOT NULL);");

        {
            Stmt ins(db_, "INSERT INTO events(ts, username, ip, success) VALUES(?,?,?,?)");
            for (const LoginEvent& e : events) {
                ins.bind(1, e.ts);
                ins.bind(2, e.user);
                ins.bind(3, e.ip);
                ins.bind(4, static_cast<int64_t>(e.success ? 1 : 0));
                ins.step();
                ins.reset();
            }
        }
        {
            Stmt insA(db_,
                      "INSERT INTO alerts(id, ts, end_ts, window_start, rule, username, ip, count, events, score,"
                      " severity, cluster_id, detail) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)");
            Stmt insF(db_, "INSERT INTO score_factors(alert_id, factor, points) VALUES(?,?,?)");
            for (const Alert& a : alerts) {
                insA.bind(1, a.id);
                insA.bind(2, a.ts);
                insA.bind(3, a.endTs);
                insA.bind(4, a.windowStart);
                insA.bind(5, a.rule);
                insA.bind(6, a.user);
                insA.bind(7, a.ip);
                insA.bind(8, static_cast<int64_t>(a.count));
                insA.bind(9, static_cast<int64_t>(a.events));
                insA.bind(10, static_cast<int64_t>(a.score));
                insA.bind(11, static_cast<int64_t>(static_cast<int>(a.severity)));
                insA.bind(12, static_cast<int64_t>(a.clusterId));
                insA.bind(13, a.detail);
                insA.step();
                insA.reset();
                for (const ScoreFactor& f : a.factors) {
                    insF.bind(1, a.id);
                    insF.bind(2, f.name);
                    insF.bind(3, static_cast<int64_t>(f.points));
                    insF.step();
                    insF.reset();
                }
            }
        }

        // Indexes are built AFTER the bulk insert (much faster than maintaining them row by row).
        exec(
            "CREATE INDEX idx_events_ts ON events(ts);"
            "CREATE INDEX idx_events_ip ON events(ip, ts);"
            "CREATE INDEX idx_events_user ON events(username, ts);"
            "CREATE INDEX idx_alerts_sev ON alerts(severity DESC, score DESC);"
            "CREATE INDEX idx_alerts_score ON alerts(score DESC);"
            "CREATE INDEX idx_alerts_ts ON alerts(ts);"
            "CREATE INDEX idx_alerts_rule ON alerts(rule);"
            "CREATE INDEX idx_alerts_ip ON alerts(ip);"
            "CREATE INDEX idx_alerts_user ON alerts(username);"
            "CREATE INDEX idx_alerts_cluster ON alerts(cluster_id);"
            "CREATE INDEX idx_factors_alert ON score_factors(alert_id);");

        // Materialised aggregates (one pass each).
        exec(
            "INSERT INTO hourly_stats(bucket, ok, fail)"
            "  SELECT (ts/3600)*3600, SUM(success), COUNT(*) - SUM(success) FROM events GROUP BY ts/3600;"
            "INSERT INTO ip_stats(ip, failures, successes, users_targeted, first_ts, last_ts)"
            "  SELECT ip, COUNT(*) - SUM(success), SUM(success),"
            "         COUNT(DISTINCT CASE WHEN success = 0 THEN username END), MIN(ts), MAX(ts)"
            "  FROM events GROUP BY ip;"
            "INSERT INTO user_stats(username, failures, successes, ips_used, first_ts, last_ts)"
            "  SELECT username, COUNT(*) - SUM(success), SUM(success), COUNT(DISTINCT ip), MIN(ts), MAX(ts)"
            "  FROM events GROUP BY username;"
            "CREATE INDEX idx_ipstats_fail ON ip_stats(failures DESC);"
            "CREATE INDEX idx_userstats_fail ON user_stats(failures DESC);");

        setMeta("schema_version", kSchemaVersion);
        for (auto it = runInfo.begin(); it != runInfo.end(); ++it) setMeta(it.key(), it.value());
        setMeta("events_total", scalar("SELECT COUNT(*) FROM events"));
        setMeta("events_success", scalar("SELECT COALESCE(SUM(success),0) FROM events"));
        setMeta("users", scalar("SELECT COUNT(*) FROM user_stats"));
        setMeta("ips", scalar("SELECT COUNT(*) FROM ip_stats"));
        setMeta("first_ts", scalar("SELECT COALESCE(MIN(ts),0) FROM events"));
        setMeta("last_ts", scalar("SELECT COALESCE(MAX(ts),0) FROM events"));
        exec("COMMIT");
    } catch (...) {
        sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr);
        throw;
    }
}

// ------------------------------------------------------------------ reading

void Database::requireValidSchema() {
    std::lock_guard<std::mutex> lock(mu_);
    json rows;
    try {
        rows = query("SELECT value FROM meta WHERE key = 'schema_version'");
    } catch (const DbError&) {
        throw DbError("this file is not a LoginGuard database - run `loginguard analyze` first");
    }
    if (rows.empty() || rows[0]["value"].get<std::string>() != std::string("\"") + kSchemaVersion + "\"") {
        throw DbError("unsupported or missing schema version - re-run `loginguard analyze`");
    }
}

json Database::summary() {
    std::lock_guard<std::mutex> lock(mu_);
    json out = json::object();
    json run = json::object();
    for (const json& row : query("SELECT key, value FROM meta")) {
        const std::string key = row["key"].get<std::string>();
        if (key == "config" || key == "schema_version") continue;
        json v = json::parse(row["value"].get<std::string>(), nullptr, false);
        run[key] = v.is_discarded() ? json(row["value"]) : v;
    }
    const int64_t total = run.value("events_total", int64_t{0});
    const int64_t ok = run.value("events_success", int64_t{0});
    out["events"] = {{"total", total},
                     {"success", ok},
                     {"failure", total - ok},
                     {"success_rate", total ? static_cast<double>(ok) / static_cast<double>(total) : 0.0},
                     {"users", run.value("users", int64_t{0})},
                     {"ips", run.value("ips", int64_t{0})},
                     {"first_ts", run.value("first_ts", int64_t{0})},
                     {"last_ts", run.value("last_ts", int64_t{0})},
                     {"first_text", formatTimestamp(run.value("first_ts", int64_t{0}))},
                     {"last_text", formatTimestamp(run.value("last_ts", int64_t{0}))}};
    json bySev = {{"low", 0}, {"medium", 0}, {"high", 0}, {"critical", 0}};
    int64_t alertTotal = 0;
    for (const json& row : query("SELECT severity, COUNT(*) AS n FROM alerts GROUP BY severity")) {
        bySev[severityName(static_cast<Severity>(row["severity"].get<int>()))] = row["n"];
        alertTotal += row["n"].get<int64_t>();
    }
    out["alerts"] = {{"total", alertTotal},
                     {"by_severity", bySev},
                     {"campaigns", scalar("SELECT COUNT(DISTINCT cluster_id) FROM alerts")}};
    out["run"] = run;
    return out;
}

json Database::timeline(int64_t bucket) {
    std::lock_guard<std::mutex> lock(mu_);
    json events = query(
        "SELECT (bucket/?1)*?1 AS t, SUM(ok) AS ok, SUM(fail) AS fail FROM hourly_stats GROUP BY t ORDER BY t",
        {bucket});
    std::map<int64_t, json> alertsByBucket;
    for (const json& r : query(
             "SELECT (ts/?1)*?1 AS t, COUNT(*) AS n, MAX(severity) AS sev FROM alerts GROUP BY t", {bucket})) {
        alertsByBucket[r["t"].get<int64_t>()] = r;
    }
    json buckets = json::array();
    for (json& e : events) {
        const int64_t t = e["t"].get<int64_t>();
        e["alerts"] = 0;
        e["max_severity"] = -1;
        auto it = alertsByBucket.find(t);
        if (it != alertsByBucket.end()) {
            e["alerts"] = it->second["n"];
            e["max_severity"] = it->second["sev"];
        }
        e["text"] = formatTimestamp(t);
        buckets.push_back(std::move(e));
    }
    return {{"bucket_seconds", bucket}, {"buckets", buckets}};
}

json Database::hourOfDay() {
    std::lock_guard<std::mutex> lock(mu_);
    json rows = query(
        "SELECT (bucket % 86400)/3600 AS hour, SUM(ok) AS ok, SUM(fail) AS fail FROM hourly_stats GROUP BY hour");
    json out = json::array();
    for (int h = 0; h < 24; ++h) out.push_back({{"hour", h}, {"ok", 0}, {"fail", 0}});
    for (const json& r : rows) out[r["hour"].get<size_t>()] = r;
    return out;
}

json Database::alerts(const AlertFilter& f) {
    std::lock_guard<std::mutex> lock(mu_);
    std::string where = " WHERE 1=1";
    std::vector<Param> params;
    if (!f.severities.empty()) {
        where += " AND severity IN (" + placeholders(f.severities.size()) + ")";
        for (Severity s : f.severities) params.emplace_back(static_cast<int64_t>(static_cast<int>(s)));
    }
    if (!f.rules.empty()) {
        where += " AND rule IN (" + placeholders(f.rules.size()) + ")";
        for (const auto& r : f.rules) params.emplace_back(r);
    }
    if (!f.user.empty()) {
        where += " AND username = ?";
        params.emplace_back(f.user);
    }
    if (!f.ip.empty()) {
        where += " AND ip = ?";
        params.emplace_back(f.ip);
    }
    if (!f.search.empty()) {
        where += " AND (username LIKE ? ESCAPE '\\' OR ip LIKE ? ESCAPE '\\' OR rule LIKE ? ESCAPE '\\')";
        const std::string pat = likePattern(toLower(f.search));
        for (int i = 0; i < 3; ++i) params.emplace_back(pat);
    }
    where += " AND score >= ? AND score <= ?";
    params.emplace_back(static_cast<int64_t>(f.minScore));
    params.emplace_back(static_cast<int64_t>(f.maxScore));
    if (f.from) {
        where += " AND end_ts >= ?";
        params.emplace_back(*f.from);
    }
    if (f.to) {
        where += " AND ts <= ?";
        params.emplace_back(*f.to);
    }
    if (f.cluster) {
        where += " AND cluster_id = ?";
        params.emplace_back(static_cast<int64_t>(*f.cluster));
    }

    // Sort column comes from a whitelist, never from raw input.
    static const std::map<std::string, std::string> kSortColumns = {
        {"score", "score"},   {"severity", "severity"}, {"ts", "ts"},       {"count", "count"},
        {"events", "events"}, {"rule", "rule"},         {"ip", "ip"},       {"username", "username"},
        {"id", "id"}};
    auto col = kSortColumns.find(f.sort);
    if (col == kSortColumns.end()) throw DbError("unsupported sort column");
    const std::string dir = f.descending ? " DESC" : " ASC";
    std::string orderBy = " ORDER BY " + col->second + dir;
    if (col->second == "severity") orderBy += ", score" + dir;
    orderBy += ", id ASC";

    const int limit = std::clamp(f.limit, 1, 500);
    const int offset = std::max(f.offset, 0);

    const int64_t total = scalar("SELECT COUNT(*) FROM alerts" + where, params);
    std::vector<Param> rowParams = params;
    rowParams.emplace_back(static_cast<int64_t>(limit));
    rowParams.emplace_back(static_cast<int64_t>(offset));
    json items = query(std::string("SELECT ") + kAlertColumns + " FROM alerts" + where + orderBy + " LIMIT ? OFFSET ?",
                       rowParams);
    for (json& row : items) decorateAlert(row);
    return {{"total", total}, {"limit", limit}, {"offset", offset}, {"items", items}};
}

json Database::alertDetail(int64_t id) {
    std::lock_guard<std::mutex> lock(mu_);
    json rows = query(std::string("SELECT ") + kAlertColumns + " FROM alerts WHERE id = ?", {id});
    if (rows.empty()) return nullptr;
    json alert = rows[0];
    decorateAlert(alert);

    json factors = query("SELECT factor AS name, points FROM score_factors WHERE alert_id = ? ORDER BY rowid", {id});

    // Events that fed this incident: context window, filtered by the entities the alert names.
    std::string where = " WHERE ts >= ? AND ts <= ?";
    std::vector<Param> params = {alert["window_start"].get<int64_t>(), alert["end_ts"].get<int64_t>()};
    if (!alert["ip"].get<std::string>().empty()) {
        where += " AND ip = ?";
        params.emplace_back(alert["ip"].get<std::string>());
    }
    if (!alert["username"].get<std::string>().empty()) {
        where += " AND username = ?";
        params.emplace_back(alert["username"].get<std::string>());
    }
    const int64_t eventTotal = scalar("SELECT COUNT(*) FROM events" + where, params);
    std::vector<Param> evParams = params;
    evParams.emplace_back(static_cast<int64_t>(kMaxRelatedEvents));
    json related = query("SELECT ts, username, ip, success FROM events" + where + " ORDER BY ts LIMIT ?", evParams);
    for (json& e : related) e["ts_text"] = formatTimestamp(e["ts"].get<int64_t>());

    json campaign = query(
        "SELECT id, ts, rule, score, severity FROM alerts WHERE cluster_id = ? ORDER BY ts, id LIMIT 50",
        {alert["cluster_id"].get<int64_t>()});
    for (json& c : campaign) {
        c["severity_label"] = severityName(static_cast<Severity>(c["severity"].get<int>()));
        c["ts_text"] = formatTimestamp(c["ts"].get<int64_t>());
    }
    return {{"alert", alert},
            {"factors", factors},
            {"events", related},
            {"events_total", eventTotal},
            {"campaign", campaign}};
}

json Database::ruleStats() {
    std::lock_guard<std::mutex> lock(mu_);
    json rows = query(
        "SELECT rule, COUNT(*) AS alerts, MAX(score) AS max_score, ROUND(AVG(score), 1) AS avg_score,"
        " MAX(severity) AS max_severity FROM alerts GROUP BY rule ORDER BY alerts DESC, rule");
    return rows;
}

json Database::topIps(int limit) {
    std::lock_guard<std::mutex> lock(mu_);
    return query(
        "SELECT s.ip, s.failures, s.successes, s.users_targeted, COALESCE(a.n, 0) AS alerts,"
        "       COALESCE(a.mx, 0) AS max_score"
        " FROM ip_stats s LEFT JOIN (SELECT ip, COUNT(*) AS n, MAX(score) AS mx FROM alerts WHERE ip <> ''"
        "                            GROUP BY ip) a ON a.ip = s.ip"
        " ORDER BY s.failures DESC, s.ip LIMIT ?",
        {static_cast<int64_t>(std::clamp(limit, 1, 100))});
}

json Database::topUsers(int limit) {
    std::lock_guard<std::mutex> lock(mu_);
    return query(
        "SELECT s.username, s.failures, s.successes, s.ips_used, COALESCE(a.n, 0) AS alerts,"
        "       COALESCE(a.mx, 0) AS max_score"
        " FROM user_stats s LEFT JOIN (SELECT username, COUNT(*) AS n, MAX(score) AS mx FROM alerts"
        "                              WHERE username <> '' GROUP BY username) a ON a.username = s.username"
        " ORDER BY s.failures DESC, s.username LIMIT ?",
        {static_cast<int64_t>(std::clamp(limit, 1, 100))});
}

json Database::topRisk(bool byIp, int limit) {
    std::lock_guard<std::mutex> lock(mu_);
    limit = std::clamp(limit, 1, 100);
    const char* col = byIp ? "ip" : "username";
    std::vector<std::pair<std::string, int>> scored;
    for (const json& r : query(std::string("SELECT ") + col + " AS k, score FROM alerts WHERE " + col + " <> ''")) {
        scored.emplace_back(r["k"].get<std::string>(), r["score"].get<int>());
    }
    // Bounded min-heap: O(n log k) instead of sorting every entity.
    std::vector<EntityRisk> top = rankEntities(scored, static_cast<size_t>(limit));
    json out = json::array();
    for (const EntityRisk& e : top) {
        json row = {{"key", e.key}, {"alerts", e.alerts}, {"total_score", e.totalScore}, {"max_score", e.maxScore}};
        const int64_t sev = scalar(std::string("SELECT COALESCE(MAX(severity), 0) FROM alerts WHERE ") + col + " = ?",
                                   {e.key});
        row["max_severity"] = sev;
        row["severity_label"] = severityName(static_cast<Severity>(sev));
        json stats = byIp ? query("SELECT failures, successes, users_targeted AS other FROM ip_stats WHERE ip = ?", {e.key})
                          : query("SELECT failures, successes, ips_used AS other FROM user_stats WHERE username = ?",
                                  {e.key});
        row["failures"] = stats.empty() ? 0 : stats[0]["failures"].get<int64_t>();
        row["successes"] = stats.empty() ? 0 : stats[0]["successes"].get<int64_t>();
        row["other"] = stats.empty() ? 0 : stats[0]["other"].get<int64_t>();
        out.push_back(std::move(row));
    }
    return out;
}

json Database::clusters(int minAlerts, int limit) {
    std::lock_guard<std::mutex> lock(mu_);
    json rows = query(
        "SELECT cluster_id, COUNT(*) AS alerts, MAX(score) AS max_score, MAX(severity) AS max_severity,"
        "       COUNT(DISTINCT CASE WHEN ip <> '' THEN ip END) AS ips,"
        "       COUNT(DISTINCT CASE WHEN username <> '' THEN username END) AS users,"
        "       GROUP_CONCAT(DISTINCT rule) AS rules, MIN(ts) AS first_ts, MAX(end_ts) AS last_ts"
        " FROM alerts GROUP BY cluster_id HAVING COUNT(*) >= ?"
        " ORDER BY max_score DESC, alerts DESC, cluster_id LIMIT ?",
        {static_cast<int64_t>(std::max(minAlerts, 1)), static_cast<int64_t>(std::clamp(limit, 1, 100))});
    for (json& r : rows) {
        r["severity_label"] = severityName(static_cast<Severity>(r["max_severity"].get<int>()));
        r["first_text"] = formatTimestamp(r["first_ts"].get<int64_t>());
        r["last_text"] = formatTimestamp(r["last_ts"].get<int64_t>());
    }
    return rows;
}

json Database::config() {
    std::lock_guard<std::mutex> lock(mu_);
    json rows = query("SELECT value FROM meta WHERE key = 'config'");
    if (rows.empty()) return json::object();
    json v = json::parse(rows[0]["value"].get<std::string>(), nullptr, false);
    return v.is_discarded() ? json::object() : v;
}

}  // namespace lg
