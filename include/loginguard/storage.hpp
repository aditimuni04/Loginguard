#pragma once
// SQLite persistence + all queries behind the dashboard API.
//
// Tables
//   events         one row per login attempt           (indexed by time / ip / user)
//   alerts         one row per detected incident       (indexed by severity+score / time / rule / ip / user / cluster)
//   score_factors  explainable score breakdown per alert
//   hourly_stats, ip_stats, user_stats
//                  materialised aggregates built once with GROUP BY at load time,
//                  so dashboard queries stay fast even for millions of events
//   meta           run information + the configuration used
//
// Every query uses bound parameters (no string-built SQL values) and the class
// serialises access with a mutex, so one instance can be shared by the HTTP
// server's worker threads.

#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <variant>
#include <vector>

#include "loginguard/types.hpp"

struct sqlite3;

namespace lg {

class DbError : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

struct AlertFilter {
    std::vector<Severity> severities;  // empty = all
    std::vector<std::string> rules;    // empty = all
    std::string user;                  // exact match
    std::string ip;                    // exact match
    std::string search;                // substring of user / ip / rule
    int minScore = 0;
    int maxScore = 100;
    std::optional<int64_t> from;       // alert overlaps [from, to]
    std::optional<int64_t> to;
    std::optional<int> cluster;
    std::string sort = "score";        // score|severity|ts|count|events|rule|ip|username|id
    bool descending = true;
    int limit = 50;                    // clamped to [1, 500]
    int offset = 0;
};

class Database {
public:
    Database(const std::string& path, bool readOnly);
    ~Database();
    Database(const Database&) = delete;
    Database& operator=(const Database&) = delete;

    // ---- writing (used by `analyze`) -------------------------------------------
    // Drops and recreates the schema, bulk-inserts everything in ONE transaction
    // and builds indexes + aggregate tables afterwards (much faster than indexing first).
    // `runInfo` is a JSON object whose entries are stored in `meta`.
    void load(const std::vector<LoginEvent>& events, const std::vector<Alert>& alerts,
              const nlohmann::json& runInfo);

    // ---- reading (used by the API) ---------------------------------------------
    void requireValidSchema();  // throws DbError if this is not a LoginGuard database
    nlohmann::json summary();
    nlohmann::json timeline(int64_t bucketSeconds);  // multiple of 3600
    nlohmann::json hourOfDay();
    nlohmann::json alerts(const AlertFilter& f);
    nlohmann::json alertDetail(int64_t id);          // JSON null when not found
    nlohmann::json ruleStats();
    nlohmann::json topIps(int limit);                // by failed logins
    nlohmann::json topUsers(int limit);              // by failed logins
    nlohmann::json topRisk(bool byIp, int limit);    // by accumulated alert score (bounded heap)
    nlohmann::json clusters(int minAlerts, int limit);
    nlohmann::json config();

private:
    using Param = std::variant<int64_t, std::string>;

    void exec(const std::string& sql);
    nlohmann::json query(const std::string& sql, const std::vector<Param>& params = {});
    int64_t scalar(const std::string& sql, const std::vector<Param>& params = {});
    void setMeta(const std::string& key, const nlohmann::json& value);

    sqlite3* db_ = nullptr;
    std::mutex mu_;
};

}  // namespace lg
