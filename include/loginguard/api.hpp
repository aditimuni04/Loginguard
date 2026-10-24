#pragma once
// HTTP layer: JSON REST API under /api/* and the static dashboard.
//
//   GET /api/health
//   GET /api/summary                       totals, severity counts, run info
//   GET /api/timeline?bucket=3600          success/failure/alert counts per time bucket
//   GET /api/hour-of-day                   success/failure per hour of day (0-23)
//   GET /api/alerts?severity=high,critical&rule=&q=&min_score=&max_score=&from=&to=
//                  &cluster=&user=&ip=&sort=score&order=desc&limit=50&offset=0
//   GET /api/alerts/{id}                   score breakdown, related events, campaign
//   GET /api/rules                         alert statistics per rule
//   GET /api/top-ips?limit=10              by failed logins
//   GET /api/top-users?limit=10            by failed logins
//   GET /api/top-risk?by=ip|user&limit=10  by accumulated risk score
//   GET /api/campaigns?min_alerts=2&limit=10
//   GET /api/config                        configuration used for the analysis

#include <string>

namespace httplib {
class Server;
}

namespace lg {

class Database;

// Registers all API routes. When `webDir` is non-empty it is also mounted at "/".
void registerApi(httplib::Server& svr, Database& db, const std::string& webDir);

// Locates the dashboard folder (must contain index.html): the explicit path if given,
// otherwise ./web, ../web and folders next to the executable. Returns "" if not found.
std::string findWebDir(const std::string& explicitPath, const std::string& exePath);

struct ServerOptions {
    std::string host = "127.0.0.1";  // loopback by default: the dashboard is not exposed to the network
    int port = 8080;
    std::string webDir;
};

// Blocks until stopped (Ctrl+C / requestStop()). Returns a process exit code.
int runServer(Database& db, const ServerOptions& opt);
void requestStop();

}  // namespace lg
