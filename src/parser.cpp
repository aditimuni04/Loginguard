#include "loginguard/parser.hpp"

#include <fstream>
#include <istream>

#include "loginguard/util.hpp"

namespace lg {

namespace {

bool parseStatus(const std::string& raw, bool& success) {
    std::string s = toLower(raw);
    if (s == "success" || s == "succeeded" || s == "ok" || s == "accepted" || s == "pass" || s == "1" ||
        s == "true") {
        success = true;
        return true;
    }
    if (s == "failure" || s == "failed" || s == "fail" || s == "denied" || s == "invalid" || s == "error" ||
        s == "0" || s == "false") {
        success = false;
        return true;
    }
    return false;
}

bool looksLikeHeader(const std::vector<std::string>& fields) {
    if (fields.empty()) return false;
    std::string f = toLower(fields[0]);
    return f == "timestamp" || f == "time" || f == "ts" || f == "date" || f == "datetime";
}

}  // namespace

bool parseLogLine(const std::string& line, LoginEvent& out, std::string& error) {
    std::vector<std::string> f;
    if (!splitCsvLine(line, f)) {
        error = "unterminated quote";
        return false;
    }
    if (f.size() < 4) {
        error = "expected 4 fields (timestamp,username,ip,status), found " + std::to_string(f.size());
        return false;
    }
    int64_t ts = 0;
    if (!parseTimestamp(f[0], ts)) {
        error = "invalid timestamp '" + f[0].substr(0, 40) + "'";
        return false;
    }
    if (f[1].empty() || f[1].size() > 128) {
        error = "username is empty or longer than 128 characters";
        return false;
    }
    for (unsigned char c : f[1]) {
        if (c < 0x20 || c == 0x7f) {
            error = "username contains control characters";
            return false;
        }
    }
    LoginEvent ev;
    if (!isValidIp(f[2], &ev.ip4, &ev.hasIp4)) {
        error = "invalid IP address '" + f[2].substr(0, 50) + "'";
        return false;
    }
    bool success = false;
    if (!parseStatus(f[3], success)) {
        error = "invalid status '" + f[3].substr(0, 20) + "'";
        return false;
    }
    ev.ts = ts;
    ev.user = toLower(f[1]);
    ev.ip = f[2];
    ev.success = success;
    out = std::move(ev);
    return true;
}

ParseReport parseLogStream(std::istream& in, std::vector<LoginEvent>& out, size_t maxSamples) {
    ParseReport rep;
    std::string line;
    bool firstNonEmpty = true;
    std::vector<std::string> fields;
    while (std::getline(in, line)) {
        ++rep.totalLines;
        if (rep.totalLines == 1 && line.size() >= 3 && static_cast<unsigned char>(line[0]) == 0xEF &&
            static_cast<unsigned char>(line[1]) == 0xBB && static_cast<unsigned char>(line[2]) == 0xBF) {
            line.erase(0, 3);  // UTF-8 BOM
        }
        if (!line.empty() && line.back() == '\r') line.pop_back();  // CRLF files
        std::string t = trim(line);
        if (t.empty() || t[0] == '#') {
            ++rep.skipped;
            continue;
        }
        if (firstNonEmpty) {
            firstNonEmpty = false;
            if (splitCsvLine(t, fields) && looksLikeHeader(fields)) {
                ++rep.skipped;
                continue;
            }
        }
        LoginEvent ev;
        std::string err;
        if (parseLogLine(t, ev, err)) {
            out.push_back(std::move(ev));
            ++rep.parsed;
        } else {
            ++rep.malformed;
            if (rep.samples.size() < maxSamples) {
                rep.samples.push_back("line " + std::to_string(rep.totalLines) + ": " + err);
            }
        }
    }
    return rep;
}

bool parseLogFile(const std::string& path, std::vector<LoginEvent>& out, ParseReport& report,
                  std::string& error) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error = "cannot open log file '" + path + "'";
        return false;
    }
    report = parseLogStream(in, out);
    return true;
}

}  // namespace lg
