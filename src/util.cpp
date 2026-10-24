#include "loginguard/util.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>

namespace lg {

// ---------------------------------------------------------------- strings

std::string trim(std::string_view s) {
    size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b]))) ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1]))) --e;
    return std::string(s.substr(b, e - b));
}

std::string toLower(std::string_view s) {
    std::string r(s);
    std::transform(r.begin(), r.end(), r.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return r;
}

bool splitCsvLine(const std::string& line, std::vector<std::string>& out) {
    out.clear();
    std::string cur;
    bool inQuotes = false;
    bool wasQuoted = false;
    for (size_t i = 0; i < line.size(); ++i) {
        char c = line[i];
        if (inQuotes) {
            if (c == '"') {
                if (i + 1 < line.size() && line[i + 1] == '"') {
                    cur.push_back('"');
                    ++i;
                } else {
                    inQuotes = false;
                }
            } else {
                cur.push_back(c);
            }
        } else if (c == '"' && trim(cur).empty()) {
            cur.clear();
            inQuotes = true;
            wasQuoted = true;
        } else if (c == ',') {
            out.push_back(wasQuoted ? cur : trim(cur));
            cur.clear();
            wasQuoted = false;
        } else {
            cur.push_back(c);
        }
    }
    if (inQuotes) return false;
    out.push_back(wasQuoted ? cur : trim(cur));
    return true;
}

// ---------------------------------------------------------------- calendar

namespace {

bool isLeap(int64_t y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }

int daysInMonth(int64_t y, int m) {
    static const int dm[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    return (m == 2 && isLeap(y)) ? 29 : dm[m - 1];
}

// Howard Hinnant's public-domain civil-calendar algorithms.
int64_t daysFromCivil(int64_t y, unsigned m, unsigned d) {
    y -= m <= 2;
    const int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<int64_t>(doe) - 719468;
}

void civilFromDays(int64_t z, int64_t& y, unsigned& m, unsigned& d) {
    z += 719468;
    const int64_t era = (z >= 0 ? z : z - 146096) / 146097;
    const unsigned doe = static_cast<unsigned>(z - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    y = static_cast<int64_t>(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    d = doy - (153 * mp + 2) / 5 + 1;
    m = mp < 10 ? mp + 3 : mp - 9;
    y += (m <= 2);
}

// Reads exactly `n` decimal digits at s[pos..pos+n).
bool readDigits(std::string_view s, size_t& pos, int n, int& out) {
    if (pos + static_cast<size_t>(n) > s.size()) return false;
    int v = 0;
    for (int i = 0; i < n; ++i) {
        char c = s[pos + static_cast<size_t>(i)];
        if (c < '0' || c > '9') return false;
        v = v * 10 + (c - '0');
    }
    pos += static_cast<size_t>(n);
    out = v;
    return true;
}

}  // namespace

bool parseTimestamp(std::string_view text, int64_t& out) {
    std::string t = trim(text);
    std::string_view s = t;
    if (s.empty()) return false;

    // Pure epoch seconds.
    if (std::all_of(s.begin(), s.end(), [](char c) { return c >= '0' && c <= '9'; })) {
        if (s.size() < 9 || s.size() > 11) return false;
        int64_t v = 0;
        for (char c : s) v = v * 10 + (c - '0');
        out = v;
        return true;
    }

    size_t p = 0;
    int Y = 0, M = 0, D = 0, h = 0, mi = 0, sec = 0;
    if (!readDigits(s, p, 4, Y)) return false;
    if (p >= s.size() || s[p++] != '-') return false;
    if (!readDigits(s, p, 2, M)) return false;
    if (p >= s.size() || s[p++] != '-') return false;
    if (!readDigits(s, p, 2, D)) return false;
    if (p >= s.size() || (s[p] != ' ' && s[p] != 'T')) return false;
    ++p;
    if (!readDigits(s, p, 2, h)) return false;
    if (p >= s.size() || s[p++] != ':') return false;
    if (!readDigits(s, p, 2, mi)) return false;
    if (p >= s.size() || s[p++] != ':') return false;
    if (!readDigits(s, p, 2, sec)) return false;

    // Optional fractional seconds (ignored).
    if (p < s.size() && s[p] == '.') {
        ++p;
        size_t start = p;
        while (p < s.size() && s[p] >= '0' && s[p] <= '9') ++p;
        if (p == start) return false;
    }

    // Optional zone.
    int64_t offsetSeconds = 0;
    if (p < s.size()) {
        char z = s[p];
        if (z == 'Z' || z == 'z') {
            ++p;
        } else if (z == '+' || z == '-') {
            int sign = (z == '-') ? -1 : 1;
            ++p;
            int oh = 0, om = 0;
            if (!readDigits(s, p, 2, oh)) return false;
            if (p < s.size() && s[p] == ':') ++p;
            if (!readDigits(s, p, 2, om)) return false;
            if (oh > 23 || om > 59) return false;
            offsetSeconds = sign * (oh * 3600 + om * 60);
        } else {
            return false;
        }
    }
    if (p != s.size()) return false;

    if (Y < 1970 || Y > 2999) return false;
    if (M < 1 || M > 12) return false;
    if (D < 1 || D > daysInMonth(Y, M)) return false;
    if (h > 23 || mi > 59 || sec > 59) return false;

    int64_t days = daysFromCivil(Y, static_cast<unsigned>(M), static_cast<unsigned>(D));
    out = days * 86400 + h * 3600 + mi * 60 + sec - offsetSeconds;
    return true;
}

std::string formatTimestamp(int64_t ts) {
    int64_t days = ts / 86400;
    int64_t rem = ts % 86400;
    if (rem < 0) {
        rem += 86400;
        --days;
    }
    int64_t y;
    unsigned m, d;
    civilFromDays(days, y, m, d);
    char buf[40];
    std::snprintf(buf, sizeof buf, "%04lld-%02u-%02u %02d:%02d:%02d", static_cast<long long>(y), m, d,
                  static_cast<int>(rem / 3600), static_cast<int>((rem % 3600) / 60),
                  static_cast<int>(rem % 60));
    return buf;
}

int hourOfDay(int64_t ts) {
    int64_t rem = ts % 86400;
    if (rem < 0) rem += 86400;
    return static_cast<int>(rem / 3600);
}

// ---------------------------------------------------------------- IPs

bool parseIpv4(std::string_view s, uint32_t& out) {
    uint32_t result = 0;
    size_t pos = 0;
    for (int part = 0; part < 4; ++part) {
        size_t start = pos;
        uint32_t v = 0;
        while (pos < s.size() && s[pos] >= '0' && s[pos] <= '9') {
            v = v * 10 + static_cast<uint32_t>(s[pos] - '0');
            if (v > 255) return false;
            ++pos;
        }
        size_t len = pos - start;
        if (len == 0 || len > 3) return false;
        if (len > 1 && s[start] == '0') return false;  // no leading zeros (octal ambiguity)
        result = (result << 8) | v;
        if (part < 3) {
            if (pos >= s.size() || s[pos] != '.') return false;
            ++pos;
        }
    }
    if (pos != s.size()) return false;
    out = result;
    return true;
}

std::string ipv4ToString(uint32_t ip) {
    char buf[20];
    std::snprintf(buf, sizeof buf, "%u.%u.%u.%u", (ip >> 24) & 255u, (ip >> 16) & 255u, (ip >> 8) & 255u,
                  ip & 255u);
    return buf;
}

bool isValidIp(std::string_view s, uint32_t* ip4, bool* hasIp4) {
    uint32_t v = 0;
    if (parseIpv4(s, v)) {
        if (ip4) *ip4 = v;
        if (hasIp4) *hasIp4 = true;
        return true;
    }
    if (hasIp4) *hasIp4 = false;
    // Loose IPv6 check: hex digits, ':' and (for IPv4-mapped forms) '.'.
    if (s.size() < 2 || s.size() > 45) return false;
    int colons = 0;
    for (char c : s) {
        if (c == ':') {
            ++colons;
        } else if (!std::isxdigit(static_cast<unsigned char>(c)) && c != '.') {
            return false;
        }
    }
    if (colons < 2) return false;
    if (s.find(":::") != std::string_view::npos) return false;
    return true;
}

}  // namespace lg
