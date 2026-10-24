#pragma once
// CSV authentication-log parser.
//
// Expected columns (header row optional):   timestamp,username,ip,status
//   timestamp : see parseTimestamp() in util.hpp
//   username  : stored lower-cased
//   ip        : IPv4 or IPv6
//   status    : SUCCESS/FAILURE (also: ok, accepted, fail, failed, denied, 1/0, true/false)
// Blank lines and lines starting with '#' are skipped. Malformed lines are
// counted and sampled, never fatal.

#include <iosfwd>
#include <string>
#include <vector>

#include "loginguard/types.hpp"

namespace lg {

struct ParseReport {
    size_t totalLines = 0;
    size_t parsed = 0;
    size_t skipped = 0;    // blanks, comments, header
    size_t malformed = 0;
    std::vector<std::string> samples;  // first few "line N: reason" messages
};

// Parses a single data line. On failure returns false and sets `error`.
bool parseLogLine(const std::string& line, LoginEvent& out, std::string& error);

// Appends valid events to `out`.
ParseReport parseLogStream(std::istream& in, std::vector<LoginEvent>& out, size_t maxSamples = 5);

// Returns false (and sets `error`) only when the file cannot be opened.
bool parseLogFile(const std::string& path, std::vector<LoginEvent>& out, ParseReport& report,
                  std::string& error);

}  // namespace lg
