#pragma once
// Small string / time / IP helpers (no external dependencies, fully portable).

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace lg {

std::string trim(std::string_view s);
std::string toLower(std::string_view s);

// Splits one CSV line. Supports double-quoted fields with "" escapes.
// Returns false on an unterminated quote. Fields are trimmed.
bool splitCsvLine(const std::string& line, std::vector<std::string>& out);

// Accepted forms:
//   YYYY-MM-DD HH:MM:SS   |   YYYY-MM-DDTHH:MM:SS   (optional .fraction)
//   optional zone suffix: Z, +HH:MM, -HH:MM, +HHMM, -HHMM
//   epoch seconds (9-11 digits)
// Calendar fields are validated (leap years, month lengths...).
bool parseTimestamp(std::string_view text, int64_t& epochSeconds);

// "YYYY-MM-DD HH:MM:SS" (UTC).
std::string formatTimestamp(int64_t epochSeconds);

// 0..23
int hourOfDay(int64_t epochSeconds);

// Strict dotted-quad parser: exactly 4 decimal parts, 0-255, no leading zeros.
bool parseIpv4(std::string_view text, uint32_t& out);
std::string ipv4ToString(uint32_t ip);

// IPv4 (strict) or a syntactically plausible IPv6 literal.
// When the address is IPv4, *ip4 / *hasIp4 are filled.
bool isValidIp(std::string_view text, uint32_t* ip4, bool* hasIp4);

}  // namespace lg
