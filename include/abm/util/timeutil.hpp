// ISO-8601 timestamp parsing / formatting with Python datetime semantics.
#pragma once

#include <cstdint>
#include <string>

namespace abm::timeutil {

// datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp(), naive times treated as UTC.
// Throws std::invalid_argument("Invalid isoformat string: '...'").
double parse_iso_timestamp(const std::string& s);

// datetime.fromtimestamp(secs, tz=UTC).isoformat() -> "2026-10-01T14:00:00+00:00"
std::string iso_from_epoch(std::int64_t secs);

// datetime.now(UTC).isoformat(timespec="seconds")
std::string now_iso_seconds();

}  // namespace abm::timeutil
