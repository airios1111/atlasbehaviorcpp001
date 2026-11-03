#include "abm/util/timeutil.hpp"

#include <chrono>
#include <cstdio>
#include <stdexcept>

namespace abm::timeutil {
namespace {

// Howard Hinnant's days_from_civil / civil_from_days
std::int64_t days_from_civil(std::int64_t y, unsigned m, unsigned d) {
  y -= m <= 2;
  const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
  const unsigned yoe = static_cast<unsigned>(y - era * 400);
  const unsigned doy = (153 * (m > 2 ? m - 3 : m + 9) + 2) / 5 + d - 1;
  const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
  return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

void civil_from_days(std::int64_t z, std::int64_t& y, unsigned& m, unsigned& d) {
  z += 719468;
  const std::int64_t era = (z >= 0 ? z : z - 146096) / 146097;
  const unsigned doe = static_cast<unsigned>(z - era * 146097);
  const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
  y = static_cast<std::int64_t>(yoe) + era * 400;
  const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
  const unsigned mp = (5 * doy + 2) / 153;
  d = doy - (153 * mp + 2) / 5 + 1;
  m = mp < 10 ? mp + 3 : mp - 9;
  y += m <= 2;
}

bool leap(std::int64_t y) { return (y % 4 == 0 && y % 100 != 0) || y % 400 == 0; }

unsigned days_in_month(std::int64_t y, unsigned m) {
  static const unsigned dim[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
  return m == 2 && leap(y) ? 29 : dim[m - 1];
}

struct Cursor {
  const std::string& s;
  std::size_t i = 0;
  bool done() const { return i >= s.size(); }
  char peek() const { return done() ? '\0' : s[i]; }
  bool digits(int n, int& out) {
    out = 0;
    for (int k = 0; k < n; ++k) {
      if (done() || s[i] < '0' || s[i] > '9') return false;
      out = out * 10 + (s[i++] - '0');
    }
    return true;
  }
};

[[noreturn]] void invalid(const std::string& s) {
  throw std::invalid_argument("Invalid isoformat string: '" + s + "'");
}

}  // namespace

double parse_iso_timestamp(const std::string& raw) {
  std::string s;
  for (char c : raw) {  // str.replace("Z", "+00:00")
    if (c == 'Z') s += "+00:00";
    else s += c;
  }
  Cursor c{s};
  int y, mo, d;
  if (!c.digits(4, y)) invalid(raw);
  bool extended = c.peek() == '-';
  if (extended) ++c.i;
  if (!c.digits(2, mo)) invalid(raw);
  if (extended) {
    if (c.peek() != '-') invalid(raw);
    ++c.i;
  }
  if (!c.digits(2, d)) invalid(raw);
  if (mo < 1 || mo > 12 || d < 1 || static_cast<unsigned>(d) > days_in_month(y, mo)) invalid(raw);

  int h = 0, mi = 0, sec = 0;
  std::int64_t micros = 0;
  int offset_seconds = 0;
  if (!c.done()) {
    char sep = c.peek();
    if (sep != 'T' && sep != 't' && sep != ' ') invalid(raw);
    ++c.i;
    if (!c.digits(2, h)) invalid(raw);
    bool colon = c.peek() == ':';
    auto component = [&](int& out) {
      if (colon) {
        if (c.peek() != ':') return false;
        ++c.i;
      }
      return c.digits(2, out);
    };
    if (!c.done() && c.peek() != '+' && c.peek() != '-') {
      if (!component(mi)) invalid(raw);
      if (!c.done() && c.peek() != '+' && c.peek() != '-') {
        if (!component(sec)) invalid(raw);
        if (c.peek() == '.' || c.peek() == ',') {
          ++c.i;
          int ndig = 0;
          std::int64_t frac = 0;
          while (!c.done() && c.peek() >= '0' && c.peek() <= '9') {
            if (ndig < 6) frac = frac * 10 + (c.peek() - '0');
            ++ndig;
            ++c.i;
          }
          if (ndig == 0) invalid(raw);
          for (int k = ndig; k < 6; ++k) frac *= 10;
          micros = frac;
        }
      }
    }
    if (h > 23 || mi > 59 || sec > 59) invalid(raw);
    if (!c.done()) {
      char sign = c.peek();
      if (sign != '+' && sign != '-') invalid(raw);
      ++c.i;
      int oh = 0, om = 0, os = 0;
      if (!c.digits(2, oh)) invalid(raw);
      if (!c.done()) {
        if (c.peek() == ':') ++c.i;
        if (!c.digits(2, om)) invalid(raw);
        if (!c.done()) {
          if (c.peek() == ':') ++c.i;
          if (!c.digits(2, os)) invalid(raw);
        }
      }
      if (!c.done() || oh > 23 || om > 59 || os > 59) invalid(raw);
      offset_seconds = (oh * 3600 + om * 60 + os) * (sign == '-' ? -1 : 1);
    }
  }
  const std::int64_t days = days_from_civil(y, static_cast<unsigned>(mo), static_cast<unsigned>(d));
  const std::int64_t secs = days * 86400 + h * 3600 + mi * 60 + sec - offset_seconds;
  const std::int64_t total_us = secs * 1000000 + micros;
  return static_cast<double>(total_us) / 1e6;
}

std::string iso_from_epoch(std::int64_t secs) {
  std::int64_t days = secs / 86400;
  std::int64_t rem = secs % 86400;
  if (rem < 0) {
    rem += 86400;
    --days;
  }
  std::int64_t y;
  unsigned m, d;
  civil_from_days(days, y, m, d);
  char buf[64];
  std::snprintf(buf, sizeof buf, "%04lld-%02u-%02uT%02d:%02d:%02d+00:00",
                static_cast<long long>(y), m, d, static_cast<int>(rem / 3600),
                static_cast<int>((rem % 3600) / 60), static_cast<int>(rem % 60));
  return buf;
}

std::string now_iso_seconds() {
  using namespace std::chrono;
  auto secs = duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
  return iso_from_epoch(static_cast<std::int64_t>(secs));
}

}  // namespace abm::timeutil
