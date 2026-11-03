#include "abm/util/regex.hpp"

#include <pcre2.h>

#include <cctype>
#include <mutex>
#include <unordered_map>

namespace abm {
namespace {

bool is_hex(char c) { return std::isxdigit(static_cast<unsigned char>(c)) != 0; }

// Translate the few Python-only escapes into their PCRE2 spelling:
//   \Z -> \z,  \uXXXX -> \x{XXXX},  \UXXXXXXXX -> \x{XXXXXXXX}
std::string translate(const std::string& p) {
  std::string out;
  out.reserve(p.size());
  for (std::size_t i = 0; i < p.size(); ++i) {
    if (p[i] != '\\' || i + 1 >= p.size()) {
      out += p[i];
      continue;
    }
    char n = p[i + 1];
    if (n == 'Z') {
      out += "\\z";
      ++i;
    } else if ((n == 'u' && i + 6 <= p.size()) ||
               (n == 'U' && i + 10 <= p.size())) {
      std::size_t len = n == 'u' ? 4 : 8;
      bool ok = true;
      for (std::size_t k = 0; k < len; ++k) ok = ok && is_hex(p[i + 2 + k]);
      if (ok) {
        out += "\\x{" + p.substr(i + 2, len) + "}";
        i += 1 + len;
      } else {
        out += p[i];
        out += n;
        ++i;
      }
    } else {
      out += p[i];
      out += n;
      ++i;
    }
  }
  return out;
}

pcre2_code_8* as_code(void* p) { return static_cast<pcre2_code_8*>(p); }

}  // namespace

Regex::Regex(std::string pattern) : pattern_(std::move(pattern)) {
  const std::string translated = translate(pattern_);
  int errcode = 0;
  PCRE2_SIZE erroffset = 0;
  code_ = pcre2_compile_8(reinterpret_cast<PCRE2_SPTR8>(translated.data()), translated.size(),
                          PCRE2_UTF | PCRE2_UCP | PCRE2_MATCH_INVALID_UTF, &errcode, &erroffset,
                          nullptr);
  if (!code_) {
    PCRE2_UCHAR8 buf[256];
    pcre2_get_error_message_8(errcode, buf, sizeof buf);
    throw RegexError(std::string(reinterpret_cast<const char*>(buf)) + " at position " +
                     std::to_string(erroffset));
  }
}

Regex::~Regex() { pcre2_code_free_8(as_code(code_)); }

std::optional<Regex::Match> Regex::find_at(std::string_view subject, std::size_t offset) const {
  pcre2_match_data_8* md = pcre2_match_data_create_from_pattern_8(as_code(code_), nullptr);
  int rc = pcre2_match_8(as_code(code_), reinterpret_cast<PCRE2_SPTR8>(subject.data()),
                         subject.size(), offset, 0, md, nullptr);
  if (rc < 0) {
    pcre2_match_data_free_8(md);
    return std::nullopt;
  }
  PCRE2_SIZE* ov = pcre2_get_ovector_pointer_8(md);
  uint32_t pairs = pcre2_get_ovector_count_8(md);
  Match m{ov[0], ov[1], {}};
  for (uint32_t g = 0; g < pairs; ++g) {
    if (ov[2 * g] == PCRE2_UNSET) {
      m.groups.emplace_back(std::nullopt);
    } else {
      m.groups.emplace_back(std::string(subject.substr(ov[2 * g], ov[2 * g + 1] - ov[2 * g])));
    }
  }
  pcre2_match_data_free_8(md);
  return m;
}

bool Regex::search(std::string_view subject) const { return find_at(subject, 0).has_value(); }

std::optional<std::vector<std::optional<std::string>>> Regex::search_groups(
    std::string_view subject) const {
  auto m = find_at(subject, 0);
  if (!m) return std::nullopt;
  return m->groups;
}

std::shared_ptr<const Regex> regex_cached(const std::string& pattern) {
  static std::mutex mu;
  static std::unordered_map<std::string, std::shared_ptr<const Regex>> cache;
  std::lock_guard<std::mutex> lock(mu);
  auto it = cache.find(pattern);
  if (it != cache.end()) return it->second;
  auto rx = std::make_shared<const Regex>(pattern);
  cache.emplace(pattern, rx);
  return rx;
}

}  // namespace abm
