// PCRE2-backed regular expressions with Python `re` semantics for str patterns
// (Unicode-aware \w \d \s \b, inline flags such as (?i), re.search / re.match behaviour).
#pragma once

#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace abm {

class RegexError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

class Regex {
 public:
  // Throws RegexError when the pattern does not compile.
  explicit Regex(std::string pattern);
  ~Regex();
  Regex(const Regex&) = delete;
  Regex& operator=(const Regex&) = delete;

  // re.search(pattern, subject) is not None
  bool search(std::string_view subject) const;
  // re.search(...) capture groups (index 0 = whole match); unset groups are std::nullopt.
  std::optional<std::vector<std::optional<std::string>>> search_groups(std::string_view subject) const;
  // re.sub(pattern, fn, subject) where fn receives the capture groups of each match
  template <class Fn>
  std::string sub(std::string_view subject, Fn&& fn) const;

  const std::string& pattern() const { return pattern_; }

 private:
  struct Match {
    std::size_t begin, end;
    std::vector<std::optional<std::string>> groups;
  };
  std::optional<Match> find_at(std::string_view subject, std::size_t offset) const;

  std::string pattern_;
  void* code_ = nullptr;  // pcre2_code_8*
};

// Compiled-pattern cache (Python's re module caches compiled patterns as well).
std::shared_ptr<const Regex> regex_cached(const std::string& pattern);

template <class Fn>
std::string Regex::sub(std::string_view subject, Fn&& fn) const {
  std::string out;
  std::size_t pos = 0;
  while (pos <= subject.size()) {
    auto m = find_at(subject, pos);
    if (!m) break;
    out.append(subject.substr(pos, m->begin - pos));
    out += fn(m->groups);
    if (m->end == m->begin) {
      if (m->end < subject.size()) out += subject[m->end];
      pos = m->end + 1;
    } else {
      pos = m->end;
    }
  }
  if (pos < subject.size()) out.append(subject.substr(pos));
  return out;
}

}  // namespace abm
