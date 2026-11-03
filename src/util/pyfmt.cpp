#include "abm/util/pyfmt.hpp"

#include <algorithm>
#include <charconv>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <stdexcept>

namespace abm::py {
namespace {

std::string type_name(const Value& v) {
  switch (v.type()) {
    case Value::value_t::null: return "NoneType";
    case Value::value_t::boolean: return "bool";
    case Value::value_t::number_integer:
    case Value::value_t::number_unsigned: return "int";
    case Value::value_t::number_float: return "float";
    case Value::value_t::string: return "str";
    case Value::value_t::array: return "list";
    case Value::value_t::object: return "dict";
    default: return "object";
  }
}

// Decode one UTF-8 code point starting at s[i]; advances i. Invalid bytes decode as themselves.
char32_t next_cp(std::string_view s, std::size_t& i) {
  auto c = static_cast<unsigned char>(s[i]);
  int n = c < 0x80 ? 0 : (c >> 5) == 0x6 ? 1 : (c >> 4) == 0xE ? 2 : (c >> 3) == 0x1E ? 3 : -1;
  if (n <= 0 || i + static_cast<std::size_t>(n) >= s.size()) {
    ++i;
    return c;
  }
  char32_t cp = c & (0x3F >> n);
  for (int k = 1; k <= n; ++k) {
    auto cc = static_cast<unsigned char>(s[i + k]);
    if ((cc >> 6) != 0x2) {
      ++i;
      return c;
    }
    cp = (cp << 6) | (cc & 0x3F);
  }
  i += n + 1;
  return cp;
}

void append_utf8(std::string& out, char32_t cp) {
  if (cp < 0x80) {
    out += static_cast<char>(cp);
  } else if (cp < 0x800) {
    out += static_cast<char>(0xC0 | (cp >> 6));
    out += static_cast<char>(0x80 | (cp & 0x3F));
  } else if (cp < 0x10000) {
    out += static_cast<char>(0xE0 | (cp >> 12));
    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
    out += static_cast<char>(0x80 | (cp & 0x3F));
  } else {
    out += static_cast<char>(0xF0 | (cp >> 18));
    out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
    out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
    out += static_cast<char>(0x80 | (cp & 0x3F));
  }
}

// Approximation of str.isprintable() for a single code point (no full Unicode tables).
bool printable(char32_t cp) {
  if (cp < 0x20 || cp == 0x7F) return false;
  if (cp < 0x7F) return true;
  if (cp >= 0x80 && cp <= 0xA0) return false;  // C1 controls + NBSP (Zs)
  if (cp == 0xAD) return false;                // soft hyphen (Cf)
  if (cp >= 0x2000 && cp <= 0x200F) return false;
  if (cp >= 0x2028 && cp <= 0x202F) return false;
  if (cp >= 0x205F && cp <= 0x206F) return false;
  if (cp == 0x1680 || cp == 0x180E || cp == 0x3000 || cp == 0xFEFF) return false;
  if (cp >= 0xD800 && cp <= 0xF8FF) return false;  // surrogates + private use
  if (cp >= 0xFFF0 && cp <= 0xFFFF) return false;
  if (cp >= 0xE0000) return false;  // tags, variation selectors supplement, private planes
  return true;
}

char hex_digit(unsigned v) { return "0123456789abcdef"[v & 0xF]; }

std::string hex(unsigned long v, int width) {
  std::string s(width, '0');
  for (int i = width - 1; i >= 0; --i, v >>= 4) s[i] = hex_digit(static_cast<unsigned>(v));
  return s;
}

void dump_json_str(std::string& out, std::string_view s) {
  out += '"';
  for (std::size_t i = 0; i < s.size();) {
    char32_t cp = next_cp(s, i);
    switch (cp) {
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case '\n': out += "\\n"; break;
      case '\r': out += "\\r"; break;
      case '\t': out += "\\t"; break;
      case '\b': out += "\\b"; break;
      case '\f': out += "\\f"; break;
      default:
        if (cp < 0x20 || (cp >= 0x7F && cp < 0x10000)) {
          out += "\\u" + hex(cp, 4);
        } else if (cp >= 0x10000) {
          char32_t v = cp - 0x10000;
          out += "\\u" + hex(0xD800 + (v >> 10), 4);
          out += "\\u" + hex(0xDC00 + (v & 0x3FF), 4);
        } else {
          out += static_cast<char>(cp);
        }
    }
  }
  out += '"';
}

std::string json_float(double d) {
  if (std::isnan(d)) return "NaN";
  if (std::isinf(d)) return d > 0 ? "Infinity" : "-Infinity";
  return float_repr(d);
}

void dump_json(std::string& out, const Value& v, int indent, bool sort_keys, int level, bool compact) {
  const bool pretty = indent >= 0;
  auto newline = [&](int lvl) {
    out += '\n';
    out.append(static_cast<std::size_t>(indent * lvl), ' ');
  };
  switch (v.type()) {
    case Value::value_t::null: out += "null"; return;
    case Value::value_t::boolean: out += v.get<bool>() ? "true" : "false"; return;
    case Value::value_t::number_integer: out += std::to_string(v.get<std::int64_t>()); return;
    case Value::value_t::number_unsigned: out += std::to_string(v.get<std::uint64_t>()); return;
    case Value::value_t::number_float: out += json_float(v.get<double>()); return;
    case Value::value_t::string: dump_json_str(out, v.get_ref<const std::string&>()); return;
    case Value::value_t::array: {
      if (v.empty()) {
        out += "[]";
        return;
      }
      out += '[';
      bool first = true;
      for (const auto& item : v) {
        if (!first) out += (pretty || compact) ? "," : ", ";
        first = false;
        if (pretty) newline(level + 1);
        dump_json(out, item, indent, sort_keys, level + 1, compact);
      }
      if (pretty) newline(level);
      out += ']';
      return;
    }
    case Value::value_t::object: {
      if (v.empty()) {
        out += "{}";
        return;
      }
      std::vector<std::pair<const std::string*, const Value*>> items;
      for (auto it = v.begin(); it != v.end(); ++it) items.emplace_back(&it.key(), &it.value());
      if (sort_keys) {
        std::stable_sort(items.begin(), items.end(),
                         [](const auto& a, const auto& b) { return *a.first < *b.first; });
      }
      out += '{';
      bool first = true;
      for (const auto& [k, val] : items) {
        if (!first) out += (pretty || compact) ? "," : ", ";
        first = false;
        if (pretty) newline(level + 1);
        dump_json_str(out, *k);
        out += compact ? ":" : ": ";
        dump_json(out, *val, indent, sort_keys, level + 1, compact);
      }
      if (pretty) newline(level);
      out += '}';
      return;
    }
    default: out += "null"; return;
  }
}

bool is_int(const Value& v) {
  return v.is_number_integer() || v.is_boolean();
}

}  // namespace

std::string float_repr(double v) {
  if (std::isnan(v)) return "nan";
  if (std::isinf(v)) return v > 0 ? "inf" : "-inf";
  if (v == 0.0) return std::signbit(v) ? "-0.0" : "0.0";

  char buf[64];
  auto res = std::to_chars(buf, buf + sizeof buf, v, std::chars_format::scientific);
  std::string sci(buf, res.ptr);
  std::string sign;
  if (sci[0] == '-') {
    sign = "-";
    sci.erase(0, 1);
  }
  auto epos = sci.find('e');
  std::string mant = sci.substr(0, epos);
  int exp = std::stoi(sci.substr(epos + 1));
  std::string digits;
  for (char c : mant)
    if (c != '.') digits += c;
  while (digits.size() > 1 && digits.back() == '0') digits.pop_back();
  const int n = static_cast<int>(digits.size());
  const int decpt = exp + 1;

  std::string out;
  if (decpt <= -4 || decpt > 16) {
    out = digits.substr(0, 1);
    if (n > 1) out += "." + digits.substr(1);
    int e = decpt - 1;
    out += e < 0 ? "e-" : "e+";
    std::string es = std::to_string(std::abs(e));
    if (es.size() < 2) es = "0" + es;
    out += es;
  } else if (decpt <= 0) {
    out = "0." + std::string(static_cast<std::size_t>(-decpt), '0') + digits;
  } else if (decpt >= n) {
    out = digits + std::string(static_cast<std::size_t>(decpt - n), '0') + ".0";
  } else {
    out = digits.substr(0, static_cast<std::size_t>(decpt)) + "." +
          digits.substr(static_cast<std::size_t>(decpt));
  }
  return sign + out;
}

std::string format_g(double v, int precision) {
  if (std::isnan(v)) return "nan";
  if (std::isinf(v)) return v > 0 ? "inf" : "-inf";
  char buf[512];
  std::snprintf(buf, sizeof buf, "%.*g", precision, v);
  return buf;
}

std::string format_f(double v, int precision) {
  if (std::isnan(v)) return "nan";
  if (std::isinf(v)) return v > 0 ? "inf" : "-inf";
  std::vector<char> buf(512);
  int n = std::snprintf(buf.data(), buf.size(), "%.*f", precision, v);
  if (n >= static_cast<int>(buf.size())) {
    buf.resize(static_cast<std::size_t>(n) + 1);
    std::snprintf(buf.data(), buf.size(), "%.*f", precision, v);
  }
  return buf.data();
}

double round(double v, int ndigits) {
  if (!std::isfinite(v)) return v;
  if (std::fabs(v) >= 1e15) return v;
  std::string s = format_f(v, ndigits);
  return std::strtod(s.c_str(), nullptr);
}

std::string repr_str(std::string_view s) {
  const bool has_single = s.find('\'') != std::string_view::npos;
  const bool has_double = s.find('"') != std::string_view::npos;
  const char q = (has_single && !has_double) ? '"' : '\'';
  std::string out(1, q);
  for (std::size_t i = 0; i < s.size();) {
    char32_t cp = next_cp(s, i);
    if (cp == static_cast<char32_t>(q) || cp == '\\') {
      out += '\\';
      out += static_cast<char>(cp);
    } else if (cp == '\t') {
      out += "\\t";
    } else if (cp == '\n') {
      out += "\\n";
    } else if (cp == '\r') {
      out += "\\r";
    } else if (!printable(cp)) {
      if (cp < 0x100) out += "\\x" + hex(cp, 2);
      else if (cp < 0x10000) out += "\\u" + hex(cp, 4);
      else out += "\\U" + hex(cp, 8);
    } else {
      append_utf8(out, cp);
    }
  }
  out += q;
  return out;
}

std::string repr(const Value& v) {
  switch (v.type()) {
    case Value::value_t::null: return "None";
    case Value::value_t::boolean: return v.get<bool>() ? "True" : "False";
    case Value::value_t::number_integer: return std::to_string(v.get<std::int64_t>());
    case Value::value_t::number_unsigned: return std::to_string(v.get<std::uint64_t>());
    case Value::value_t::number_float: return float_repr(v.get<double>());
    case Value::value_t::string: return repr_str(v.get_ref<const std::string&>());
    case Value::value_t::array: {
      std::string out = "[";
      bool first = true;
      for (const auto& item : v) {
        if (!first) out += ", ";
        first = false;
        out += repr(item);
      }
      return out + "]";
    }
    case Value::value_t::object: {
      std::string out = "{";
      bool first = true;
      for (auto it = v.begin(); it != v.end(); ++it) {
        if (!first) out += ", ";
        first = false;
        out += repr_str(it.key()) + ": " + repr(it.value());
      }
      return out + "}";
    }
    default: return "None";
  }
}

std::string str(const Value& v) {
  if (v.is_string()) return v.get<std::string>();
  return repr(v);
}

std::string repr_list(const std::vector<std::string>& items) {
  std::string out = "[";
  for (std::size_t i = 0; i < items.size(); ++i) {
    if (i) out += ", ";
    out += repr_str(items[i]);
  }
  return out + "]";
}

std::string json_dumps(const Value& v, int indent, bool sort_keys, bool compact) {
  std::string out;
  dump_json(out, v, indent, sort_keys, 0, compact);
  return out;
}

bool truthy(const Value& v) {
  switch (v.type()) {
    case Value::value_t::null: return false;
    case Value::value_t::boolean: return v.get<bool>();
    case Value::value_t::number_integer: return v.get<std::int64_t>() != 0;
    case Value::value_t::number_unsigned: return v.get<std::uint64_t>() != 0;
    case Value::value_t::number_float: return v.get<double>() != 0.0;
    case Value::value_t::string:
    case Value::value_t::array:
    case Value::value_t::object: return !v.empty();
    default: return false;
  }
}

bool is_number(const Value& v) { return v.is_number() || v.is_boolean(); }

double to_double(const Value& v) {
  if (v.is_boolean()) return v.get<bool>() ? 1.0 : 0.0;
  if (v.is_number_unsigned()) return static_cast<double>(v.get<std::uint64_t>());
  if (v.is_number_integer()) return static_cast<double>(v.get<std::int64_t>());
  if (v.is_number_float()) return v.get<double>();
  throw std::runtime_error("float() argument must be a string or a real number, not '" +
                           type_name(v) + "'");
}

bool eq(const Value& a, const Value& b) {
  if (is_number(a) && is_number(b)) {
    if (is_int(a) && is_int(b)) {
      auto as_i = [](const Value& x) -> long double {
        if (x.is_boolean()) return x.get<bool>() ? 1 : 0;
        if (x.is_number_unsigned()) return static_cast<long double>(x.get<std::uint64_t>());
        return static_cast<long double>(x.get<std::int64_t>());
      };
      return as_i(a) == as_i(b);
    }
    return to_double(a) == to_double(b);
  }
  if (a.type() != b.type()) return false;
  if (a.is_null()) return true;
  if (a.is_string()) return a.get_ref<const std::string&>() == b.get_ref<const std::string&>();
  if (a.is_array()) {
    if (a.size() != b.size()) return false;
    for (std::size_t i = 0; i < a.size(); ++i)
      if (!eq(a[i], b[i])) return false;
    return true;
  }
  if (a.is_object()) {
    if (a.size() != b.size()) return false;
    for (auto it = a.begin(); it != a.end(); ++it) {
      auto f = b.find(it.key());
      if (f == b.end() || !eq(it.value(), *f)) return false;
    }
    return true;
  }
  return false;
}

bool contains(const Value& container, const Value& item) {
  if (container.is_array()) {
    for (const auto& x : container)
      if (eq(x, item)) return true;
    return false;
  }
  if (container.is_string()) {
    if (!item.is_string())
      throw std::runtime_error("'in <string>' requires string as left operand, not " +
                               type_name(item));
    return container.get_ref<const std::string&>().find(item.get_ref<const std::string&>()) !=
           std::string::npos;
  }
  if (container.is_object()) {
    if (item.is_array() || item.is_object())
      throw std::runtime_error("unhashable type: '" + type_name(item) + "'");
    return item.is_string() && container.contains(item.get<std::string>());
  }
  throw std::runtime_error("argument of type '" + type_name(container) + "' is not iterable");
}

double floordiv(double a, double b) {
  double mod = std::fmod(a, b);
  double div = (a - mod) / b;
  if (mod != 0.0 && ((b < 0) != (mod < 0))) div -= 1.0;
  double fl;
  if (div != 0.0) {
    fl = std::floor(div);
    if (div - fl > 0.5) fl += 1.0;
  } else {
    fl = std::copysign(0.0, a / b);
  }
  return fl;
}

std::string upper(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return (c >= 'a' && c <= 'z') ? c - 32 : c; });
  return s;
}

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(),
                 [](unsigned char c) { return (c >= 'A' && c <= 'Z') ? c + 32 : c; });
  return s;
}

std::size_t utf8_len(std::string_view s) {
  std::size_t n = 0;
  for (unsigned char c : s)
    if ((c & 0xC0) != 0x80) ++n;
  return n;
}

std::string join(const std::vector<std::string>& parts, std::string_view sep) {
  std::string out;
  for (std::size_t i = 0; i < parts.size(); ++i) {
    if (i) out += sep;
    out += parts[i];
  }
  return out;
}

std::string strip(std::string_view s) {
  auto ws = [](char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v'; };
  std::size_t b = 0, e = s.size();
  while (b < e && ws(s[b])) ++b;
  while (e > b && ws(s[e - 1])) --e;
  return std::string(s.substr(b, e - b));
}

}  // namespace abm::py
