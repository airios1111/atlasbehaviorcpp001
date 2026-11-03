#include "abm/util/yaml.hpp"

#include "abm/util/regex.hpp"

#include <yaml-cpp/yaml.h>

#include <cmath>
#include <fstream>
#include <limits>
#include <sstream>

namespace abm::yaml {
namespace {

const Regex& rx_bool() {
  static const Regex r(R"(^(?:yes|Yes|YES|no|No|NO|true|True|TRUE|false|False|FALSE|on|On|ON|off|Off|OFF)\z)");
  return r;
}
const Regex& rx_float() {
  static const Regex r(
      R"(^(?:[-+]?(?:[0-9][0-9_]*)\.[0-9_]*(?:[eE][-+][0-9]+)?|\.[0-9_]+(?:[eE][-+][0-9]+)?|[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*|[-+]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))\z)");
  return r;
}
const Regex& rx_int() {
  static const Regex r(
      R"(^(?:[-+]?0b[0-1_]+|[-+]?0[0-7_]+|[-+]?(?:0|[1-9][0-9_]*)|[-+]?0x[0-9a-fA-F_]+|[-+]?[1-9][0-9_]*(?::[0-5]?[0-9])+)\z)");
  return r;
}
const Regex& rx_null() {
  static const Regex r(R"(^(?:~|null|Null|NULL|)\z)");
  return r;
}
const Regex& rx_timestamp() {
  static const Regex r(
      R"(^(?:[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]|[0-9][0-9][0-9][0-9]-[0-9][0-9]?-[0-9][0-9]?(?:[Tt]|[ \t]+)[0-9][0-9]?:[0-9][0-9]:[0-9][0-9](?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9][0-9]?(?::[0-9][0-9])?))?)\z)");
  return r;
}

std::string without_underscores(const std::string& s) {
  std::string out;
  for (char c : s)
    if (c != '_') out += c;
  return out;
}

Value construct_int(std::string v) {
  v = without_underscores(v);
  int sign = 1;
  if (!v.empty() && (v[0] == '-' || v[0] == '+')) {
    if (v[0] == '-') sign = -1;
    v.erase(0, 1);
  }
  long double result = 0;
  if (v == "0") return 0;
  if (v.rfind("0b", 0) == 0) {
    for (char c : v.substr(2)) result = result * 2 + (c - '0');
  } else if (v.rfind("0x", 0) == 0) {
    result = static_cast<long double>(std::stoull(v.substr(2), nullptr, 16));
  } else if (v[0] == '0') {
    result = static_cast<long double>(std::stoull(v, nullptr, 8));
  } else if (v.find(':') != std::string::npos) {
    long double base = 1;
    std::vector<std::string> parts;
    std::stringstream ss(v);
    std::string p;
    while (std::getline(ss, p, ':')) parts.push_back(p);
    for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
      result += std::stoll(*it) * base;
      base *= 60;
    }
  } else {
    if (v.size() <= 18) return static_cast<std::int64_t>(std::stoll(v)) * sign;
    result = std::stold(v);
  }
  result *= sign;
  if (result >= static_cast<long double>(std::numeric_limits<std::int64_t>::min()) &&
      result <= static_cast<long double>(std::numeric_limits<std::int64_t>::max()))
    return static_cast<std::int64_t>(result);
  return static_cast<double>(result);
}

Value construct_float(std::string v) {
  v = py::lower(without_underscores(v));
  double sign = 1;
  if (!v.empty() && (v[0] == '-' || v[0] == '+')) {
    if (v[0] == '-') sign = -1;
    v.erase(0, 1);
  }
  if (v == ".inf") return sign * std::numeric_limits<double>::infinity();
  if (v == ".nan") return std::numeric_limits<double>::quiet_NaN();
  if (v.find(':') != std::string::npos) {
    std::vector<std::string> parts;
    std::stringstream ss(v);
    std::string p;
    while (std::getline(ss, p, ':')) parts.push_back(p);
    double base = 1, value = 0;
    for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
      value += std::stod(*it) * base;
      base *= 60;
    }
    return sign * value;
  }
  return sign * std::stod(v);
}

Value from_node(const YAML::Node& n) {
  switch (n.Type()) {
    case YAML::NodeType::Null: {
      const std::string& tag = n.Tag();
      if (tag == "!" ) return std::string();
      return nullptr;
    }
    case YAML::NodeType::Scalar: {
      const std::string& tag = n.Tag();
      const std::string& s = n.Scalar();
      if (tag == "?" || tag.empty()) return resolve_plain(s);
      if (tag == "!" || tag == "tag:yaml.org,2002:str") return s;
      if (tag == "tag:yaml.org,2002:int") return construct_int(s);
      if (tag == "tag:yaml.org,2002:float") return construct_float(s);
      if (tag == "tag:yaml.org,2002:bool") return resolve_plain(s);
      if (tag == "tag:yaml.org,2002:null") return nullptr;
      throw YamlError("could not determine a constructor for the tag '" + tag + "'");
    }
    case YAML::NodeType::Sequence: {
      Value arr = Value::array();
      for (const auto& item : n) arr.push_back(from_node(item));
      return arr;
    }
    case YAML::NodeType::Map: {
      Value obj = Value::object();
      for (const auto& kv : n) {
        Value key = from_node(kv.first);
        std::string k = key.is_string() ? key.get<std::string>() : py::str(key);
        obj[k] = from_node(kv.second);
      }
      return obj;
    }
    default: return nullptr;
  }
}

// ---------------------------------------------------------------- emitter
char32_t decode(std::string_view s, std::size_t& i) {
  auto c = static_cast<unsigned char>(s[i]);
  int n = c < 0x80 ? 0 : (c >> 5) == 0x6 ? 1 : (c >> 4) == 0xE ? 2 : (c >> 3) == 0x1E ? 3 : 0;
  char32_t cp = n == 0 ? c : c & (0x3F >> n);
  for (int k = 1; k <= n && i + k < s.size(); ++k)
    cp = (cp << 6) | (static_cast<unsigned char>(s[i + k]) & 0x3F);
  i += n + 1;
  return cp;
}

bool yaml_printable(char32_t ch, bool allow_unicode) {
  if (ch == 0x09 || ch == 0x0A || ch == 0x0D || (ch >= 0x20 && ch <= 0x7E)) return true;
  if (!allow_unicode) return false;
  if (ch == 0xFEFF) return false;
  return ch == 0x85 || (ch >= 0xA0 && ch <= 0xD7FF) || (ch >= 0xE000 && ch <= 0xFFFD) ||
         (ch >= 0x10000 && ch < 0x10FFFF);
}

bool resolves_to_non_string(const std::string& s) {
  if (!resolve_plain(s).is_string()) return true;
  return rx_timestamp().search(s) || s == "<<" || s == "=";
}

enum class Style { Plain, Single, Double };

Style choose_style(const std::string& s, bool allow_unicode) {
  if (s.empty()) return Style::Single;
  bool special = false, line_break = false, block_ind = false;
  std::size_t i = 0;
  std::size_t index = 0;
  char32_t prev = 0;
  while (i < s.size()) {
    char32_t ch = decode(s, i);
    char32_t next = i < s.size() ? static_cast<unsigned char>(s[i]) : 0;
    bool followed_by_ws = i >= s.size() || next == ' ' || next == '\t' || next == '\n' || next == '\r';
    bool preceded_by_ws = index == 0 || prev == ' ' || prev == '\t' || prev == '\n' || prev == '\r';
    if (index == 0) {
      if (std::u32string_view(U"#,[]{}&*!|>'\"%@`").find(ch) != std::u32string_view::npos)
        block_ind = true;
      if ((ch == '?' || ch == ':' || ch == '-') && followed_by_ws) block_ind = true;
    } else {
      if (ch == ':' && followed_by_ws) block_ind = true;
      if (ch == '#' && preceded_by_ws) block_ind = true;
    }
    if (ch == '\n' || ch == '\r' || ch == 0x85 || ch == 0x2028 || ch == 0x2029) line_break = true;
    if (!yaml_printable(ch, allow_unicode)) special = true;
    prev = ch;
    ++index;
  }
  if (special) return Style::Double;
  if (line_break) return Style::Double;
  const char first = s.front(), last = s.back();
  const bool edge_space = first == ' ' || last == ' ' || first == '\t' || last == '\t';
  const bool doc_marker = s.rfind("---", 0) == 0 || s.rfind("...", 0) == 0;
  if (block_ind || edge_space || doc_marker || resolves_to_non_string(s)) return Style::Single;
  return Style::Plain;
}

std::string hexn(unsigned long v, int width) {
  std::string out(width, '0');
  for (int i = width - 1; i >= 0; --i, v >>= 4) out[i] = "0123456789ABCDEF"[v & 0xF];
  return out;
}

std::string quote_double(const std::string& s, bool allow_unicode) {
  std::string out = "\"";
  for (std::size_t i = 0; i < s.size();) {
    std::size_t start = i;
    char32_t ch = decode(s, i);
    switch (ch) {
      case 0: out += "\\0"; break;
      case 0x07: out += "\\a"; break;
      case 0x08: out += "\\b"; break;
      case 0x09: out += "\\t"; break;
      case 0x0A: out += "\\n"; break;
      case 0x0B: out += "\\v"; break;
      case 0x0C: out += "\\f"; break;
      case 0x0D: out += "\\r"; break;
      case 0x1B: out += "\\e"; break;
      case '"': out += "\\\""; break;
      case '\\': out += "\\\\"; break;
      case 0x85: out += "\\N"; break;
      case 0xA0: out += "\\_"; break;
      case 0x2028: out += "\\L"; break;
      case 0x2029: out += "\\P"; break;
      default:
        if (yaml_printable(ch, allow_unicode)) {
          out.append(s, start, i - start);
        } else if (ch <= 0xFF) {
          out += "\\x" + hexn(ch, 2);
        } else if (ch <= 0xFFFF) {
          out += "\\u" + hexn(ch, 4);
        } else {
          out += "\\U" + hexn(ch, 8);
        }
    }
  }
  return out + "\"";
}

std::string scalar(const Value& v, const DumpOptions& opts) {
  switch (v.type()) {
    case Value::value_t::null: return "null";
    case Value::value_t::boolean: return v.get<bool>() ? "true" : "false";
    case Value::value_t::number_integer:
    case Value::value_t::number_unsigned: return py::repr(v);
    case Value::value_t::number_float: {
      double d = v.get<double>();
      if (std::isnan(d)) return ".nan";
      if (std::isinf(d)) return d > 0 ? ".inf" : "-.inf";
      std::string r = py::lower(py::float_repr(d));
      if (r.find('.') == std::string::npos && r.find('e') != std::string::npos)
        r.insert(r.find('e'), ".0");
      return r;
    }
    case Value::value_t::string: {
      const std::string& s = v.get_ref<const std::string&>();
      switch (choose_style(s, opts.allow_unicode)) {
        case Style::Plain: return s;
        case Style::Single: {
          std::string out = "'";
          for (char c : s) {
            if (c == '\'') out += "''";
            else out += c;
          }
          return out + "'";
        }
        case Style::Double: return quote_double(s, opts.allow_unicode);
      }
      return s;
    }
    case Value::value_t::array: return "[]";
    case Value::value_t::object: return "{}";
    default: return "null";
  }
}

void emit_list(std::string& out, const Value& list, int indent, bool first_inline,
               const DumpOptions& opts);

void emit_map(std::string& out, const Value& map, int indent, bool first_inline,
              const DumpOptions& opts) {
  bool first = true;
  for (auto it = map.begin(); it != map.end(); ++it) {
    if (!(first && first_inline)) out.append(static_cast<std::size_t>(indent), ' ');
    first = false;
    out += scalar(Value(it.key()), opts) + ":";
    const Value& v = it.value();
    if (v.is_object() && !v.empty()) {
      out += "\n";
      emit_map(out, v, indent + 2, false, opts);
    } else if (v.is_array() && !v.empty()) {
      out += "\n";
      emit_list(out, v, indent, false, opts);
    } else {
      out += " " + scalar(v, opts) + "\n";
    }
  }
}

void emit_list(std::string& out, const Value& list, int indent, bool first_inline,
               const DumpOptions& opts) {
  bool first = true;
  for (const auto& item : list) {
    if (!(first && first_inline)) out.append(static_cast<std::size_t>(indent), ' ');
    first = false;
    out += "- ";
    if (item.is_object() && !item.empty()) {
      emit_map(out, item, indent + 2, true, opts);
    } else if (item.is_array() && !item.empty()) {
      emit_list(out, item, indent + 2, true, opts);
    } else {
      out += scalar(item, opts) + "\n";
    }
  }
}

std::string dump_doc(const Value& v, const DumpOptions& opts) {
  std::string out;
  if (v.is_object() && !v.empty()) emit_map(out, v, 0, false, opts);
  else if (v.is_array() && !v.empty()) emit_list(out, v, 0, false, opts);
  else out = scalar(v, opts) + "\n...\n";
  return out;
}

}  // namespace

Value resolve_plain(const std::string& s) {
  if (rx_null().search(s)) return nullptr;
  if (rx_bool().search(s)) {
    const std::string l = py::lower(s);
    return l == "yes" || l == "true" || l == "on";
  }
  if (rx_int().search(s)) return construct_int(s);
  if (rx_float().search(s)) return construct_float(s);
  return s;
}

Value load(const std::string& text) {
  try {
    YAML::Node n = YAML::Load(text);
    return from_node(n);
  } catch (const YAML::Exception& e) {
    throw YamlError(e.what());
  }
}

std::vector<Value> load_all(const std::string& text) {
  try {
    std::vector<Value> out;
    for (const auto& n : YAML::LoadAll(text)) out.push_back(from_node(n));
    return out;
  } catch (const YAML::Exception& e) {
    throw YamlError(e.what());
  }
}

std::string read_text(const std::filesystem::path& path) {
  std::ifstream in(path, std::ios::binary);
  if (!in) throw std::runtime_error("[Errno 2] No such file or directory: '" + path.string() + "'");
  std::ostringstream ss;
  ss << in.rdbuf();
  std::string s = ss.str();
  if (s.rfind("\xEF\xBB\xBF", 0) == 0) s.erase(0, 3);  // tolerate UTF-8 BOM
  return s;
}

void write_text(const std::filesystem::path& path, const std::string& content) {
  std::ofstream out(path, std::ios::binary | std::ios::trunc);
  if (!out) throw std::runtime_error("cannot write " + path.string());
  out << content;
}

Value load_file(const std::filesystem::path& path) { return load(read_text(path)); }

std::string dump(const Value& v, DumpOptions opts) { return dump_doc(v, opts); }

std::string dump_all(const std::vector<Value>& docs, DumpOptions opts) {
  std::string out;
  for (std::size_t i = 0; i < docs.size(); ++i) {
    if (i) out += "---\n";
    out += dump_doc(docs[i], opts);
  }
  return out;
}

}  // namespace abm::yaml
