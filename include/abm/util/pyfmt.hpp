// Python-compatible value semantics and formatting.
//
// The reference implementation of ATLAS Behavior Map was written in Python, and several outputs
// (SIEM rules, JSON reports, evidence strings, response-plan templating) embed Python's textual
// representations. These helpers reproduce them exactly so the C++ port emits identical artifacts.
#pragma once

#include <nlohmann/json.hpp>

#include <string>
#include <string_view>
#include <vector>

namespace abm {

// Dynamic, insertion-ordered value: the C++ counterpart of the parsed YAML / JSON Python objects.
using Value = nlohmann::ordered_json;

namespace py {

// float.__repr__  e.g. 5000.0 -> "5000.0", 1e-05 -> "1e-05", 1e16 -> "1e+16"
std::string float_repr(double v);
// format(v, ".{precision}g")
std::string format_g(double v, int precision = 6);
// format(v, ".{precision}f")
std::string format_f(double v, int precision);
// round(v, ndigits) for floats (correctly rounded, half-even on the exact binary value)
double round(double v, int ndigits);

// repr(obj) / str(obj) for JSON-like values
std::string repr(const Value& v);
std::string str(const Value& v);
std::string repr_str(std::string_view s);
std::string repr_list(const std::vector<std::string>& items);

// json.dumps(obj, indent=..., sort_keys=...) with Python's default separators and ensure_ascii=True
// compact=true is separators=(",", ":")
std::string json_dumps(const Value& v, int indent = -1, bool sort_keys = false, bool compact = false);

// truthiness, ==, isinstance(x, (int, float)), float(x), `item in container`
bool truthy(const Value& v);
bool eq(const Value& a, const Value& b);
bool is_number(const Value& v);
double to_double(const Value& v);
bool contains(const Value& container, const Value& item);  // throws std::runtime_error on TypeError

// float // int as Python computes it
double floordiv(double a, double b);

// str.upper() / str.lower() for ASCII; number of code points in a UTF-8 string
std::string upper(std::string s);
std::string lower(std::string s);
std::size_t utf8_len(std::string_view s);
std::string join(const std::vector<std::string>& parts, std::string_view sep);
std::string strip(std::string_view s);  // str.strip() (ASCII whitespace)

}  // namespace py
}  // namespace abm
