// Compile behaviors to KQL for Microsoft Sentinel / Defender XDR.
#include "abm/compilers.hpp"

#include <map>

namespace abm::compilers::kql {
namespace {

std::string agg(const std::string& a, const std::string& f) {
  if (a == "count") return "count()";
  static const std::map<std::string, std::string> fn = {{"dcount", "dcount"}, {"sum", "sum"}, {"avg", "avg"},
                                                        {"variance", "variance"}, {"max", "max"}, {"min", "min"}};
  return fn.at(a) + "(" + f + ")";
}

const std::map<std::string, std::string>& cmp() {
  static const std::map<std::string, std::string> m = {{"gt", ">"}, {"gte", ">="}, {"lt", "<"}, {"lte", "<="}};
  return m;
}

std::string lit(const Value& v) {
  if (v.is_boolean()) return v.get<bool>() ? "true" : "false";
  if (v.is_number()) return py::repr(v);
  return py::json_dumps(py::str(v));
}

// KQL verbatim string literal: double any embedded quotes.
std::string rx(const std::string& pattern) {
  std::string out = "@\"";
  for (char c : pattern) {
    if (c == '"') out += "\"\"";
    else out += c;
  }
  return out + "\"";
}

std::string lit_list(const Value& arg) {
  std::vector<std::string> parts;
  if (arg.is_array()) {
    for (const auto& a : arg) parts.push_back(lit(a));
  } else if (arg.is_string()) {  // iterating a Python str yields its characters
    for (char c : arg.get<std::string>()) parts.push_back(lit(std::string(1, c)));
  } else if (arg.is_object()) {
    for (auto it = arg.begin(); it != arg.end(); ++it) parts.push_back(lit(it.key()));
  }
  return py::join(parts, ", ");
}

std::vector<std::string> where(const std::string& field, const Value& spec) {
  const std::string col = pascal(field);
  if (!spec.is_object()) return {col + " == " + lit(spec)};
  std::vector<std::string> out;
  for (auto it = spec.begin(); it != spec.end(); ++it) {
    const std::string& op = it.key();
    const Value& arg = it.value();
    if (op == "in") out.push_back(col + " in (" + lit_list(arg) + ")");
    else if (op == "not_in") out.push_back(col + " !in (" + lit_list(arg) + ")");
    else if (op == "ne") out.push_back(col + " != " + lit(arg));
    else if (op == "exists") out.push_back(py::truthy(arg) ? "isnotempty(" + col + ")" : "isempty(" + col + ")");
    else if (op == "regex") out.push_back(col + " matches regex " + rx(py::str(arg)));
    else if (cmp().count(op)) out.push_back(col + " " + cmp().at(op) + " " + lit(arg));
  }
  return out;
}

}  // namespace

std::string compile_behavior(const Behavior& b) {
  const Detection& d = b.detection;
  const std::string* t = kql_table(b.log_source());
  const std::string table = t ? *t : pascal(b.log_source());
  std::vector<std::string> lines = {header(b), table};
  if (d.window && !d.window->empty()) lines.push_back("| where TimeGenerated > ago(" + *d.window + ")");
  for (auto it = d.filters.begin(); it != d.filters.end(); ++it)
    for (const auto& w : where(it.key(), it.value())) lines.push_back("| where " + w);

  if (d.logic == "signature") {
    std::vector<std::string> ors;
    for (const auto& s : d.signatures) {
      const std::string col = pascal(s.field);
      for (const auto& p : s.patterns) ors.push_back(col + " matches regex " + rx(p));
    }
    lines.push_back("| where " + py::join(ors, "\n    or "));
  } else if (d.logic == "field_match") {
    for (auto it = d.match.begin(); it != d.match.end(); ++it)
      for (const auto& w : where(it.key(), it.value())) lines.push_back("| where " + w);
  } else {
    std::vector<std::string> aggs;
    for (const auto& [name, m] : d.parsed_metrics()) aggs.push_back(pascal(name) + " = " + agg(m.agg, pascal(m.field.value_or(""))));
    std::vector<std::string> by;
    for (const auto& g : d.group_by) by.push_back(pascal(g));
    by.push_back("bin(TimeGenerated, " + d.window.value_or("") + ")");
    lines.push_back("| summarize " + py::join(aggs, ",\n            ") + "\n          by " + py::join(by, ", "));
    std::vector<std::string> conds;
    for (const auto& c : d.parsed_conditions()) conds.push_back(pascal(c.metric) + " " + c.op + " " + py::format_g(c.value));
    lines.push_back("| where " + py::join(conds, " and "));
  }

  lines.push_back("| extend BehaviorId = \"" + b.id + "\", AtlasTechnique = \"" + b.primary_technique() +
                  "\",\n         AtlasTactics = dynamic(" + py::json_dumps(Value(b.atlas.tactics)) +
                  "), Severity = \"" + to_string(b.severity) + "\"");
  return py::join(lines, "\n") + "\n";
}

}  // namespace abm::compilers::kql
