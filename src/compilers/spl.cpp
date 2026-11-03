// Compile behaviors to Splunk SPL.
#include "abm/compilers.hpp"

#include <map>

namespace abm::compilers::spl {
namespace {

std::string agg(const std::string& a, const std::string& f) {
  if (a == "count") return "count";
  static const std::map<std::string, std::string> fn = {{"dcount", "dc"}, {"sum", "sum"}, {"avg", "avg"},
                                                        {"variance", "varp"}, {"max", "max"}, {"min", "min"}};
  return fn.at(a) + "(" + f + ")";
}

const std::map<std::string, std::string>& cmp() {
  static const std::map<std::string, std::string> m = {{"gt", ">"}, {"gte", ">="}, {"lt", "<"}, {"lte", "<="}};
  return m;
}

std::string lit(const Value& v) {
  if (v.is_number() && !v.is_boolean()) return py::repr(v);
  return py::json_dumps(py::str(v));
}

std::string lit_list(const Value& arg) {
  std::vector<std::string> parts;
  if (arg.is_array()) {
    for (const auto& a : arg) parts.push_back(lit(a));
  } else if (arg.is_string()) {
    for (char c : arg.get<std::string>()) parts.push_back(lit(std::string(1, c)));
  } else if (arg.is_object()) {
    for (auto it = arg.begin(); it != arg.end(); ++it) parts.push_back(lit(it.key()));
  }
  return py::join(parts, ", ");
}

std::vector<std::string> where(const std::string& field, const Value& spec) {
  if (!spec.is_object()) return {field + "=" + lit(spec)};
  std::vector<std::string> out;
  for (auto it = spec.begin(); it != spec.end(); ++it) {
    const std::string& op = it.key();
    const Value& arg = it.value();
    if (op == "in") out.push_back("in(" + field + ", " + lit_list(arg) + ")");
    else if (op == "not_in") out.push_back("NOT in(" + field + ", " + lit_list(arg) + ")");
    else if (op == "ne") out.push_back(field + "!=" + lit(arg));
    else if (op == "exists") out.push_back(py::truthy(arg) ? "isnotnull(" + field + ")" : "isnull(" + field + ")");
    else if (op == "regex") out.push_back("match(" + field + ", " + lit(arg) + ")");
    else if (cmp().count(op)) out.push_back(field + cmp().at(op) + lit(arg));
  }
  return out;
}

}  // namespace

std::string compile_behavior(const Behavior& b) {
  const Detection& d = b.detection;
  const std::string* src = spl_source(b.log_source());
  const std::string base = src ? *src : "index=ai sourcetype=\"" + b.log_source() + "\"";
  const bool has_window = d.window && !d.window->empty();
  std::vector<std::string> lines = {header(b, "```"), base + (has_window ? " earliest=-" + *d.window : "")};
  for (auto it = d.filters.begin(); it != d.filters.end(); ++it)
    for (const auto& w : where(it.key(), it.value())) lines.push_back("| where " + w);

  if (d.logic == "signature") {
    std::vector<std::string> ors;
    for (const auto& s : d.signatures)
      for (const auto& p : s.patterns) ors.push_back("match(" + s.field + ", " + lit(p) + ")");
    lines.push_back("| where " + py::join(ors, " OR "));
  } else if (d.logic == "field_match") {
    for (auto it = d.match.begin(); it != d.match.end(); ++it)
      for (const auto& w : where(it.key(), it.value())) lines.push_back("| where " + w);
  } else {
    lines.push_back("| bin _time span=" + d.window.value_or(""));
    std::vector<std::string> aggs;
    for (const auto& [name, m] : d.parsed_metrics()) aggs.push_back(agg(m.agg, m.field.value_or("")) + " as " + name);
    std::vector<std::string> by = d.group_by;
    by.push_back("_time");
    lines.push_back("| stats " + py::join(aggs, " ") + " by " + py::join(by, " "));
    std::vector<std::string> conds;
    for (const auto& c : d.parsed_conditions()) conds.push_back(c.metric + c.op + py::format_g(c.value));
    lines.push_back("| where " + py::join(conds, " AND "));
  }
  lines.push_back("| eval behavior_id=\"" + b.id + "\", atlas_technique=\"" + b.primary_technique() +
                  "\", atlas_tactics=\"" + py::join(b.atlas.tactics, ",") + "\", severity=\"" +
                  to_string(b.severity) + "\"");
  return py::join(lines, "\n") + "\n";
}

}  // namespace abm::compilers::spl
