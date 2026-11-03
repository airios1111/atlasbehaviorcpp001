// Compile behaviors to Sigma (base rules + Sigma correlation rules for windowed thresholds).
#include "abm/compilers.hpp"

#include "abm/util/hash.hpp"
#include "abm/util/yaml.hpp"

#include <map>
#include <optional>

namespace abm::compilers::sigma {
namespace {

constexpr const char* NS = "8a3c0e1e-6c1f-4b7a-9d42-41b8a7d0a7f1";  // stable namespace for rule ids

const std::map<std::string, std::string>& cmp() {
  static const std::map<std::string, std::string> m = {{"gt", "gt"}, {"gte", "gte"}, {"lt", "lt"}, {"lte", "lte"}};
  return m;
}

const std::map<std::string, std::string>& sigma_cond() {
  static const std::map<std::string, std::string> m = {
      {">", "gt"}, {">=", "gte"}, {"<", "lt"}, {"<=", "lte"}, {"==", "eq"}};
  return m;
}

std::string rule_name(const std::string& id) {
  std::string s = py::lower(id);
  for (char& c : s)
    if (c == '-') c = '_';
  return s;
}

Value tags(const Behavior& b) {
  Value t = Value::array();
  for (const auto& x : b.atlas.tactics) t.push_back("atlas." + py::lower(x));
  for (const auto& x : b.atlas.techniques) t.push_back("atlas." + py::lower(x.id));
  for (const auto& x : b.attack_bridge) t.push_back("attack." + py::lower(x));
  return t;
}

Value as_list(const Value& arg) {
  if (arg.is_array()) return arg;
  Value out = Value::array();
  if (arg.is_string())
    for (char c : arg.get<std::string>()) out.push_back(std::string(1, c));
  else if (arg.is_object())
    for (auto it = arg.begin(); it != arg.end(); ++it) out.push_back(it.key());
  return out;
}

// Split a match/filter spec into a positive selection and a negated filter block.
std::pair<Value, Value> selection(const Value& match) {
  Value sel = Value::object(), neg = Value::object();
  for (auto it = match.begin(); it != match.end(); ++it) {
    const std::string& f = it.key();
    const Value& spec = it.value();
    if (!spec.is_object()) {
      sel[f] = spec;
      continue;
    }
    for (auto op_it = spec.begin(); op_it != spec.end(); ++op_it) {
      const std::string& op = op_it.key();
      const Value& arg = op_it.value();
      if (op == "in") sel[f] = as_list(arg);
      else if (op == "not_in") neg[f] = as_list(arg);
      else if (op == "ne") neg[f] = arg;
      else if (op == "exists") (py::truthy(arg) ? sel : neg)[f + "|exists"] = true;
      else if (op == "regex") sel[f + "|re"] = arg;
      else if (cmp().count(op)) sel[f + "|" + cmp().at(op)] = arg;
    }
  }
  return {sel, neg};
}

bool starts_with(const std::string& s, const std::string& p) { return s.rfind(p, 0) == 0; }

// Sigma correlation supports one event_count/value_count condition. Pick the first expressible
// one; remaining conditions are documented and must be enforced by the backend query.
std::optional<Value> correlation(const Behavior& b) {
  const Detection& d = b.detection;
  const auto metrics = d.parsed_metrics();
  auto metric = [&](const std::string& name) -> const Metric& {
    for (const auto& [k, m] : metrics)
      if (k == name) return m;
    throw std::out_of_range(name);
  };
  for (const auto& c : d.parsed_conditions()) {
    const Metric& m = metric(c.metric);
    if ((m.agg == "count" || m.agg == "dcount") && sigma_cond().count(c.op)) {
      std::vector<std::string> others;
      for (const auto& x : d.conditions)
        if (!starts_with(x, c.metric)) others.push_back(x);
      Value corr = Value::object();
      corr["type"] = m.agg == "count" ? "event_count" : "value_count";
      corr["rules"] = Value::array({rule_name(b.id)});
      corr["group-by"] = d.group_by;
      corr["timespan"] = d.window ? Value(*d.window) : Value(nullptr);
      Value cond = Value::object();
      cond[sigma_cond().at(c.op)] = static_cast<std::int64_t>(c.value);
      if (m.agg == "dcount") cond["field"] = m.field ? Value(*m.field) : Value(nullptr);
      corr["condition"] = cond;

      Value doc = Value::object();
      doc["title"] = b.name + " (correlation)";
      doc["id"] = rule_id(b.id, ":correlation");
      doc["status"] = to_string(b.status);
      doc["description"] = others.empty() ? std::string("Windowed threshold.")
                                          : "Windowed threshold. Not expressible in Sigma correlation, enforce in "
                                            "backend: " + py::join(others, "; ");
      doc["tags"] = tags(b);
      doc["correlation"] = corr;
      doc["level"] = to_string(b.severity);
      return doc;
    }
  }
  return std::nullopt;
}

std::string collapse_ws(const std::string& s) {
  std::vector<std::string> words;
  std::string cur;
  for (char c : s) {
    if (c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v') {
      if (!cur.empty()) words.push_back(cur);
      cur.clear();
    } else {
      cur += c;
    }
  }
  if (!cur.empty()) words.push_back(cur);
  return py::join(words, " ");
}

}  // namespace

std::string rule_id(const std::string& behavior_id, const std::string& suffix) {
  return hash::uuid5(NS, behavior_id + suffix);
}

std::string compile_behavior(const Behavior& b) {
  const Detection& d = b.detection;
  Value detection = Value::object();
  std::vector<std::string> cond_parts;

  if (d.logic == "signature") {
    for (std::size_t i = 0; i < d.signatures.size(); ++i) {
      Value sel = Value::object();
      sel[d.signatures[i].field + "|re"] = d.signatures[i].patterns;
      detection["selection_" + std::to_string(i)] = sel;
    }
    cond_parts.push_back("1 of selection_*");
  } else {
    auto [sel, neg] = selection(d.logic == "field_match" ? d.match : Value::object());
    if (!sel.empty()) {
      detection["selection"] = sel;
      cond_parts.push_back("selection");
    }
  }
  auto [fsel, fneg] = selection(d.filters);
  if (!fsel.empty()) {
    detection["scope"] = fsel;
    cond_parts.push_back("scope");
  }
  Value neg_all = fneg;
  if (d.logic == "field_match") {
    Value mneg = selection(d.match).second;
    for (auto it = mneg.begin(); it != mneg.end(); ++it) neg_all[it.key()] = it.value();
  }
  if (!neg_all.empty()) {
    detection["filter_exclude"] = neg_all;
    cond_parts.push_back("not filter_exclude");
  }
  bool has_positive = false;
  for (const auto& p : cond_parts)
    if (!starts_with(p, "not ")) has_positive = true;
  if (!has_positive) {
    // no positive selection (threshold or exclusion-only): anchor on a required field
    Value anchor = Value::object();
    anchor[b.telemetry.required.front().fields.front() + "|exists"] = true;
    detection["selection"] = anchor;
    cond_parts.insert(cond_parts.begin(), "selection");
  }
  detection["condition"] = py::join(cond_parts, " and ");

  Value base = Value::object();
  base["title"] = b.name;
  base["id"] = rule_id(b.id);
  base["name"] = rule_name(b.id);
  base["status"] = to_string(b.status);
  base["description"] = collapse_ws(b.description);
  if (!b.references.empty()) base["references"] = b.references;
  base["author"] = "atlas-behavior-map";
  base["tags"] = tags(b);
  Value logsource = Value::object();
  logsource["product"] = "ai";
  logsource["service"] = b.log_source();
  base["logsource"] = logsource;
  base["detection"] = detection;
  base["falsepositives"] = d.false_positives.empty() ? Value::array({"Unknown"}) : Value(d.false_positives);
  base["level"] = to_string(b.severity);

  std::vector<Value> docs = {base};
  if (d.logic == "windowed_threshold") {
    if (auto corr = correlation(b)) {
      docs[0]["generate"] = true;
      docs.push_back(*corr);
    }
  }
  return header(b, "#") + "\n" + yaml::dump_all(docs, yaml::DumpOptions{true});
}

}  // namespace abm::compilers::sigma
