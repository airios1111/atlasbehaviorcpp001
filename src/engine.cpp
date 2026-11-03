#include "abm/engine.hpp"

#include "abm/util/regex.hpp"
#include "abm/util/timeutil.hpp"
#include "abm/util/yaml.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <set>
#include <sstream>
#include <stdexcept>
#include <unordered_map>

namespace abm {
namespace {

const Value& get(const Event& ev, const std::string& key) {
  static const Value null_value = nullptr;
  if (!ev.is_object()) throw std::runtime_error("event is not a JSON object: " + py::repr(ev));
  auto it = ev.find(key);
  return it == ev.end() ? null_value : *it;
}

bool compare(const std::string& op, double a, double b) {
  if (op == ">") return a > b;
  if (op == ">=") return a >= b;
  if (op == "<") return a < b;
  if (op == "<=") return a <= b;
  if (op == "==") return a == b;
  if (op == "!=") return a != b;
  throw std::invalid_argument("unknown operator " + op);
}

double ts(const Event& ev) {
  static const std::string key = "timestamp";
  const Value& v = get(ev, key);
  if (py::is_number(v)) return py::to_double(v);
  if (v.is_string()) return timeutil::parse_iso_timestamp(v.get<std::string>());
  throw std::invalid_argument("event missing/invalid timestamp: " + py::repr(ev));
}

bool passes(const Event& ev, const Value& conds) {
  for (auto it = conds.begin(); it != conds.end(); ++it)
    if (!match_value(get(ev, it.key()), it.value())) return false;
  return true;
}

// Neumaier-compensated sum (Python 3.12+ sum() / math.fsum-like accuracy)
double accurate_sum(const std::vector<double>& xs) {
  double sum = 0.0, c = 0.0;
  for (double x : xs) {
    double t = sum + x;
    if (std::fabs(sum) >= std::fabs(x)) c += (sum - t) + x;
    else c += (x - t) + sum;
    sum = t;
  }
  return sum + c;
}

double aggregate(const Metric& m, const std::vector<const Event*>& rows) {
  if (m.agg == "count") return static_cast<double>(rows.size());
  std::vector<const Value*> vals;
  for (const Event* r : rows) {
    const Value& v = get(*r, *m.field);
    if (!v.is_null()) vals.push_back(&v);
  }
  if (m.agg == "dcount") {
    std::set<std::string> distinct;
    for (const Value* v : vals) distinct.insert(py::json_dumps(*v, -1, true));
    return static_cast<double>(distinct.size());
  }
  std::vector<double> nums;
  for (const Value* v : vals)
    if (py::is_number(*v)) nums.push_back(py::to_double(*v));
  if (nums.empty()) return std::numeric_limits<double>::quiet_NaN();
  if (m.agg == "sum") return accurate_sum(nums);
  if (m.agg == "avg") return accurate_sum(nums) / static_cast<double>(nums.size());
  if (m.agg == "max") return *std::max_element(nums.begin(), nums.end());
  if (m.agg == "min") return *std::min_element(nums.begin(), nums.end());
  if (m.agg == "variance") {
    if (nums.size() <= 1) return 0.0;
    // statistics.pvariance: two-pass with compensated sums
    const double mean = accurate_sum(nums) / static_cast<double>(nums.size());
    std::vector<double> sq;
    sq.reserve(nums.size());
    double dev_sum = 0.0;
    for (double x : nums) {
      sq.push_back((x - mean) * (x - mean));
      dev_sum += x - mean;
    }
    double ss = accurate_sum(sq) - dev_sum * dev_sum / static_cast<double>(nums.size());
    return std::max(0.0, ss / static_cast<double>(nums.size()));
  }
  throw std::invalid_argument(m.agg);
}

Value event_ctx(const Event& e, const Behavior& b) {
  std::set<std::string> keep = {"principal_id", "session_id", "model_id", "source_uri", "tool_name", "artifact_id"};
  for (const auto& src : b.telemetry.required)
    for (const auto& f : src.fields) keep.insert(f);
  Value out = Value::object();
  for (auto it = e.begin(); it != e.end(); ++it) {
    if (keep.count(it.key()) && !it.value().is_array() && !it.value().is_object()) out[it.key()] = it.value();
  }
  return out;
}

// Hash key with Python dict-key equality for scalars (1 == 1.0 == True).
std::string canonical_key(const Value& v) {
  if (py::is_number(v)) {
    double d = py::to_double(v);
    if (std::isfinite(d) && d == std::floor(d) && std::fabs(d) < 9e15) return "n:" + std::to_string(static_cast<long long>(d));
    return "n:" + py::float_repr(d);
  }
  return "v:" + py::json_dumps(v, -1, true);
}

}  // namespace

std::vector<Event> load_events(const std::filesystem::path& path) {
  std::vector<Event> events;
  std::istringstream in(yaml::read_text(path));
  std::string line;
  int n = 0;
  while (std::getline(in, line)) {
    ++n;
    std::string s = py::strip(line);
    if (s.empty() || s[0] == '#') continue;
    try {
      events.push_back(Value::parse(s));
    } catch (const Value::parse_error& e) {
      throw std::invalid_argument(path.string() + ":" + std::to_string(n) + ": invalid JSON: " + e.what());
    }
  }
  return events;
}

bool match_value(const Value& actual, const Value& spec) {
  if (!spec.is_object()) return py::eq(actual, spec);
  for (auto it = spec.begin(); it != spec.end(); ++it) {
    const std::string& op = it.key();
    const Value& arg = it.value();
    if (op == "in" && !py::contains(arg, actual)) return false;
    if (op == "not_in" && py::contains(arg, actual)) return false;
    if (op == "ne" && py::eq(actual, arg)) return false;
    if (op == "exists" && (!actual.is_null()) != py::truthy(arg)) return false;
    if (op == "regex") {
      if (!actual.is_string()) return false;
      if (!arg.is_string()) throw std::runtime_error("regex spec must be a string");
      if (!regex_cached(arg.get<std::string>())->search(actual.get_ref<const std::string&>())) return false;
    }
    if (op == "gt" || op == "gte" || op == "lt" || op == "lte") {
      if (!py::is_number(actual)) return false;
      if (!py::is_number(arg))
        throw std::runtime_error("'" + op + "' not supported between number and " + py::repr(arg));
      const double a = py::to_double(actual), b = py::to_double(arg);
      const bool ok = op == "gt" ? a > b : op == "gte" ? a >= b : op == "lt" ? a < b : a <= b;
      if (!ok) return false;
    }
  }
  return true;
}

Engine::Engine(std::vector<Behavior> behaviors, const AtlasCatalog* catalog)
    : behaviors_(std::move(behaviors)), catalog_(catalog) {}

std::vector<Alert> Engine::evaluate(const Behavior& b, const std::vector<Event>& events) const {
  const Detection& d = b.detection;
  auto make_alert = [&]() {
    Alert a;
    a.behavior_id = b.id;
    a.name = b.name;
    a.severity = to_string(b.severity);
    a.technique = b.primary_technique();
    a.tactics = b.atlas.tactics;
    return a;
  };

  std::vector<const Event*> evs;
  for (const auto& e : events)
    if (d.filters.empty() || passes(e, d.filters)) evs.push_back(&e);

  std::vector<Alert> alerts;
  if (d.logic == "signature") {
    std::vector<std::pair<std::string, std::vector<std::shared_ptr<const Regex>>>> compiled;
    for (const auto& s : d.signatures) {
      std::vector<std::shared_ptr<const Regex>> pats;
      for (const auto& p : s.patterns) pats.push_back(regex_cached(p));
      compiled.emplace_back(s.field, std::move(pats));
    }
    for (const Event* e : evs) {
      for (const auto& [fld, pats] : compiled) {
        const Value& val = get(*e, fld);
        if (!val.is_string()) continue;
        const std::string& text = val.get_ref<const std::string&>();
        auto hit = std::find_if(pats.begin(), pats.end(), [&](const auto& p) { return p->search(text); });
        if (hit != pats.end()) {
          Alert a = make_alert();
          a.context = event_ctx(*e, b);
          a.evidence = {fld + " =~ " + (*hit)->pattern()};
          a.window_start = get(*e, "timestamp");
          alerts.push_back(std::move(a));
          break;
        }
      }
    }
    return alerts;
  }

  if (d.logic == "field_match") {
    for (const Event* e : evs) {
      if (!passes(*e, d.match)) continue;
      Alert a = make_alert();
      a.context = event_ctx(*e, b);
      a.evidence = {"field_match " + py::repr(d.match)};
      a.window_start = get(*e, "timestamp");
      alerts.push_back(std::move(a));
    }
    return alerts;
  }

  // windowed_threshold: tumbling windows per group
  const double win = static_cast<double>(d.window_seconds());
  struct Bucket {
    std::vector<Value> key;  // group values (first seen)
    long long window_index;
    std::vector<const Event*> rows;
  };
  std::vector<Bucket> buckets;
  std::unordered_map<std::string, std::size_t> index;
  for (const Event* e : evs) {
    std::vector<Value> key;
    std::string hkey;
    for (const auto& g : d.group_by) {
      key.push_back(get(*e, g));
      hkey += canonical_key(key.back()) + '\x1f';
    }
    const long long w = static_cast<long long>(py::floordiv(ts(*e), win));
    hkey += std::to_string(w);
    auto it = index.find(hkey);
    if (it == index.end()) {
      index.emplace(hkey, buckets.size());
      buckets.push_back({std::move(key), w, {e}});
    } else {
      buckets[it->second].rows.push_back(e);
    }
  }

  // sorted(buckets.items(), key=lambda kv: str(kv[0]))  -- str() of the Python key tuple
  auto tuple_str = [](const Bucket& bk) {
    std::string s = "(";
    for (const auto& v : bk.key) s += py::repr(v) + ", ";
    s += std::to_string(bk.window_index);
    s += bk.key.empty() ? ",)" : ")";
    return s;
  };
  std::vector<std::pair<std::string, const Bucket*>> order;
  for (const auto& bk : buckets) order.emplace_back(tuple_str(bk), &bk);
  std::stable_sort(order.begin(), order.end(), [](const auto& a, const auto& b) { return a.first < b.first; });

  const auto metrics_def = d.parsed_metrics();
  const auto conds = d.parsed_conditions();
  for (const auto& [_, bk] : order) {
    std::vector<std::pair<std::string, double>> values;
    for (const auto& [name, m] : metrics_def) values.emplace_back(name, aggregate(m, bk->rows));
    auto value_of = [&](const std::string& name) {
      for (const auto& [k, v] : values)
        if (k == name) return v;
      throw std::out_of_range(name);
    };
    bool fire = std::all_of(conds.begin(), conds.end(), [&](const Condition& c) {
      double v = value_of(c.metric);
      return !std::isnan(v) && compare(c.op, v, c.value);
    });
    if (!fire) continue;
    Alert a = make_alert();
    Value ctx = Value::object();
    for (std::size_t i = 0; i < d.group_by.size(); ++i) ctx[d.group_by[i]] = bk->key[i];
    a.context = ctx;
    for (const auto& [k, v] : values) a.metrics.emplace_back(k, py::round(v, 6));
    for (const auto& c : conds)
      a.evidence.push_back(c.metric + "=" + py::format_g(value_of(c.metric), 4) + " " + c.op + " " +
                           py::format_g(c.value));
    a.window_start = timeutil::iso_from_epoch(static_cast<std::int64_t>(bk->window_index) *
                                              static_cast<std::int64_t>(win));
    alerts.push_back(std::move(a));
  }
  return alerts;
}

std::vector<Alert> Engine::run(const std::vector<Event>& events) const {
  std::vector<Alert> out;
  for (const auto& b : behaviors_) {
    auto alerts = evaluate(b, events);
    out.insert(out.end(), std::make_move_iterator(alerts.begin()), std::make_move_iterator(alerts.end()));
  }
  return out;
}

std::vector<TestResult> run_tests(const Behavior& b, const std::filesystem::path& root) {
  Engine eng({b});
  std::vector<TestResult> results;
  for (const auto& tc : b.tests) {
    auto alerts = eng.evaluate(b, load_events(root / tc.fixture));
    const bool passed = (!alerts.empty()) == (tc.expect == "alert");
    results.push_back({tc.fixture, tc.expect, passed, alerts.size()});
  }
  return results;
}

}  // namespace abm
