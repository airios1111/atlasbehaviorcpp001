#include "abm/models.hpp"

#include "abm/util/regex.hpp"

#include <algorithm>
#include <climits>
#include <set>

namespace abm {
namespace {

const Regex& BEHAVIOR_ID_RE() {
  static const Regex r(R"(^BHV-(PI|JB|LK|EXF|EV|PO|SC|BD|AG|DOS|CH)-\d{3}$)");
  return r;
}
const Regex& ATLAS_TACTIC_RE() {
  static const Regex r(R"(^AML\.TA\d{4}$)");
  return r;
}
const Regex& ATLAS_TECHNIQUE_RE() {
  static const Regex r(R"(^AML\.T\d{4}(\.\d{3})?$)");
  return r;
}
const Regex& ATLAS_MITIGATION_RE() {
  static const Regex r(R"(^AML\.M\d{4}$)");
  return r;
}
const Regex& ATTACK_TECHNIQUE_RE() {
  static const Regex r(R"(^T\d{4}(\.\d{3})?$)");
  return r;
}
const Regex& WINDOW_RE() {
  static const Regex r(R"(^(\d+)([smhd])$)");
  return r;
}
const Regex& CONDITION_RE() {
  static const Regex r(R"(^\s*([a-z_][a-z0-9_]*)\s*(>=|<=|==|!=|>|<)\s*(-?\d+(?:\.\d+)?)\s*$)");
  return r;
}
const Regex& METRIC_RE() {
  static const Regex r(R"(^(count|dcount|sum|avg|variance|max|min)(?:\(([a-z_][a-z0-9_]*)\))?$)");
  return r;
}

// ------------------------------------------------------------------ validation context
// Mirrors pydantic: every field is checked, errors are collected with a dotted location,
// and model-level validators only run when all of that model's fields were valid.
struct Ctx {
  std::vector<FieldError> errors;
  void add(const std::string& loc, const std::string& msg) {
    errors.push_back({loc.empty() ? "<root>" : loc, msg});
  }
  void value_error(const std::string& loc, const std::string& msg) { add(loc, "Value error, " + msg); }
};

std::string at(const std::string& base, const std::string& part) {
  return base.empty() ? part : base + "." + part;
}

std::string literal_msg(const std::vector<std::string>& options) {
  std::string out = "Input should be ";
  for (std::size_t i = 0; i < options.size(); ++i) {
    if (i) out += i + 1 == options.size() ? " or " : ", ";
    out += "'" + options[i] + "'";
  }
  return out;
}

class Obj {
 public:
  Obj(const Value& v, std::string loc, Ctx& ctx, std::vector<std::string> fields)
      : v_(v), loc_(std::move(loc)), ctx_(ctx), start_(ctx.errors.size()) {
    ok_ = v.is_object();
    if (!ok_) {
      ctx.add(loc_, "Input should be a valid dictionary or object to extract fields from");
      return;
    }
    for (auto it = v.begin(); it != v.end(); ++it) {
      if (std::find(fields.begin(), fields.end(), it.key()) == fields.end())
        extras_.push_back(it.key());
    }
  }

  bool ok() const { return ok_; }
  const std::string& loc() const { return loc_; }
  Ctx& ctx() { return ctx_; }

  const Value* get(const std::string& key, bool required) {
    if (!ok_) return nullptr;
    auto it = v_.find(key);
    if (it == v_.end()) {
      if (required) ctx_.add(at(loc_, key), "Field required");
      return nullptr;
    }
    return &*it;
  }

  // Report extra keys; returns true when this object (and its children) produced no errors.
  bool finish() {
    for (const auto& k : extras_) ctx_.add(at(loc_, k), "Extra inputs are not permitted");
    return ok_ && ctx_.errors.size() == start_;
  }

 private:
  const Value& v_;
  std::string loc_;
  Ctx& ctx_;
  std::size_t start_;
  bool ok_ = false;
  std::vector<std::string> extras_;
};

bool as_str(const Value* v, const std::string& loc, Ctx& ctx, std::string& out) {
  if (!v) return false;
  if (!v->is_string()) {
    ctx.add(loc, "Input should be a valid string");
    return false;
  }
  out = v->get<std::string>();
  return true;
}

bool as_str_list(const Value* v, const std::string& loc, Ctx& ctx, std::vector<std::string>& out,
                 bool min_one) {
  if (!v) return false;
  if (!v->is_array()) {
    ctx.add(loc, "Input should be a valid list");
    return false;
  }
  bool ok = true;
  std::vector<std::string> tmp;
  for (std::size_t i = 0; i < v->size(); ++i) {
    std::string s;
    if (as_str(&(*v)[i], at(loc, std::to_string(i)), ctx, s)) tmp.push_back(s);
    else ok = false;
  }
  if (ok && min_one && tmp.empty()) {
    ctx.add(loc, "List should have at least 1 item after validation, not 0");
    return false;
  }
  if (ok) out = std::move(tmp);
  return ok;
}

bool as_dict(const Value* v, const std::string& loc, Ctx& ctx, Value& out) {
  if (!v) return false;
  if (!v->is_object()) {
    ctx.add(loc, "Input should be a valid dictionary");
    return false;
  }
  out = *v;
  return true;
}

bool as_literal(const Value* v, const std::string& loc, Ctx& ctx, const std::vector<std::string>& options,
                std::string& out) {
  if (!v) return false;
  if (!v->is_string() || std::find(options.begin(), options.end(), v->get<std::string>()) == options.end()) {
    ctx.add(loc, literal_msg(options));
    return false;
  }
  out = v->get<std::string>();
  return true;
}

bool as_bool(const Value* v, const std::string& loc, Ctx& ctx, std::optional<bool>& out) {
  if (!v) return false;
  if (v->is_null()) {
    out.reset();
    return true;
  }
  if (v->is_boolean()) {
    out = v->get<bool>();
    return true;
  }
  if (v->is_number()) {
    double d = py::to_double(*v);
    if (d == 0.0 || d == 1.0) {
      out = d == 1.0;
      return true;
    }
  }
  if (v->is_string()) {
    std::string s = py::lower(v->get<std::string>());
    static const std::set<std::string> t = {"1", "on", "t", "true", "y", "yes"};
    static const std::set<std::string> f = {"0", "off", "f", "false", "n", "no"};
    if (t.count(s)) {
      out = true;
      return true;
    }
    if (f.count(s)) {
      out = false;
      return true;
    }
  }
  ctx.add(loc, "Input should be a valid boolean");
  return false;
}

template <class T, class Fn>
bool as_model_list(const Value* v, const std::string& loc, Ctx& ctx, std::vector<T>& out, bool min_one,
                   Fn&& parse_item) {
  if (!v) return false;
  if (!v->is_array()) {
    ctx.add(loc, "Input should be a valid list");
    return false;
  }
  bool ok = true;
  std::vector<T> tmp;
  for (std::size_t i = 0; i < v->size(); ++i) {
    T item;
    if (parse_item((*v)[i], at(loc, std::to_string(i)), ctx, item)) tmp.push_back(std::move(item));
    else ok = false;
  }
  if (ok && min_one && tmp.empty()) {
    ctx.add(loc, "List should have at least 1 item after validation, not 0");
    return false;
  }
  if (ok) out = std::move(tmp);
  return ok;
}

// ------------------------------------------------------------------ sub-models
bool parse_technique_ref(const Value& v, const std::string& loc, Ctx& ctx, TechniqueRef& out) {
  Obj o(v, loc, ctx, {"id", "relationship"});
  if (as_str(o.get("id", true), at(loc, "id"), ctx, out.id) && !ATLAS_TECHNIQUE_RE().search(out.id))
    ctx.value_error(at(loc, "id"), "invalid ATLAS technique id: " + out.id);
  if (const Value* r = o.get("relationship", false))
    as_literal(r, at(loc, "relationship"), ctx, {"primary", "secondary", "precondition"}, out.relationship);
  return o.finish();
}

bool parse_atlas(const Value& v, const std::string& loc, Ctx& ctx, AtlasMapping& out) {
  Obj o(v, loc, ctx, {"tactics", "techniques"});
  if (as_str_list(o.get("tactics", true), at(loc, "tactics"), ctx, out.tactics, true)) {
    for (const auto& t : out.tactics) {
      if (!ATLAS_TACTIC_RE().search(t)) {
        ctx.value_error(at(loc, "tactics"), "invalid ATLAS tactic id: " + t);
        break;
      }
    }
  }
  as_model_list<TechniqueRef>(o.get("techniques", true), at(loc, "techniques"), ctx, out.techniques, true,
                              parse_technique_ref);
  if (!o.finish()) return false;
  if (out.primary().empty()) {
    ctx.value_error(loc, "at least one technique must have relationship: primary");
    return false;
  }
  return true;
}

bool parse_telemetry_source(const Value& v, const std::string& loc, Ctx& ctx, TelemetrySource& out) {
  Obj o(v, loc, ctx, {"source", "fields"});
  as_str(o.get("source", true), at(loc, "source"), ctx, out.source);
  as_str_list(o.get("fields", true), at(loc, "fields"), ctx, out.fields, true);
  return o.finish();
}

bool parse_telemetry(const Value& v, const std::string& loc, Ctx& ctx, Telemetry& out) {
  Obj o(v, loc, ctx, {"required", "optional"});
  as_model_list<TelemetrySource>(o.get("required", true), at(loc, "required"), ctx, out.required, true,
                                 parse_telemetry_source);
  as_model_list<TelemetrySource>(o.get("optional", false), at(loc, "optional"), ctx, out.optional, false,
                                 parse_telemetry_source);
  return o.finish();
}

bool parse_signature(const Value& v, const std::string& loc, Ctx& ctx, Signature& out) {
  Obj o(v, loc, ctx, {"field", "patterns"});
  as_str(o.get("field", true), at(loc, "field"), ctx, out.field);
  if (as_str_list(o.get("patterns", true), at(loc, "patterns"), ctx, out.patterns, true)) {
    for (const auto& p : out.patterns) {
      try {
        regex_cached(p);
      } catch (const RegexError& e) {
        ctx.value_error(at(loc, "patterns"), "invalid signature regex " + py::repr_str(p) + ": " + e.what());
        break;
      }
    }
  }
  return o.finish();
}

bool parse_detection(const Value& v, const std::string& loc, Ctx& ctx, Detection& out) {
  Obj o(v, loc, ctx,
        {"logic", "signatures", "window", "group_by", "metrics", "conditions", "match", "filters",
         "false_positives"});
  as_literal(o.get("logic", true), at(loc, "logic"), ctx, {"signature", "windowed_threshold", "field_match"},
             out.logic);
  as_model_list<Signature>(o.get("signatures", false), at(loc, "signatures"), ctx, out.signatures, false,
                           parse_signature);
  if (const Value* w = o.get("window", false)) {
    if (!w->is_null()) {
      std::string s;
      if (as_str(w, at(loc, "window"), ctx, s)) out.window = s;
    }
  }
  as_str_list(o.get("group_by", false), at(loc, "group_by"), ctx, out.group_by, false);
  if (const Value* m = o.get("metrics", false)) {
    Value d;
    if (as_dict(m, at(loc, "metrics"), ctx, d)) {
      for (auto it = d.begin(); it != d.end(); ++it) {
        std::string s;
        if (as_str(&it.value(), at(at(loc, "metrics"), it.key()), ctx, s)) out.metrics.emplace_back(it.key(), s);
      }
    }
  }
  as_str_list(o.get("conditions", false), at(loc, "conditions"), ctx, out.conditions, false);
  as_dict(o.get("match", false), at(loc, "match"), ctx, out.match);
  as_dict(o.get("filters", false), at(loc, "filters"), ctx, out.filters);
  as_str_list(o.get("false_positives", false), at(loc, "false_positives"), ctx, out.false_positives, false);
  if (!o.finish()) return false;

  // model validator (_shape)
  auto fail = [&](const std::string& msg) {
    ctx.value_error(loc, msg);
    return false;
  };
  if (out.logic == "signature" && out.signatures.empty()) return fail("signature logic requires 'signatures'");
  if (out.logic == "field_match" && out.match.empty()) return fail("field_match logic requires 'match'");
  if (out.logic == "windowed_threshold") {
    if (!(out.window && !out.window->empty() && WINDOW_RE().search(*out.window)))
      return fail("windowed_threshold requires 'window' like 1h, 15m");
    if (out.window_seconds() == 0) return fail("window must be greater than zero");
    if (out.conditions.empty()) return fail("windowed_threshold requires 'conditions'");
    try {
      for (const auto& [name, expr] : out.metrics) Metric::parse(expr);
      for (const auto& c : out.parsed_conditions()) {
        if (!out.has_metric(c.metric)) return fail("condition references undefined metric '" + c.metric + "'");
      }
    } catch (const std::invalid_argument& e) {
      return fail(e.what());
    }
  }
  return true;
}

bool parse_response_step(const Value& v, const std::string& loc, Ctx& ctx, ResponseStep& out) {
  Obj o(v, loc, ctx, {"action", "params", "requires_approval"});
  as_str(o.get("action", true), at(loc, "action"), ctx, out.action);
  as_dict(o.get("params", false), at(loc, "params"), ctx, out.params);
  as_bool(o.get("requires_approval", false), at(loc, "requires_approval"), ctx, out.requires_approval);
  return o.finish();
}

bool parse_countermeasures(const Value& v, const std::string& loc, Ctx& ctx, Countermeasures& out) {
  Obj o(v, loc, ctx, {"mitigations", "response"});
  if (as_str_list(o.get("mitigations", false), at(loc, "mitigations"), ctx, out.mitigations, false)) {
    for (const auto& m : out.mitigations) {
      if (!ATLAS_MITIGATION_RE().search(m)) {
        ctx.value_error(at(loc, "mitigations"), "invalid ATLAS mitigation id: " + m);
        break;
      }
    }
  }
  as_model_list<ResponseStep>(o.get("response", false), at(loc, "response"), ctx, out.response, false,
                              parse_response_step);
  return o.finish();
}

bool parse_test_case(const Value& v, const std::string& loc, Ctx& ctx, TestCase& out) {
  Obj o(v, loc, ctx, {"fixture", "expect"});
  as_str(o.get("fixture", true), at(loc, "fixture"), ctx, out.fixture);
  as_literal(o.get("expect", true), at(loc, "expect"), ctx, {"alert", "no_alert"}, out.expect);
  return o.finish();
}

template <class E>
bool as_enum(const Value* v, const std::string& loc, Ctx& ctx, const std::vector<std::pair<std::string, E>>& opts,
             E& out) {
  if (!v) return false;
  std::vector<std::string> names;
  for (const auto& [n, e] : opts) {
    names.push_back(n);
    if (v->is_string() && v->get<std::string>() == n) {
      out = e;
      return true;
    }
  }
  ctx.add(loc, literal_msg(names));
  return false;
}

const std::vector<std::pair<std::string, Status>>& status_opts() {
  static const std::vector<std::pair<std::string, Status>> o = {{"experimental", Status::experimental},
                                                                {"test", Status::test},
                                                                {"stable", Status::stable},
                                                                {"deprecated", Status::deprecated}};
  return o;
}

const std::vector<std::pair<std::string, Level>>& level_opts() {
  static const std::vector<std::pair<std::string, Level>> o = {
      {"low", Level::low}, {"medium", Level::medium}, {"high", Level::high}, {"critical", Level::critical}};
  return o;
}

}  // namespace

// ------------------------------------------------------------------ public API
std::string to_string(Status s) {
  for (const auto& [n, e] : status_opts())
    if (e == s) return n;
  return "experimental";
}

std::string to_string(Level l) {
  for (const auto& [n, e] : level_opts())
    if (e == l) return n;
  return "low";
}

bool is_behavior_id(const std::string& s) { return BEHAVIOR_ID_RE().search(s); }
bool is_atlas_tactic(const std::string& s) { return ATLAS_TACTIC_RE().search(s); }
bool is_atlas_technique(const std::string& s) { return ATLAS_TECHNIQUE_RE().search(s); }
bool is_atlas_mitigation(const std::string& s) { return ATLAS_MITIGATION_RE().search(s); }
bool is_attack_technique(const std::string& s) { return ATTACK_TECHNIQUE_RE().search(s); }

std::vector<std::string> AtlasMapping::primary() const {
  std::vector<std::string> out;
  for (const auto& t : techniques)
    if (t.relationship == "primary") out.push_back(t.id);
  return out;
}

Condition Condition::parse(const std::string& expr) {
  auto m = CONDITION_RE().search_groups(expr);
  if (!m) throw std::invalid_argument("invalid condition '" + expr + "' (expected: name <op> number)");
  Condition c;
  c.metric = *(*m)[1];
  c.op = *(*m)[2];
  c.value = std::stod(*(*m)[3]);
  return c;
}

Metric Metric::parse(const std::string& expr) {
  auto m = METRIC_RE().search_groups(py::strip(expr));
  if (!m) throw std::invalid_argument("invalid metric '" + expr + "' (expected agg or agg(field))");
  Metric out;
  out.agg = *(*m)[1];
  if (m->size() > 2 && (*m)[2] && !(*m)[2]->empty()) out.field = *(*m)[2];
  if (out.agg != "count" && !out.field)
    throw std::invalid_argument("metric '" + expr + "': " + out.agg + " requires a field");
  return out;
}

std::vector<Condition> Detection::parsed_conditions() const {
  std::vector<Condition> out;
  for (const auto& c : conditions) out.push_back(Condition::parse(c));
  return out;
}

std::vector<std::pair<std::string, Metric>> Detection::parsed_metrics() const {
  std::vector<std::pair<std::string, Metric>> out;
  for (const auto& [name, expr] : metrics) out.emplace_back(name, Metric::parse(expr));
  return out;
}

bool Detection::has_metric(const std::string& name) const {
  return std::any_of(metrics.begin(), metrics.end(), [&](const auto& kv) { return kv.first == name; });
}

long long Detection::window_seconds() const {
  auto m = WINDOW_RE().search_groups(window.value_or(""));
  if (!m) return 0;
  long long n;
  try {
    n = std::stoll(*(*m)[1]);
  } catch (const std::exception&) {
    return LLONG_MAX;
  }
  const char unit = (*(*m)[2])[0];
  const long long mult = unit == 's' ? 1 : unit == 'm' ? 60 : unit == 'h' ? 3600 : 86400;
  if (n > LLONG_MAX / mult) return LLONG_MAX;
  return n * mult;
}

const std::string& Behavior::primary_technique() const {
  for (const auto& t : atlas.techniques)
    if (t.relationship == "primary") return t.id;
  return atlas.techniques.front().id;
}

const std::string& Behavior::log_source() const { return telemetry.required.front().source; }

ValidationError::ValidationError(std::vector<FieldError> errors)
    : std::runtime_error([&] {
        std::string s;
        for (std::size_t i = 0; i < errors.size(); ++i) {
          if (i) s += "; ";
          s += errors[i].loc + ": " + errors[i].msg;
        }
        return s;
      }()),
      errors_(std::move(errors)) {}

Behavior Behavior::from_value(const Value& raw) {
  Ctx ctx;
  Behavior b;
  Obj o(raw, "", ctx,
        {"id", "name", "status", "severity", "confidence", "description", "atlas", "attack_bridge", "telemetry",
         "detection", "countermeasures", "tests", "references", "source_path"});
  if (as_str(o.get("id", true), "id", ctx, b.id) && !BEHAVIOR_ID_RE().search(b.id))
    ctx.value_error("id", "invalid behavior id '" + b.id + "' (expected BHV-<PREFIX>-NNN)");
  as_str(o.get("name", true), "name", ctx, b.name);
  as_enum(o.get("status", true), "status", ctx, status_opts(), b.status);
  as_enum(o.get("severity", true), "severity", ctx, level_opts(), b.severity);
  as_enum(o.get("confidence", true), "confidence", ctx, level_opts(), b.confidence);
  as_str(o.get("description", true), "description", ctx, b.description);
  if (const Value* v = o.get("atlas", true)) parse_atlas(*v, "atlas", ctx, b.atlas);
  if (as_str_list(o.get("attack_bridge", false), "attack_bridge", ctx, b.attack_bridge, false)) {
    for (const auto& t : b.attack_bridge) {
      if (!ATTACK_TECHNIQUE_RE().search(t)) {
        ctx.value_error("attack_bridge", "invalid ATT&CK technique id: " + t);
        break;
      }
    }
  }
  if (const Value* v = o.get("telemetry", true)) parse_telemetry(*v, "telemetry", ctx, b.telemetry);
  if (const Value* v = o.get("detection", true)) parse_detection(*v, "detection", ctx, b.detection);
  if (const Value* v = o.get("countermeasures", false))
    parse_countermeasures(*v, "countermeasures", ctx, b.countermeasures);
  as_model_list<TestCase>(o.get("tests", false), "tests", ctx, b.tests, false, parse_test_case);
  as_str_list(o.get("references", false), "references", ctx, b.references, false);
  if (o.finish() && b.status == Status::stable) {
    std::set<std::string> expects;
    for (const auto& t : b.tests) expects.insert(t.expect);
    if (expects != std::set<std::string>{"alert", "no_alert"})
      ctx.value_error("", "stable behaviors require at least one 'alert' and one 'no_alert' test");
  }
  if (!ctx.errors.empty()) throw ValidationError(ctx.errors);
  return b;
}

}  // namespace abm
