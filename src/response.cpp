#include "abm/response.hpp"

#include "abm/util/regex.hpp"

#include <algorithm>
#include <stdexcept>

namespace abm {
namespace {

const Regex& TEMPLATE_RE() {
  static const Regex r(R"(\{\{\s*([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\})");
  return r;
}

int xsoar_severity(const std::string& s) {
  if (s == "low") return 1;
  if (s == "medium") return 2;
  if (s == "high") return 3;
  if (s == "critical") return 4;
  return 0;
}

bool starts_with(const std::string& s, const std::string& prefix) { return s.rfind(prefix, 0) == 0; }

std::string rstrip_slash(std::string s) {
  while (!s.empty() && s.back() == '/') s.pop_back();
  return s;
}

}  // namespace

const OrderedMap<ActionSpec>& action_registry() {
  static const OrderedMap<ActionSpec> reg = [] {
    OrderedMap<ActionSpec> r;
    r.set("block_request", {false, true, "request", "Reject the offending request"});
    r.set("redact_output", {false, true, "request", "Redact sensitive spans from model output"});
    r.set("strip_content", {false, true, "request", "Strip instruction-bearing spans from retrieved content"});
    r.set("deny_tool_call", {false, true, "request", "Deny an agent tool invocation"});
    r.set("cap_tokens", {false, true, "request", "Cap max input/output tokens"});
    r.set("increment_risk", {false, true, "principal", "Raise the principal's risk score"});
    r.set("rate_limit", {false, true, "principal", "Throttle the principal"});
    r.set("enforce_quota", {false, true, "principal", "Enforce spend/compute quota"});
    r.set("degrade_output", {false, true, "model", "Reduce output fidelity (e.g. top-1 label only)"});
    r.set("open_incident", {false, true, "org", "Open an incident in the SOC queue"});
    r.set("notify", {false, true, "org", "Notify a channel or distribution list"});
    r.set("kill_session", {false, true, "session", "Terminate the agent/LLM session"});
    r.set("quarantine_source", {true, true, "source", "Quarantine a retrieval source document"});
    r.set("revoke_token", {true, true, "principal", "Revoke the principal's credentials/tokens"});
    r.set("block_deploy", {false, true, "service", "Block a model artifact from deployment"});
    r.set("pull_model", {true, true, "service", "Remove a model from serving / roll back"});
    r.set("halt_pipeline", {true, true, "pipeline", "Halt a training/data pipeline"});
    r.set("step_up_auth", {false, true, "principal", "Require re-authentication / MFA for the principal"});
    r.set("quarantine_vector_records", {false, true, "source", "Exclude vector-store records from retrieval"});
    r.set("quarantine_artifact", {false, true, "service", "Mark a model/dataset artifact as quarantined"});
    r.set("disable_tool", {true, true, "service", "Disable an agent tool / MCP server for all agents"});
    r.set("rotate_credentials", {true, true, "service", "Rotate credentials exposed to or by an AI component"});
    r.set("purge_agent_memory", {true, false, "principal", "Delete poisoned entries from agent long-term memory"});
    return r;
  }();
  return reg;
}

std::vector<std::string> action_names_sorted() {
  std::vector<std::string> names;
  for (const auto& [k, v] : action_registry()) names.push_back(k);
  std::sort(names.begin(), names.end());
  return names;
}

Value Alert::to_dict() const {
  Value d = Value::object();
  d["behavior_id"] = behavior_id;
  d["name"] = name;
  d["severity"] = severity;
  d["technique"] = technique;
  d["tactics"] = tactics;
  d["context"] = context;
  Value m = Value::object();
  for (const auto& [k, v] : metrics) m[k] = v;
  d["metrics"] = m;
  d["evidence"] = evidence;
  d["window_start"] = window_start;
  return d;
}

Value PlannedAction::to_dict() const {
  Value d = Value::object();
  d["action"] = action;
  d["params"] = params;
  d["requires_approval"] = requires_approval;
  d["reversible"] = reversible;
  d["blast_radius"] = blast_radius;
  d["status"] = status;
  return d;
}

Value render(const Value& value, const Value& ctx) {
  if (value.is_string()) {
    return TEMPLATE_RE().sub(value.get_ref<const std::string&>(), [&](const auto& groups) {
      const std::string& key = *groups[1];
      auto it = ctx.find(key);
      return it == ctx.end() ? *groups[0] : py::str(*it);
    });
  }
  if (value.is_object()) {
    Value out = Value::object();
    for (auto it = value.begin(); it != value.end(); ++it) out[it.key()] = render(it.value(), ctx);
    return out;
  }
  if (value.is_array()) {
    Value out = Value::array();
    for (const auto& v : value) out.push_back(render(v, ctx));
    return out;
  }
  return value;
}

std::vector<PlannedAction> plan(const Behavior& behavior, const Alert& alert) {
  Value ctx = alert.context;
  for (const auto& [k, v] : alert.metrics) ctx[k] = v;
  ctx["behavior_id"] = alert.behavior_id;
  ctx["technique"] = alert.technique;
  ctx["severity"] = alert.severity;

  std::vector<PlannedAction> actions;
  for (const auto& step : behavior.countermeasures.response) {
    const ActionSpec& spec = action_registry().at(step.action);
    const bool gated = step.requires_approval.value_or(spec.requires_approval);
    PlannedAction a;
    a.action = step.action;
    a.params = render(step.params, ctx);
    a.requires_approval = gated;
    a.reversible = spec.reversible;
    a.blast_radius = spec.blast_radius;
    a.status = gated ? "awaiting_approval" : "auto";
    actions.push_back(std::move(a));
  }
  return actions;
}

std::vector<PlannedAction> Executor::execute_plan(const Alert& alert, std::vector<PlannedAction> actions) {
  std::vector<PlannedAction> out;
  for (auto& a : actions) out.push_back(execute(alert, std::move(a)));
  return out;
}

PlannedAction DryRunExecutor::execute(const Alert&, PlannedAction action) {
  if (action.status == "auto") action.status = "executed(dry-run)";
  return action;
}

// ------------------------------------------------------------------ webhook
WebhookExecutor::WebhookExecutor(std::string url, int timeout, http::Headers headers,
                                 std::shared_ptr<http::Transport> transport)
    : url_(std::move(url)), timeout_(timeout), headers_(std::move(headers)), transport_(std::move(transport)) {
  if (!starts_with(url_, "https://")) throw std::invalid_argument("webhook URL must be https");
}

PlannedAction WebhookExecutor::execute(const Alert& alert, PlannedAction action) {
  if (action.status != "auto") return action;
  Value body = Value::object();
  body["alert"] = alert.to_dict();
  body["action"] = action.to_dict();
  http::Request req{"POST", url_, {{"Content-Type", "application/json"}}, py::json_dumps(body), timeout_};
  for (const auto& h : headers_) req.headers.push_back(h);
  try {
    auto transport = transport_ ? transport_ : http::default_transport();
    http::Response r = transport->send(req);
    if (r.status >= 400) action.status = "failed(HTTPError)";  // urllib raises HTTPError (an OSError)
    else action.status = (r.status >= 200 && r.status < 300) ? "executed" : "failed(" + std::to_string(r.status) + ")";
  } catch (const http::TransportError& e) {
    action.status = "failed(" + e.kind() + ")";
  }
  return action;
}

// ------------------------------------------------------------------ XSOAR
XsoarExecutor::XsoarExecutor(std::string url, std::string api_key, std::optional<std::string> api_key_id,
                             std::string incident_type, int timeout, std::optional<std::string> path,
                             std::shared_ptr<http::Transport> transport)
    : api_key_(std::move(api_key)),
      api_key_id_(std::move(api_key_id)),
      incident_type_(std::move(incident_type)),
      timeout_(timeout),
      transport_(std::move(transport)) {
  if (!starts_with(url, "https://")) throw std::invalid_argument("XSOAR URL must be https");
  if (api_key_.empty()) throw std::invalid_argument("XSOAR API key is required");
  url_ = rstrip_slash(std::move(url));
  if (api_key_id_ && api_key_id_->empty()) api_key_id_.reset();
  path_ = path ? *path : (api_key_id_ ? "/xsoar/public/v1/incident" : "/incident");
}

http::Headers XsoarExecutor::headers() const {
  http::Headers h = {{"Content-Type", "application/json"}, {"Accept", "application/json"}, {"Authorization", api_key_}};
  if (api_key_id_) h.emplace_back("x-xdr-auth-id", *api_key_id_);
  return h;
}

Value XsoarExecutor::incident(const Alert& alert, const std::vector<PlannedAction>& actions) const {
  Value plan_rows = Value::array();
  for (const auto& a : actions) plan_rows.push_back(a.to_dict());

  auto label = [](const std::string& type, const std::string& value) {
    Value l = Value::object();
    l["type"] = type;
    l["value"] = value;
    return l;
  };
  Value labels = Value::array();
  labels.push_back(label("behavior_id", alert.behavior_id));
  labels.push_back(label("atlas_technique", alert.technique));
  for (const auto& t : alert.tactics) labels.push_back(label("atlas_tactic", t));
  for (auto it = alert.context.begin(); it != alert.context.end(); ++it)
    labels.push_back(label("context." + it.key(), py::str(it.value())));
  for (const auto& a : actions) labels.push_back(label("planned_action", a.action + ":" + a.status));

  std::vector<std::string> details = {alert.name,
                                      "ATLAS " + alert.technique + " (" + py::join(alert.tactics, ", ") + ")",
                                      "Evidence:"};
  for (const auto& e : alert.evidence) details.push_back("- " + e);

  Value raw = Value::object();
  raw["alert"] = alert.to_dict();
  raw["response_plan"] = plan_rows;

  Value payload = Value::object();
  payload["name"] = "[" + alert.behavior_id + "] " + alert.name;
  payload["type"] = incident_type_;
  payload["severity"] = xsoar_severity(alert.severity);
  payload["details"] = py::join(details, "\n");
  payload["labels"] = labels;
  payload["rawJSON"] = py::json_dumps(raw);
  Value custom = Value::object();
  custom["abmbehaviorid"] = alert.behavior_id;
  custom["abmatlastechnique"] = alert.technique;
  custom["abmatlastactics"] = py::join(alert.tactics, ", ");
  custom["abmresponseplan"] = py::json_dumps(plan_rows);
  payload["CustomFields"] = custom;
  payload["createInvestigation"] = true;
  if (py::truthy(alert.window_start)) payload["occurred"] = alert.window_start;
  return payload;
}

std::vector<PlannedAction> XsoarExecutor::execute_plan(const Alert& alert, std::vector<PlannedAction> actions) {
  http::Request req{"POST", url_ + path_, headers(), py::json_dumps(incident(alert, actions)), timeout_};
  std::string outcome;
  try {
    auto transport = transport_ ? transport_ : http::default_transport();
    http::Response r = transport->send(req);
    if (r.status >= 400) {
      outcome = "failed(HTTPError)";  // urllib raises HTTPError (an OSError) for 4xx/5xx
    } else if (r.status >= 200 && r.status < 300) {
      Value body = Value::parse(r.body.empty() ? std::string("{}") : r.body);
      std::string ref = "?";
      if (body.is_object() && body.contains("id")) ref = py::str(body["id"]);
      outcome = "xsoar:" + ref;
    } else {
      outcome = "failed(" + std::to_string(r.status) + ")";
    }
  } catch (const http::TransportError& e) {
    outcome = "failed(" + e.kind() + ")";
  } catch (const Value::parse_error&) {
    outcome = "failed(JSONDecodeError)";
  }
  for (auto& a : actions) {
    if (starts_with(outcome, "failed")) a.status = outcome;
    else a.status = std::string(a.status == "awaiting_approval" ? "awaiting_approval" : "delegated") + "(" + outcome + ")";
  }
  return actions;
}

PlannedAction XsoarExecutor::execute(const Alert& alert, PlannedAction action) {
  return execute_plan(alert, {std::move(action)})[0];
}

std::vector<PlannedAction> run_plan(Executor& executor, const Alert& alert, std::vector<PlannedAction> actions) {
  return executor.execute_plan(alert, std::move(actions));
}

}  // namespace abm
