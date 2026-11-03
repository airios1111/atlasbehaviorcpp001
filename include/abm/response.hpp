// Countermeasure resolver: turns alerts into gated, templated response plans and executes them.
#pragma once

#include "abm/models.hpp"
#include "abm/ordered_map.hpp"
#include "abm/util/http.hpp"

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace abm {

struct ActionSpec {
  bool requires_approval;
  bool reversible;
  std::string blast_radius;  // request | session | principal | model | source | pipeline | service | org
  std::string description;
};

const OrderedMap<ActionSpec>& action_registry();
std::vector<std::string> action_names_sorted();

struct Alert {
  std::string behavior_id;
  std::string name;
  std::string severity;
  std::string technique;
  std::vector<std::string> tactics;
  Value context = Value::object();  // group keys / matched fields
  std::vector<std::pair<std::string, double>> metrics;
  std::vector<std::string> evidence;
  Value window_start = nullptr;  // str | None (raw event timestamp for per-event logic)

  Value to_dict() const;
};

struct PlannedAction {
  std::string action;
  Value params = Value::object();
  bool requires_approval = false;
  bool reversible = true;
  std::string blast_radius;
  std::string status = "pending";  // pending | auto | awaiting_approval | executed | failed

  Value to_dict() const;
};

// Replace {{name}} placeholders in strings (recursively through dicts and lists).
Value render(const Value& value, const Value& ctx);

std::vector<PlannedAction> plan(const Behavior& behavior, const Alert& alert);

class Executor {
 public:
  virtual ~Executor() = default;
  virtual PlannedAction execute(const Alert& alert, PlannedAction action) = 0;
  // Executors that hand the whole plan to another system (XSOAR) override this.
  virtual std::vector<PlannedAction> execute_plan(const Alert& alert, std::vector<PlannedAction> actions);
};

// Default: records intent, changes nothing.
class DryRunExecutor : public Executor {
 public:
  PlannedAction execute(const Alert& alert, PlannedAction action) override;
};

// POSTs auto-approved actions to a SOAR webhook. Gated actions are never auto-executed.
class WebhookExecutor : public Executor {
 public:
  explicit WebhookExecutor(std::string url, int timeout = 10, http::Headers headers = {},
                           std::shared_ptr<http::Transport> transport = nullptr);
  PlannedAction execute(const Alert& alert, PlannedAction action) override;

 private:
  std::string url_;
  int timeout_;
  http::Headers headers_;
  std::shared_ptr<http::Transport> transport_;
};

// Creates one Cortex XSOAR incident per alert carrying the full response plan.
//
// XSOAR owns execution: its playbook runs `auto` actions and routes `awaiting_approval` ones to an
// analyst task. Auth uses an XSOAR API key; for XSOAR 8 / Cortex cloud tenants also pass the API key
// ID, which switches to the `x-xdr-auth-id` header and the `/xsoar/public/v1` API path.
class XsoarExecutor : public Executor {
 public:
  XsoarExecutor(std::string url, std::string api_key, std::optional<std::string> api_key_id = std::nullopt,
                std::string incident_type = "AI Security Alert", int timeout = 15,
                std::optional<std::string> path = std::nullopt,
                std::shared_ptr<http::Transport> transport = nullptr);

  http::Headers headers() const;
  // XSOAR create-incident payload. Labels always survive; CustomFields need the matching
  // incident fields (see integrations/xsoar/README.md).
  Value incident(const Alert& alert, const std::vector<PlannedAction>& actions) const;
  std::vector<PlannedAction> execute_plan(const Alert& alert, std::vector<PlannedAction> actions) override;
  PlannedAction execute(const Alert& alert, PlannedAction action) override;

  const std::string& url() const { return url_; }
  const std::string& path() const { return path_; }

 private:
  std::string url_;
  std::string api_key_;
  std::optional<std::string> api_key_id_;
  std::string incident_type_;
  int timeout_;
  std::string path_;
  std::shared_ptr<http::Transport> transport_;
};

std::vector<PlannedAction> run_plan(Executor& executor, const Alert& alert, std::vector<PlannedAction> actions);

}  // namespace abm
