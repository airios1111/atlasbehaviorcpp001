// Reference detection engine: evaluates behaviors against normalized JSONL telemetry.
//
// Used for adversarial replay, fixture tests and local triage. Production detection runs as
// compiled KQL/SPL/Sigma in the SIEM; this engine is the semantic reference those must match.
#pragma once

#include "abm/catalog.hpp"
#include "abm/models.hpp"
#include "abm/response.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace abm {

using Event = Value;

std::vector<Event> load_events(const std::filesystem::path& path);

// Spec forms: scalar (equality) | {in|not_in|ne|regex|exists|gt|gte|lt|lte: ...} (AND).
bool match_value(const Value& actual, const Value& spec);

class Engine {
 public:
  explicit Engine(std::vector<Behavior> behaviors, const AtlasCatalog* catalog = nullptr);

  std::vector<Alert> evaluate(const Behavior& b, const std::vector<Event>& events) const;
  std::vector<Alert> run(const std::vector<Event>& events) const;

  const std::vector<Behavior>& behaviors() const { return behaviors_; }

 private:
  std::vector<Behavior> behaviors_;
  const AtlasCatalog* catalog_;
};

struct TestResult {
  std::string fixture;
  std::string expect;
  bool passed;
  std::size_t alert_count;
};

// One result per declared test of the behavior.
std::vector<TestResult> run_tests(const Behavior& b, const std::filesystem::path& root);

}  // namespace abm
