// Behavior definition model. The YAML behavior file is the contract; everything else is generated.
#pragma once

#include "abm/util/pyfmt.hpp"

#include <filesystem>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace abm {

enum class Status { experimental, test, stable, deprecated };
enum class Level { low, medium, high, critical };

std::string to_string(Status s);
std::string to_string(Level l);

struct TechniqueRef {
  std::string id;
  std::string relationship = "primary";  // primary | secondary | precondition
};

struct AtlasMapping {
  std::vector<std::string> tactics;
  std::vector<TechniqueRef> techniques;
  std::vector<std::string> primary() const;
};

struct TelemetrySource {
  std::string source;
  std::vector<std::string> fields;
};

struct Telemetry {
  std::vector<TelemetrySource> required;
  std::vector<TelemetrySource> optional;
};

// Parsed form of 'metric_name <op> number'.
struct Condition {
  std::string metric;
  std::string op;
  double value = 0;
  static Condition parse(const std::string& expr);  // throws std::invalid_argument
};

// Parsed form of 'agg(field)' e.g. dcount(session_id), count.
struct Metric {
  std::string agg;
  std::optional<std::string> field;
  static Metric parse(const std::string& expr);  // throws std::invalid_argument
};

struct Signature {
  std::string field;
  std::vector<std::string> patterns;
};

struct Detection {
  std::string logic;  // signature | windowed_threshold | field_match
  std::vector<Signature> signatures;
  std::optional<std::string> window;
  std::vector<std::string> group_by;
  std::vector<std::pair<std::string, std::string>> metrics;  // insertion-ordered name -> expr
  std::vector<std::string> conditions;
  Value match = Value::object();
  Value filters = Value::object();
  std::vector<std::string> false_positives;

  std::vector<Condition> parsed_conditions() const;
  std::vector<std::pair<std::string, Metric>> parsed_metrics() const;
  long long window_seconds() const;
  bool has_metric(const std::string& name) const;
};

struct ResponseStep {
  std::string action;
  Value params = Value::object();
  std::optional<bool> requires_approval;  // overrides action registry default
};

struct Countermeasures {
  std::vector<std::string> mitigations;
  std::vector<ResponseStep> response;
};

struct TestCase {
  std::string fixture;
  std::string expect;  // alert | no_alert
};

struct Behavior {
  std::string id;
  std::string name;
  Status status = Status::experimental;
  Level severity = Level::low;
  Level confidence = Level::low;
  std::string description;
  AtlasMapping atlas;
  std::vector<std::string> attack_bridge;
  Telemetry telemetry;
  Detection detection;
  Countermeasures countermeasures;
  std::vector<TestCase> tests;
  std::vector<std::string> references;

  // populated by loader, not part of YAML
  std::optional<std::filesystem::path> source_path;

  const std::string& primary_technique() const;
  const std::string& log_source() const;

  // Behavior.model_validate(raw): throws ValidationError listing every problem found.
  static Behavior from_value(const Value& raw);
};

struct FieldError {
  std::string loc;  // dotted path, '<root>' for model-level checks
  std::string msg;
};

class ValidationError : public std::runtime_error {
 public:
  explicit ValidationError(std::vector<FieldError> errors);
  const std::vector<FieldError>& errors() const { return errors_; }

 private:
  std::vector<FieldError> errors_;
};

// Shared id patterns
bool is_behavior_id(const std::string& s);
bool is_atlas_tactic(const std::string& s);
bool is_atlas_technique(const std::string& s);
bool is_atlas_mitigation(const std::string& s);
bool is_attack_technique(const std::string& s);

}  // namespace abm
