#include "abm/models.hpp"
#include "abm/util/yaml.hpp"
#include "support.hpp"

#include <filesystem>
#include <random>

using namespace abm;
using namespace abm::testing;
namespace fs = std::filesystem;

namespace {

Value minimal() {
  return Value::parse(R"({
    "id": "BHV-PI-099",
    "name": "x",
    "status": "experimental",
    "severity": "low",
    "confidence": "low",
    "description": "x",
    "atlas": {"tactics": ["AML.TA0005"], "techniques": [{"id": "AML.T0051.000"}]},
    "telemetry": {"required": [{"source": "llm_gateway", "fields": ["prompt"]}]},
    "detection": {"logic": "signature", "signatures": [{"field": "prompt", "patterns": ["x"]}]}
  })");
}

Behavior make(const Value& overrides = Value::object()) {
  Value d = minimal();
  for (auto it = overrides.begin(); it != overrides.end(); ++it) d[it.key()] = it.value();
  return Behavior::from_value(d);
}

std::string error_of(const Value& overrides) {
  try {
    make(overrides);
  } catch (const ValidationError& e) {
    return e.what();
  }
  return "";
}

Value threshold(const std::string& window, const std::string& cond = "n > 1") {
  return Value::parse(R"({"detection": {"logic": "windowed_threshold", "window": ")" + window +
                      R"(", "metrics": {"n": "count"}, "conditions": [")" + cond + R"("]}})");
}

}  // namespace

TEST_CASE("minimal behavior is valid") { CHECK(make().primary_technique() == "AML.T0051.000"); }

TEST_CASE("rejects bad behavior id") {
  for (const char* bad : {"BHV-XX-001", "PI-001", "BHV-PI-1"}) {
    Value o = Value::object();
    o["id"] = bad;
    CHECK_THROWS_AS(make(o), ValidationError);
  }
}

TEST_CASE("rejects bad ATLAS ids") {
  CHECK_THROWS_AS(make(Value::parse(R"({"atlas": {"tactics": ["TA0005"], "techniques": [{"id": "AML.T0051"}]}})")),
                  ValidationError);
  CHECK_THROWS_AS(make(Value::parse(R"({"atlas": {"tactics": ["AML.TA0005"], "techniques": [{"id": "T1059"}]}})")),
                  ValidationError);
}

TEST_CASE("requires a primary technique") {
  auto msg = error_of(Value::parse(
      R"({"atlas": {"tactics": ["AML.TA0005"], "techniques": [{"id": "AML.T0051", "relationship": "precondition"}]}})"));
  CHECK(msg.find("primary") != std::string::npos);
}

TEST_CASE("stable requires positive and negative tests") {
  auto msg = error_of(Value::parse(R"({"status": "stable", "tests": [{"fixture": "a.jsonl", "expect": "alert"}]})"));
  CHECK(msg.find("stable") != std::string::npos);
}

TEST_CASE("threshold condition must reference a metric") {
  auto msg = error_of(threshold("1h", "m > 1"));
  CHECK(msg.find("undefined metric") != std::string::npos);
}

TEST_CASE("threshold window must be positive") {
  for (const char* w : {"0s", "0m", "0h", "0d", "00h"}) {
    CAPTURE(w);
    CHECK(error_of(threshold(w)).find("window must be greater than zero") != std::string::npos);
  }
}

TEST_CASE("positive threshold windows remain valid") {
  const std::vector<std::pair<std::string, long long>> cases = {{"1s", 1}, {"15m", 900}, {"1h", 3600}, {"2d", 172800}};
  for (const auto& [w, secs] : cases) {
    CAPTURE(w);
    CHECK(make(threshold(w)).detection.window_seconds() == secs);
  }
}

TEST_CASE("invalid signature regex is a validation error") {
  for (const char* p : {"(", "[unterminated"}) {
    Value o = Value::object();
    o["detection"] = Value::parse(R"({"logic": "signature", "signatures": [{"field": "prompt", "patterns": []}]})");
    o["detection"]["signatures"][0]["patterns"].push_back(p);
    CHECK(error_of(o).find("invalid signature regex") != std::string::npos);
  }
}

TEST_CASE("CLI reports invalid detection and continues") {
  const std::vector<std::pair<Value, std::string>> cases = {
      {Value::parse(R"({"logic": "signature", "signatures": [{"field": "prompt", "patterns": ["("]}]})"),
       "invalid signature regex"},
      {Value::parse(R"({"logic": "windowed_threshold", "window": "0h", "metrics": {"n": "count"}, "conditions": ["n > 1"]})"),
       "window must be greater than zero"},
  };
  for (const auto& [detection, message] : cases) {
    std::mt19937_64 rng(std::random_device{}());
    fs::path tmp = fs::temp_directory_path() / ("abm-test-" + std::to_string(rng()));
    fs::create_directories(tmp);
    Value invalid = minimal();
    invalid["id"] = "BHV-PI-098";
    invalid["detection"] = detection;
    yaml::write_text(tmp / "a-invalid.yaml", yaml::dump(invalid));
    yaml::write_text(tmp / "b-valid.yaml", yaml::dump(minimal()));

    auto r = run_cli({"--root", root().string(), "validate", tmp.string()});
    CHECK(r.code == 1);
    CHECK(r.out.find("a-invalid.yaml") != std::string::npos);
    CHECK(r.out.find(message) != std::string::npos);
    CHECK(r.out.find("1 behavior(s), 1 error(s)") != std::string::npos);
    fs::remove_all(tmp);
  }
}

TEST_CASE("unknown field rejected") {
  CHECK_THROWS_AS(make(Value::parse(R"({"unexpected": true})")), ValidationError);
}

TEST_CASE("condition and metric parsing") {
  Condition c = Condition::parse("request_count >= 10.5");
  CHECK(c.metric == "request_count");
  CHECK(c.op == ">=");
  CHECK(c.value == 10.5);
  CHECK(Metric::parse("dcount(session_id)").field == std::optional<std::string>("session_id"));
  CHECK_THROWS_AS(Metric::parse("sum"), std::invalid_argument);
  CHECK_THROWS_AS(Condition::parse("a >> 3"), std::invalid_argument);
}

TEST_CASE("pydantic-style error locations") {
  auto msg = error_of(Value::parse(R"({"severity": "extreme", "telemetry": {"required": []}})"));
  CHECK(msg.find("severity: Input should be 'low', 'medium', 'high' or 'critical'") != std::string::npos);
  CHECK(msg.find("telemetry.required: List should have at least 1 item") != std::string::npos);
}
