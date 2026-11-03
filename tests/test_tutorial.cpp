// Keep the tutorial in examples/tutorial/ runnable.
#include "support.hpp"

using namespace abm;
using namespace abm::testing;

namespace {
std::vector<std::string> tut_args() {
  return {"--root", (root() / "examples" / "tutorial").string(), "--catalog",
          (root() / "atlas" / "catalog.yaml").string()};
}
}  // namespace

TEST_CASE("tutorial behaviors validate and pass fixtures") {
  auto args = tut_args();
  args.insert(args.end(), {"validate", "--run-tests"});
  auto r = run_cli(args);
  CHECK(r.code == 0);
  CHECK(r.out.find("2 behavior(s), 0 error(s), 0 warning(s)") != std::string::npos);
}

TEST_CASE("tutorial mixed traffic replay") {
  auto args = tut_args();
  const std::string fixture = (root() / "examples" / "tutorial" / "fixtures" / "traffic_mixed.jsonl").string();
  args.insert(args.end(), {"replay", "--fixture", fixture, "--respond", "--expect", "alert"});
  auto r = run_cli(args);
  CHECK(r.code == 0);
  std::map<std::string, Value> by_id;
  for (const auto& line : lines(r.out)) {
    Value a = Value::parse(line);
    by_id[a["behavior_id"].get<std::string>()] = a;
  }
  CHECK(by_id.size() == 2);
  REQUIRE(by_id.count("BHV-PI-901"));
  REQUIRE(by_id.count("BHV-CH-901"));
  CHECK(by_id["BHV-CH-901"]["context"] == Value::parse(R"({"principal_id": "key-7731"})"));
  std::map<std::string, std::string> statuses;
  for (const auto& resp : by_id["BHV-PI-901"]["response"])
    statuses[resp["action"].get<std::string>()] = resp["status"].get<std::string>();
  CHECK(statuses["revoke_token"] == "awaiting_approval");
  CHECK(statuses["block_request"] == "executed(dry-run)");
}
