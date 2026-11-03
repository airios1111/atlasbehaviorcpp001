// Detection compilers: one behavior definition -> SIEM-native rules.
#pragma once

#include "abm/models.hpp"

#include <functional>
#include <string>
#include <vector>

namespace abm::compilers {

// Normalized source -> SIEM table / index. Override per deployment.
const std::string* kql_table(const std::string& source);
const std::string* spl_source(const std::string& source);

// snake_case normalized field -> PascalCase Sentinel column.
std::string pascal(const std::string& name);
std::string header(const Behavior& b, const std::string& comment = "//");

namespace kql {
std::string compile_behavior(const Behavior& b);
}
namespace sigma {
std::string rule_id(const std::string& behavior_id, const std::string& suffix = "");
std::string compile_behavior(const Behavior& b);
}  // namespace sigma
namespace spl {
std::string compile_behavior(const Behavior& b);
}

struct Target {
  std::string name;
  std::function<std::string(const Behavior&)> compile;
  std::string extension;
};

// target -> (compile function, file extension), in declaration order: kql, sigma, spl
const std::vector<Target>& targets();
const Target* find_target(const std::string& name);

}  // namespace abm::compilers
