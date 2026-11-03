// Semantic validation: ATLAS ID resolution, tactic consistency, response actions, fixtures.
#pragma once

#include "abm/catalog.hpp"
#include "abm/loader.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace abm {

struct Finding {
  std::string behavior_id;
  std::string level;  // error | warning
  std::string message;

  std::string str() const;  // "[ERROR  ] BHV-..: message"
};

std::vector<Finding> validate(const LoadResult& result, const AtlasCatalog& catalog,
                              const std::filesystem::path& root);

}  // namespace abm
