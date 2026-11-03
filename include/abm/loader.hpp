// Load behavior YAML files and resolve project paths.
#pragma once

#include "abm/models.hpp"

#include <filesystem>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace abm {

struct LoadError {
  std::filesystem::path path;
  std::string message;
};

struct LoadResult {
  std::vector<Behavior> behaviors;
  std::vector<LoadError> errors;
  std::map<std::string, Behavior> by_id() const;
};

// Walk up from start until a directory containing behaviors/ or CMakeLists.txt is found.
std::filesystem::path find_root(const std::optional<std::filesystem::path>& start = std::nullopt);

LoadResult load_behaviors(const std::filesystem::path& path);

}  // namespace abm
