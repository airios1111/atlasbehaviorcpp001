#include "abm/loader.hpp"

#include "abm/util/yaml.hpp"

#include <algorithm>
#include <unordered_map>

namespace fs = std::filesystem;

namespace abm {

std::map<std::string, Behavior> LoadResult::by_id() const {
  std::map<std::string, Behavior> out;
  for (const auto& b : behaviors) out[b.id] = b;
  return out;
}

fs::path find_root(const std::optional<fs::path>& start) {
  std::error_code ec;
  fs::path p = fs::weakly_canonical(start.value_or(fs::current_path()), ec);
  if (ec) p = fs::absolute(start.value_or(fs::current_path()));
  for (fs::path cand = p;; cand = cand.parent_path()) {
    if (fs::is_directory(cand / "behaviors") || fs::is_regular_file(cand / "CMakeLists.txt")) return cand;
    if (cand == cand.parent_path()) break;
  }
  return p;
}

LoadResult load_behaviors(const fs::path& path) {
  LoadResult result;
  std::vector<fs::path> files;
  if (fs::is_regular_file(path)) {
    files.push_back(path);
  } else if (fs::is_directory(path)) {
    for (const auto& entry : fs::recursive_directory_iterator(path)) {
      if (!entry.is_regular_file()) continue;
      const auto ext = entry.path().extension().string();
      if (ext == ".yaml" || ext == ".yml") files.push_back(entry.path());
    }
    std::sort(files.begin(), files.end(),
              [](const fs::path& a, const fs::path& b) { return a.generic_string() < b.generic_string(); });
  }

  std::unordered_map<std::string, fs::path> seen;
  for (const auto& f : files) {
    Behavior b;
    try {
      Value raw = yaml::load_file(f);
      if (!raw.is_object()) throw std::invalid_argument("top-level YAML must be a mapping");
      b = Behavior::from_value(raw);
      b.source_path = f;
    } catch (const std::exception& e) {
      result.errors.push_back({f, e.what()});
      continue;
    }
    auto it = seen.find(b.id);
    if (it != seen.end()) {
      result.errors.push_back({f, "duplicate behavior id " + b.id + " (also in " + it->second.string() + ")"});
      continue;
    }
    seen.emplace(b.id, f);
    result.behaviors.push_back(std::move(b));
  }
  return result;
}

}  // namespace abm
