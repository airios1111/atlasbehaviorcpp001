#include "abm/validator.hpp"

#include "abm/response.hpp"

#include <algorithm>
#include <set>

namespace fs = std::filesystem;

namespace abm {
namespace {

std::vector<Finding> check(const Behavior& b, const AtlasCatalog& cat, const fs::path& root) {
  std::vector<Finding> out;
  auto err = [&](const std::string& msg) { out.push_back({b.id, "error", msg}); };
  auto warn = [&](const std::string& msg) { out.push_back({b.id, "warning", msg}); };

  // ATLAS resolution (drift detection)
  for (const auto& t : b.atlas.tactics)
    if (!cat.tactics.contains(t)) err("tactic " + t + " not in ATLAS catalog (" + cat.source + " " + cat.version + ")");
  for (const auto& ref : b.atlas.techniques) {
    if (!cat.techniques.contains(ref.id)) {
      err("technique " + ref.id + " not in ATLAS catalog (" + cat.source + " " + cat.version + ")");
      continue;
    }
    if (ref.relationship == "primary") {
      auto mapped_v = cat.tactics_for(ref.id);
      std::set<std::string> mapped(mapped_v.begin(), mapped_v.end());
      bool intersects = std::any_of(b.atlas.tactics.begin(), b.atlas.tactics.end(),
                                    [&](const std::string& t) { return mapped.count(t) > 0; });
      if (!mapped.empty() && !intersects) {
        warn("primary technique " + ref.id + " belongs to " +
             py::repr_list(std::vector<std::string>(mapped.begin(), mapped.end())) + ", none listed in tactics " +
             py::repr_list(b.atlas.tactics));
      }
    }
  }
  for (const auto& m : b.countermeasures.mitigations)
    if (!cat.mitigations.contains(m)) err("mitigation " + m + " not in ATLAS catalog");

  // Response actions
  for (const auto& step : b.countermeasures.response)
    if (!action_registry().contains(step.action))
      err("unknown response action '" + step.action + "' (registry: " + py::repr_list(action_names_sorted()) + ")");

  // Fixtures
  for (const auto& tc : b.tests)
    if (!fs::is_regular_file(root / tc.fixture)) err("test fixture not found: " + tc.fixture);

  // Hygiene
  if (b.countermeasures.mitigations.empty()) warn("no ATLAS mitigations bound");
  if ((b.status == Status::test || b.status == Status::stable) && b.countermeasures.response.empty())
    warn("no response actions defined");
  if (b.status == Status::deprecated) warn("deprecated behavior still present");
  return out;
}

}  // namespace

std::string Finding::str() const {
  std::string lvl = py::upper(level);
  if (lvl.size() < 7) lvl += std::string(7 - lvl.size(), ' ');
  return "[" + lvl + "] " + behavior_id + ": " + message;
}

std::vector<Finding> validate(const LoadResult& result, const AtlasCatalog& catalog, const fs::path& root) {
  std::vector<Finding> findings;
  for (const auto& e : result.errors) findings.push_back({e.path.string(), "error", e.message});
  for (const auto& b : result.behaviors) {
    auto f = check(b, catalog, root);
    findings.insert(findings.end(), f.begin(), f.end());
  }
  return findings;
}

}  // namespace abm
