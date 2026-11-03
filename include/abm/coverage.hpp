// Coverage scoring against the ATLAS matrix, gap listing, and ATLAS Navigator layer output.
#pragma once

#include "abm/catalog.hpp"
#include "abm/models.hpp"

#include <array>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace abm {

inline const std::array<const char*, 4> SCORE_LABEL = {
    "none",
    "mitigation-only",
    "detection",
    "detection + automated response (replay passing)",
};
inline const std::array<const char*, 4> SCORE_COLOR = {"#ffffff", "#fde68a", "#93c5fd", "#34d399"};

struct TechniqueCoverage {
  std::string technique;
  std::string name;
  std::vector<std::string> tactics;
  int score = 0;
  std::vector<std::string> behaviors;
  std::vector<std::string> notes;

  Value to_dict() const;
};

using CoverageMap = OrderedMap<TechniqueCoverage>;

CoverageMap compute(const std::vector<Behavior>& behaviors, const AtlasCatalog& catalog,
                    const std::filesystem::path& root);

std::vector<TechniqueCoverage> gaps(const CoverageMap& cov, const std::optional<std::string>& tactic = std::nullopt,
                                    int below = 1);

Value navigator_layer(const CoverageMap& cov, const AtlasCatalog& catalog,
                      const std::string& name = "ATLAS Behavior Map coverage");

std::string markdown_report(const CoverageMap& cov, const AtlasCatalog& catalog);

std::vector<std::filesystem::path> write_reports(const CoverageMap& cov, const AtlasCatalog& catalog,
                                                 const std::filesystem::path& out_dir,
                                                 const std::optional<std::filesystem::path>& layer_path = std::nullopt);

}  // namespace abm
