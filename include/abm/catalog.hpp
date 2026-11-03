// ATLAS catalog: tactic/technique/mitigation lookup, plus import from the official atlas-data release.
#pragma once

#include "abm/ordered_map.hpp"

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace abm {

inline constexpr const char* ATLAS_DATA_URL =
    "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml";

struct Entry {
  std::string id;
  std::string name;
  std::vector<std::string> tactics;
  std::optional<std::string> parent;
};

struct AtlasCatalog {
  std::string source;
  std::string version;
  OrderedMap<Entry> tactics;
  OrderedMap<Entry> techniques;
  OrderedMap<Entry> mitigations;

  // ---- lookup
  bool has(const std::string& atlas_id) const;
  std::string name(const std::string& atlas_id) const;
  std::vector<std::string> tactics_for(const std::string& technique_id) const;

  // ---- io
  static AtlasCatalog load(const std::filesystem::path& path);
  void dump(const std::filesystem::path& path) const;

  // Parse the official dist/ATLAS.yaml (handles both matrix-nested and flat layouts).
  static AtlasCatalog from_atlas_data(const std::string& raw);
};

// Fetch (or import) ATLAS.yaml, write catalog + lock file with checksum.
AtlasCatalog sync(const std::filesystem::path& dest, const std::filesystem::path& lock,
                  const std::string& url = ATLAS_DATA_URL,
                  const std::optional<std::filesystem::path>& local_file = std::nullopt);

}  // namespace abm
