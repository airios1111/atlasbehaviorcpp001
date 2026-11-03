// YAML <-> Value with PyYAML SafeLoader / safe_dump semantics (YAML 1.1 implicit typing,
// block-style output, insertion-ordered mappings).
#pragma once

#include "abm/util/pyfmt.hpp"

#include <filesystem>
#include <stdexcept>
#include <string>
#include <vector>

namespace abm::yaml {

class YamlError : public std::runtime_error {
 public:
  using std::runtime_error::runtime_error;
};

Value load(const std::string& text);                    // yaml.safe_load
std::vector<Value> load_all(const std::string& text);   // yaml.safe_load_all
Value load_file(const std::filesystem::path& path);

struct DumpOptions {
  bool allow_unicode = false;
};
std::string dump(const Value& v, DumpOptions opts = {});                     // yaml.safe_dump(sort_keys=False)
std::string dump_all(const std::vector<Value>& docs, DumpOptions opts = {}); // yaml.safe_dump_all

// Resolve a plain (unquoted) scalar the way PyYAML's SafeLoader does.
Value resolve_plain(const std::string& s);

std::string read_text(const std::filesystem::path& path);
void write_text(const std::filesystem::path& path, const std::string& content);

}  // namespace abm::yaml
