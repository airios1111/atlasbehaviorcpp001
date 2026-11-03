#include "abm/catalog.hpp"

#include "abm/util/hash.hpp"
#include "abm/util/http.hpp"
#include "abm/util/pyfmt.hpp"
#include "abm/util/timeutil.hpp"
#include "abm/util/yaml.hpp"

#include <algorithm>
#include <stdexcept>

namespace abm {
namespace {

Value get(const Value& obj, const std::string& key, Value dflt = nullptr) {
  if (!obj.is_object()) return dflt;
  auto it = obj.find(key);
  return it == obj.end() ? dflt : *it;
}

std::string req_str(const Value& obj, const std::string& key) {
  if (!obj.is_object() || !obj.contains(key)) throw std::runtime_error("KeyError: '" + key + "'");
  return py::str(obj.at(key));
}

std::vector<std::string> str_list(const Value& v) {
  std::vector<std::string> out;
  if (v.is_array())
    for (const auto& x : v) out.push_back(py::str(x));
  return out;
}

Value row(const Entry& e) {
  Value d = Value::object();
  d["id"] = e.id;
  d["name"] = e.name;
  if (!e.tactics.empty()) d["tactics"] = e.tactics;
  if (e.parent) d["parent"] = *e.parent;
  return d;
}

std::vector<const Entry*> sorted_entries(const OrderedMap<Entry>& m) {
  std::vector<const Entry*> out;
  for (const auto& [k, e] : m) out.push_back(&e);
  std::stable_sort(out.begin(), out.end(), [](const Entry* a, const Entry* b) { return a->id < b->id; });
  return out;
}

}  // namespace

bool AtlasCatalog::has(const std::string& id) const {
  return tactics.contains(id) || techniques.contains(id) || mitigations.contains(id);
}

std::string AtlasCatalog::name(const std::string& id) const {
  for (const auto* table : {&techniques, &tactics, &mitigations}) {
    if (const Entry* e = table->find(id)) {
      if (e->parent && techniques.contains(*e->parent))
        return techniques.at(*e->parent).name + ": " + e->name;
      return e->name;
    }
  }
  return "<unresolved>";
}

std::vector<std::string> AtlasCatalog::tactics_for(const std::string& technique_id) const {
  const Entry* e = techniques.find(technique_id);
  if (!e) return {};
  if (e->tactics.empty() && e->parent) return tactics_for(*e->parent);  // sub-techniques inherit
  return e->tactics;
}

AtlasCatalog AtlasCatalog::load(const std::filesystem::path& path) {
  Value data = yaml::load_file(path);
  AtlasCatalog cat;
  cat.source = py::str(get(data, "source", "unknown"));
  cat.version = py::str(get(data, "version", ""));
  for (const auto& t : get(data, "tactics", Value::array()))
    cat.tactics.set(req_str(t, "id"), Entry{req_str(t, "id"), req_str(t, "name"), {}, std::nullopt});
  for (const auto& t : get(data, "techniques", Value::array())) {
    Entry e{req_str(t, "id"), req_str(t, "name"), str_list(get(t, "tactics", Value::array())), std::nullopt};
    Value parent = get(t, "parent");
    if (py::truthy(parent)) e.parent = py::str(parent);
    cat.techniques.set(e.id, e);
  }
  for (const auto& m : get(data, "mitigations", Value::array()))
    cat.mitigations.set(req_str(m, "id"), Entry{req_str(m, "id"), req_str(m, "name"), {}, std::nullopt});
  return cat;
}

void AtlasCatalog::dump(const std::filesystem::path& path) const {
  Value out = Value::object();
  out["source"] = source;
  out["version"] = version;
  out["tactics"] = Value::array();
  for (const auto& [k, e] : tactics) out["tactics"].push_back(row(e));
  out["techniques"] = Value::array();
  for (const Entry* e : sorted_entries(techniques)) out["techniques"].push_back(row(*e));
  out["mitigations"] = Value::array();
  for (const Entry* e : sorted_entries(mitigations)) out["mitigations"].push_back(row(*e));
  yaml::write_text(path, yaml::dump(out));
}

AtlasCatalog AtlasCatalog::from_atlas_data(const std::string& raw) {
  Value data = yaml::load(raw);
  AtlasCatalog cat;
  cat.source = "mitre-atlas/atlas-data";
  cat.version = py::str(get(data, "version", "unknown"));
  Value matrices = get(data, "matrices");
  if (!py::truthy(matrices)) matrices = Value::array({data});

  for (const auto& mx : matrices) {
    Value tacs = get(mx, "tactics");
    if (tacs.is_array())
      for (const auto& t : tacs)
        cat.tactics.set(req_str(t, "id"), Entry{req_str(t, "id"), req_str(t, "name"), {}, std::nullopt});
    Value techs = get(mx, "techniques");
    if (!techs.is_array()) techs = Value::array();
    OrderedMap<const Value*> by_id;
    for (const auto& t : techs) by_id.set(req_str(t, "id"), &t);
    for (const auto& t : techs) {
      Value parent = get(t, "specializes");
      if (!py::truthy(parent)) parent = get(t, "subtechnique-of");
      Value tactics = get(t, "tactics");
      if (!py::truthy(tactics) && py::truthy(parent)) {
        const Value* const* p = by_id.find(py::str(parent));
        tactics = p ? get(**p, "tactics") : Value();
      }
      Entry e{req_str(t, "id"), req_str(t, "name"), str_list(tactics), std::nullopt};
      if (py::truthy(parent)) e.parent = py::str(parent);
      cat.techniques.set(e.id, e);
    }
    Value mits = get(mx, "mitigations");
    if (mits.is_array())
      for (const auto& m : mits)
        cat.mitigations.set(req_str(m, "id"), Entry{req_str(m, "id"), req_str(m, "name"), {}, std::nullopt});
  }
  if (cat.techniques.empty()) throw std::invalid_argument("no techniques found: unrecognized ATLAS.yaml layout");
  return cat;
}

AtlasCatalog sync(const std::filesystem::path& dest, const std::filesystem::path& lock, const std::string& url,
                  const std::optional<std::filesystem::path>& local_file) {
  std::string raw, origin;
  if (local_file) {
    raw = yaml::read_text(*local_file);
    origin = local_file->string();
  } else {
    http::Request req{"GET", url, {}, "", 30};
    http::Response resp = http::default_transport()->send(req);
    if (resp.status < 200 || resp.status >= 300)
      throw http::TransportError("HTTPError", "HTTP Error " + std::to_string(resp.status));
    raw = resp.body;
    origin = url;
  }
  AtlasCatalog cat = AtlasCatalog::from_atlas_data(raw);
  cat.dump(dest);
  Value lockdoc = Value::object();
  lockdoc["origin"] = origin;
  lockdoc["version"] = cat.version;
  lockdoc["sha256"] = hash::sha256_hex(raw);
  lockdoc["synced_at"] = timeutil::now_iso_seconds();
  lockdoc["counts"] = Value::object();
  lockdoc["counts"]["tactics"] = cat.tactics.size();
  lockdoc["counts"]["techniques"] = cat.techniques.size();
  lockdoc["counts"]["mitigations"] = cat.mitigations.size();
  yaml::write_text(lock, yaml::dump(lockdoc));
  return cat;
}

}  // namespace abm
