#include "abm/coverage.hpp"

#include "abm/engine.hpp"
#include "abm/response.hpp"
#include "abm/util/regex.hpp"
#include "abm/util/yaml.hpp"

#include <algorithm>

namespace fs = std::filesystem;

namespace abm {
namespace {

std::pair<int, std::string> behavior_score(const Behavior& b, const fs::path& root) {
  if (b.status == Status::deprecated) return {0, "deprecated"};
  if (b.status == Status::experimental)
    return b.countermeasures.mitigations.empty() ? std::pair<int, std::string>{0, "experimental, no mitigations"}
                                                 : std::pair<int, std::string>{1, "experimental detection"};
  int score = 2;
  std::string note = to_string(b.status) + " detection";
  if (b.status == Status::stable) {
    bool any_auto = false;
    for (const auto& s : b.countermeasures.response) {
      const ActionSpec* spec = action_registry().find(s.action);
      if (!spec) spec = &action_registry().at("notify");
      if (!s.requires_approval.value_or(spec->requires_approval)) any_auto = true;
    }
    auto results = run_tests(b, root);
    const bool all_pass = std::all_of(results.begin(), results.end(), [](const TestResult& r) { return r.passed; });
    if (any_auto && !results.empty() && all_pass) {
      score = 3;
      note = "stable, auto-response, replay passing";
    } else if (!all_pass) {
      note = "stable but replay FAILING";
    }
  }
  return {score, note};
}

std::string shortname(const std::string& name) {
  static const Regex non_alnum(R"([^a-z0-9]+)");
  std::string s = non_alnum.sub(py::lower(name), [](const auto&) { return std::string("-"); });
  std::size_t b = 0, e = s.size();
  while (b < e && s[b] == '-') ++b;
  while (e > b && s[e - 1] == '-') --e;
  return s.substr(b, e - b);
}

}  // namespace

Value TechniqueCoverage::to_dict() const {
  Value d = Value::object();
  d["technique"] = technique;
  d["name"] = name;
  d["tactics"] = tactics;
  d["score"] = score;
  d["behaviors"] = behaviors;
  d["notes"] = notes;
  return d;
}

CoverageMap compute(const std::vector<Behavior>& behaviors, const AtlasCatalog& catalog, const fs::path& root) {
  CoverageMap cov;
  for (const auto& [tid, e] : catalog.techniques)
    cov.set(tid, TechniqueCoverage{tid, catalog.name(tid), e.tactics, 0, {}, {}});
  for (const auto& b : behaviors) {
    auto [s, note] = behavior_score(b, root);
    for (const auto& ref : b.atlas.techniques) {
      TechniqueCoverage* c = cov.find(ref.id);
      if (ref.relationship == "precondition" || !c) continue;
      c->behaviors.push_back(b.id);
      c->notes.push_back(b.id + ": " + note);
      c->score = std::max(c->score, s);
    }
  }
  return cov;
}

std::vector<TechniqueCoverage> gaps(const CoverageMap& cov, const std::optional<std::string>& tactic, int below) {
  std::vector<TechniqueCoverage> out;
  for (const auto& [k, c] : cov) {
    if (c.score >= below) continue;
    if (tactic && std::find(c.tactics.begin(), c.tactics.end(), *tactic) == c.tactics.end()) continue;
    out.push_back(c);
  }
  return out;
}

Value navigator_layer(const CoverageMap& cov, const AtlasCatalog& catalog, const std::string& name) {
  Value techniques = Value::array();
  for (const auto& [k, c] : cov) {
    if (c.score == 0) continue;
    std::vector<std::string> tacs = c.tactics.empty() ? std::vector<std::string>{""} : c.tactics;
    for (const auto& tac : tacs) {
      Value entry = Value::object();
      entry["techniqueID"] = c.technique;
      entry["score"] = c.score;
      entry["color"] = SCORE_COLOR[static_cast<std::size_t>(c.score)];
      entry["comment"] = std::string(SCORE_LABEL[static_cast<std::size_t>(c.score)]) + " | " + py::join(c.notes, "; ");
      Value meta = Value::object();
      meta["name"] = "behaviors";
      meta["value"] = py::join(c.behaviors, ", ");
      entry["metadata"] = Value::array({meta});
      entry["enabled"] = true;
      if (!tac.empty() && catalog.tactics.contains(tac)) entry["tactic"] = shortname(catalog.tactics.at(tac).name);
      techniques.push_back(entry);
    }
  }
  Value layer = Value::object();
  layer["name"] = name;
  layer["versions"] = Value::object();
  layer["versions"]["layer"] = "4.5";
  layer["versions"]["navigator"] = "4.9.1";
  layer["domain"] = "atlas-atlas";
  layer["description"] = "Generated from behaviors; catalog " + catalog.source + " " + catalog.version;
  layer["gradient"] = Value::object();
  layer["gradient"]["colors"] = Value::array({SCORE_COLOR[0], SCORE_COLOR[3]});
  layer["gradient"]["minValue"] = 0;
  layer["gradient"]["maxValue"] = 3;
  Value legend = Value::array();
  for (std::size_t k = 0; k < SCORE_LABEL.size(); ++k) {
    Value item = Value::object();
    item["label"] = std::to_string(k) + ": " + SCORE_LABEL[k];
    item["color"] = SCORE_COLOR[k];
    legend.push_back(item);
  }
  layer["legendItems"] = legend;
  layer["techniques"] = techniques;
  return layer;
}

std::string markdown_report(const CoverageMap& cov, const AtlasCatalog& catalog) {
  const std::size_t total = cov.size();
  std::size_t covered = 0;
  for (const auto& [k, c] : cov)
    if (c.score >= 2) ++covered;
  const double pct = total ? static_cast<double>(covered) / static_cast<double>(total) * 100 : 0;
  std::vector<std::string> lines = {
      "# ATLAS Coverage Report",
      "",
      "Catalog: `" + catalog.source + "` version `" + catalog.version + "`  ",
      "Techniques with detection (score >= 2): **" + std::to_string(covered) + "/" + std::to_string(total) + "** (" +
          py::format_f(pct, 0) + "%)",
      "",
  };
  for (const auto& [tac_id, tac] : catalog.tactics) {
    std::vector<const TechniqueCoverage*> rows;
    for (const auto& [k, c] : cov)
      if (std::find(c.tactics.begin(), c.tactics.end(), tac_id) != c.tactics.end()) rows.push_back(&c);
    if (rows.empty()) continue;
    std::stable_sort(rows.begin(), rows.end(),
                     [](const auto* a, const auto* b) { return a->technique < b->technique; });
    lines.push_back("## " + tac.name + " (" + tac_id + ")");
    lines.push_back("");
    lines.push_back("| Technique | Name | Score | Behaviors |");
    lines.push_back("|---|---|---|---|");
    for (const auto* c : rows) {
      lines.push_back("| " + c->technique + " | " + c->name + " | " + std::to_string(c->score) + " (" +
                      SCORE_LABEL[static_cast<std::size_t>(c->score)] + ") | " +
                      (c->behaviors.empty() ? std::string("\xE2\x80\x94") : py::join(c->behaviors, ", ")) + " |");
    }
    lines.push_back("");
  }
  return py::join(lines, "\n");
}

std::vector<fs::path> write_reports(const CoverageMap& cov, const AtlasCatalog& catalog, const fs::path& out_dir,
                                    const std::optional<fs::path>& layer_path_opt) {
  fs::create_directories(out_dir);
  const fs::path layer_path = layer_path_opt.value_or(out_dir / "atlas-layer.json");
  if (layer_path.has_parent_path()) fs::create_directories(layer_path.parent_path());

  Value all = Value::array(), gap_rows = Value::array();
  for (const auto& [k, c] : cov) all.push_back(c.to_dict());
  for (const auto& c : gaps(cov)) gap_rows.push_back(c.to_dict());

  std::vector<std::pair<fs::path, std::string>> files = {
      {out_dir / "coverage.md", markdown_report(cov, catalog)},
      {out_dir / "coverage.json", py::json_dumps(all, 2)},
      {out_dir / "gaps.json", py::json_dumps(gap_rows, 2)},
      {layer_path, py::json_dumps(navigator_layer(cov, catalog), 2)},
  };
  std::vector<fs::path> out;
  for (const auto& [p, content] : files) {
    yaml::write_text(p, content + "\n");
    out.push_back(p);
  }
  return out;
}

}  // namespace abm
