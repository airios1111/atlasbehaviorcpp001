#include "abm/cli.hpp"

#include "abm/catalog.hpp"
#include "abm/compilers.hpp"
#include "abm/coverage.hpp"
#include "abm/engine.hpp"
#include "abm/loader.hpp"
#include "abm/response.hpp"
#include "abm/util/yaml.hpp"
#include "abm/validator.hpp"

#include <CLI/CLI.hpp>

#include <algorithm>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <optional>

namespace fs = std::filesystem;

namespace abm::cli {
namespace {

struct Args {
  std::string root, catalog;
  // validate
  std::string path;
  bool run_tests = false, quiet = false;
  // compile
  std::string target = "all", out, compile_path;
  bool include_deprecated = false;
  // map
  std::string behavior, technique, format = "table";
  // coverage
  std::string matrix = "atlas", layer;
  // gaps
  std::string tactic;
  int below = 1;
  // replay
  std::string fixture, expect, webhook, xsoar, xsoar_incident_type = "AI Security Alert";
  bool respond = false;
  // atlas-sync
  std::string file;
};

struct Io {
  std::ostream& out;
  std::ostream& err;
};

std::optional<std::string> env(const char* name) {
  const char* v = std::getenv(name);
  if (!v) return std::nullopt;
  return std::string(v);
}

// ---------------------------------------------------------------- helpers
std::pair<fs::path, AtlasCatalog> context(const Args& a) {
  fs::path root = a.root.empty() ? find_root() : fs::absolute(a.root);
  fs::path catalog_path = a.catalog.empty() ? root / "atlas" / "catalog.yaml" : fs::path(a.catalog);
  return {root, AtlasCatalog::load(catalog_path)};
}

LoadResult behaviors(const fs::path& root, const std::string& path, Io& io) {
  LoadResult res = load_behaviors(path.empty() ? root / "behaviors" : fs::path(path));
  for (const auto& e : res.errors) io.err << "[ERROR  ] " << e.path.string() << ": " << e.message << "\n";
  return res;
}

std::string table(const std::vector<std::vector<std::string>>& rows, const std::vector<std::string>& headers) {
  std::vector<std::size_t> widths;
  for (std::size_t c = 0; c < headers.size(); ++c) {
    std::size_t w = py::utf8_len(headers[c]);
    for (const auto& r : rows) w = std::max(w, py::utf8_len(r[c]));
    widths.push_back(w);
  }
  auto fmt = [&](const std::vector<std::string>& cells) {
    std::string line;
    for (std::size_t c = 0; c < cells.size(); ++c) {
      if (c) line += "  ";
      line += cells[c];  // every column is left-aligned and padded, like f"{x:<w}"
      line += std::string(widths[c] - py::utf8_len(cells[c]), ' ');
    }
    return line;
  };
  std::vector<std::string> out = {fmt(headers)};
  std::vector<std::string> dashes;
  for (auto w : widths) dashes.emplace_back(w, '-');
  out.push_back(fmt(dashes));
  for (const auto& r : rows) out.push_back(fmt(r));
  return py::join(out, "\n");
}

// ---------------------------------------------------------------- commands
int cmd_validate(const Args& a, Io& io) {
  auto [root, catalog] = context(a);
  LoadResult res = load_behaviors(a.path.empty() ? root / "behaviors" : fs::path(a.path));
  auto findings = validate(res, catalog, root);
  std::size_t errors = 0, warnings = 0;
  for (const auto& f : findings) {
    if (f.level == "error") ++errors;
    else ++warnings;
    if (f.level == "error" || !a.quiet) io.out << f.str() << "\n";
  }
  if (a.run_tests) {
    for (const auto& b : res.behaviors) {
      for (const auto& r : run_tests(b, root)) {
        if (!r.passed) {
          ++errors;
          io.out << "[ERROR  ] " << b.id << ": test " << r.fixture << " expected " << r.expect << ", got "
                 << r.alert_count << " alert(s)\n";
        }
      }
    }
  }
  if (catalog.source == "seed") {
    io.out << "[WARNING] catalog is the unverified seed subset; run `abm atlas-sync` for drift checks "
              "against the official ATLAS release\n";
  }
  io.out << "\n" << res.behaviors.size() << " behavior(s), " << errors << " error(s), " << warnings
         << " warning(s)\n";
  return errors ? 1 : 0;
}

int cmd_compile(const Args& a, Io& io) {
  auto [root, catalog] = context(a);
  LoadResult res = behaviors(root, a.compile_path, io);
  std::vector<const compilers::Target*> targets;
  if (a.target == "all") {
    for (const auto& t : compilers::targets()) targets.push_back(&t);
  } else {
    targets.push_back(compilers::find_target(a.target));
  }
  const fs::path out_root = a.out.empty() ? root / "dist" : fs::path(a.out);
  int n = 0;
  for (const auto* t : targets) {
    const fs::path out = (a.target == "all" || a.out.empty()) ? out_root / t->name : out_root;
    fs::create_directories(out);
    for (const auto& b : res.behaviors) {
      if (b.status == Status::deprecated && !a.include_deprecated) continue;
      yaml::write_text(out / (b.id + t->extension), t->compile(b));
      ++n;
    }
  }
  io.out << "compiled " << n << " rule(s) -> " << out_root.string() << "\n";
  return res.errors.empty() ? 0 : 1;
}

int cmd_map(const Args& a, Io& io) {
  auto [root, catalog] = context(a);
  LoadResult res = behaviors(root, "", io);
  std::vector<const Behavior*> bs;
  for (const auto& b : res.behaviors) {
    if (!a.behavior.empty() && b.id != a.behavior) continue;
    if (!a.technique.empty() &&
        std::none_of(b.atlas.techniques.begin(), b.atlas.techniques.end(),
                     [&](const TechniqueRef& t) { return t.id.rfind(a.technique, 0) == 0; }))
      continue;
    bs.push_back(&b);
  }
  if (bs.empty()) {
    io.err << "no matching behaviors\n";
    return 1;
  }
  if (a.format == "json") {
    Value arr = Value::array();
    for (const auto* b : bs) {
      auto named = [&](const std::string& id) {
        Value o = Value::object();
        o["id"] = id;
        o["name"] = catalog.name(id);
        return o;
      };
      Value d = Value::object();
      d["behavior"] = b->id;
      d["name"] = b->name;
      d["status"] = to_string(b->status);
      d["tactics"] = Value::array();
      for (const auto& t : b->atlas.tactics) d["tactics"].push_back(named(t));
      d["techniques"] = Value::array();
      for (const auto& t : b->atlas.techniques) {
        Value o = named(t.id);
        o["relationship"] = t.relationship;
        d["techniques"].push_back(o);
      }
      d["mitigations"] = Value::array();
      for (const auto& m : b->countermeasures.mitigations) d["mitigations"].push_back(named(m));
      d["response"] = Value::array();
      for (const auto& s : b->countermeasures.response) d["response"].push_back(s.action);
      d["attack_bridge"] = b->attack_bridge;
      arr.push_back(d);
    }
    io.out << py::json_dumps(arr, 2) << "\n";
    return 0;
  }
  std::vector<std::vector<std::string>> rows;
  for (const auto* b : bs) {
    std::vector<std::string> actions;
    for (const auto& s : b->countermeasures.response) actions.push_back(s.action);
    for (const auto& t : b->atlas.techniques) {
      rows.push_back({b->id, to_string(b->status), t.id, t.relationship, catalog.name(t.id),
                      py::join(b->countermeasures.mitigations, ", "), py::join(actions, ", ")});
    }
  }
  io.out << table(rows, {"BEHAVIOR", "STATUS", "TECHNIQUE", "REL", "NAME", "MITIGATIONS", "RESPONSE"}) << "\n";
  return 0;
}

int cmd_coverage(const Args& a, Io& io) {
  auto [root, catalog] = context(a);
  LoadResult res = behaviors(root, "", io);
  CoverageMap cov = compute(res.behaviors, catalog, root);
  auto paths = write_reports(cov, catalog, a.out.empty() ? root / "reports" : fs::path(a.out),
                             a.layer.empty() ? std::nullopt : std::optional<fs::path>(a.layer));
  std::vector<std::vector<std::string>> rows;
  for (std::size_t s = 0; s < SCORE_LABEL.size(); ++s) {
    std::size_t count = 0;
    for (const auto& [k, c] : cov)
      if (c.score == static_cast<int>(s)) ++count;
    rows.push_back({std::to_string(s), SCORE_LABEL[s], std::to_string(count)});
  }
  io.out << table(rows, {"SCORE", "MEANING", "TECHNIQUES"}) << "\n";
  for (const auto& p : paths) io.out << "wrote " << p.string() << "\n";
  return 0;
}

int cmd_gaps(const Args& a, Io& io) {
  auto [root, catalog] = context(a);
  LoadResult res = behaviors(root, "", io);
  auto gs = gaps(compute(res.behaviors, catalog, root),
                 a.tactic.empty() ? std::nullopt : std::optional<std::string>(a.tactic), a.below);
  std::stable_sort(gs.begin(), gs.end(), [](const auto& x, const auto& y) { return x.technique < y.technique; });
  std::vector<std::vector<std::string>> rows;
  for (const auto& g : gs) rows.push_back({g.technique, g.name, py::join(g.tactics, ", "), std::to_string(g.score)});
  io.out << (rows.empty() ? std::string("no gaps") : table(rows, {"TECHNIQUE", "NAME", "TACTICS", "SCORE"})) << "\n";
  return 0;
}

std::unique_ptr<Executor> make_executor(const Args& a) {
  if (!a.xsoar.empty()) {
    // secrets only from the environment, never the command line (shell history, process list)
    auto key_id = env("XSOAR_API_KEY_ID");
    if (key_id && key_id->empty()) key_id.reset();
    return std::make_unique<XsoarExecutor>(a.xsoar, env("XSOAR_API_KEY").value_or(""), key_id,
                                           a.xsoar_incident_type);
  }
  if (!a.respond) return nullptr;
  if (!a.webhook.empty()) return std::make_unique<WebhookExecutor>(a.webhook);
  return std::make_unique<DryRunExecutor>();
}

int cmd_replay(const Args& a, Io& io) {
  auto [root, catalog] = context(a);
  LoadResult res = behaviors(root, "", io);
  std::vector<Behavior> bs;
  for (const auto& b : res.behaviors)
    if (a.behavior.empty() || b.id == a.behavior) bs.push_back(b);
  auto events = load_events(a.fixture);
  Engine engine(bs, &catalog);
  auto alerts = engine.run(events);
  std::unique_ptr<Executor> executor;
  try {
    executor = make_executor(a);
  } catch (const std::invalid_argument& e) {
    io.err << "replay: " << e.what() << "\n";
    return 2;
  }
  for (const auto& alert : alerts) {
    Value rec = alert.to_dict();
    if (executor) {
      const Behavior* b = nullptr;
      for (const auto& x : bs)
        if (x.id == alert.behavior_id) b = &x;
      Value resp = Value::array();
      for (const auto& p : run_plan(*executor, alert, plan(*b, alert))) resp.push_back(p.to_dict());
      rec["response"] = resp;
    }
    io.out << py::json_dumps(rec) << "\n";
  }
  io.err << "# " << alerts.size() << " alert(s) from " << events.size() << " event(s)\n";
  if (!a.expect.empty()) {
    const bool ok = (!alerts.empty()) == (a.expect == "alert");
    io.err << "# expect=" << a.expect << ": " << (ok ? "PASS" : "FAIL") << "\n";
    return ok ? 0 : 1;
  }
  return 0;
}

int cmd_test(const Args& a, Io& io) {
  auto [root, catalog] = context(a);
  LoadResult res = behaviors(root, "", io);
  std::size_t failed = 0;
  std::vector<std::vector<std::string>> rows;
  for (const auto& b : res.behaviors) {
    for (const auto& r : run_tests(b, root)) {
      if (!r.passed) ++failed;
      rows.push_back({b.id, fs::path(r.fixture).filename().string(), r.expect, std::to_string(r.alert_count),
                      r.passed ? "PASS" : "FAIL"});
    }
  }
  io.out << table(rows, {"BEHAVIOR", "FIXTURE", "EXPECT", "ALERTS", "RESULT"}) << "\n";
  io.out << "\n" << rows.size() - failed << "/" << rows.size() << " passed\n";
  return (failed || !res.errors.empty()) ? 1 : 0;
}

int cmd_atlas_sync(const Args& a, Io& io) {
  fs::path root = a.root.empty() ? find_root() : fs::absolute(a.root);
  fs::path dest = a.catalog.empty() ? root / "atlas" / "catalog.yaml" : fs::path(a.catalog);
  fs::path lock = root / "atlas" / "atlas-data.lock";
  try {
    AtlasCatalog cat = sync(dest, lock, ATLAS_DATA_URL,
                            a.file.empty() ? std::nullopt : std::optional<fs::path>(a.file));
    io.out << "ATLAS " << cat.version << ": " << cat.tactics.size() << " tactics, " << cat.techniques.size()
           << " techniques, " << cat.mitigations.size() << " mitigations -> " << dest.string() << "\n";
    return 0;
  } catch (const http::TransportError& e) {
    io.err << "sync failed: " << e.what()
           << ". Download dist/ATLAS.yaml from mitre-atlas/atlas-data and run `abm atlas-sync --file ATLAS.yaml`.\n";
    return 1;
  }
}

}  // namespace

// ---------------------------------------------------------------- parser
int run(const std::vector<std::string>& argv, std::ostream& out, std::ostream& err) {
  Args a;
  Io io{out, err};
  CLI::App app{"ATLAS Behavior Map", "abm"};
  app.set_version_flag("--version", std::string("abm ") + ABM_VERSION);
  app.add_option("--root", a.root, "project root (default: auto-detect)");
  app.add_option("--catalog", a.catalog, "ATLAS catalog YAML (default: atlas/catalog.yaml)");
  app.require_subcommand(1);

  auto* s = app.add_subcommand("validate", "schema + ATLAS ID resolution + fixtures");
  s->add_option("path", a.path);
  s->add_flag("--run-tests", a.run_tests, "also replay declared test fixtures");
  s->add_flag("-q,--quiet", a.quiet, "errors only");

  std::vector<std::string> target_names;
  for (const auto& t : compilers::targets()) target_names.push_back(t.name);
  target_names.push_back("all");
  s = app.add_subcommand("compile", "compile behaviors to SIEM rules");
  s->add_option("--target", a.target)->check(CLI::IsMember(target_names))->capture_default_str();
  s->add_option("--out", a.out);
  s->add_option("--path", a.compile_path);
  s->add_flag("--include-deprecated", a.include_deprecated);

  s = app.add_subcommand("map", "show behavior -> ATLAS mapping");
  s->add_option("--behavior", a.behavior);
  s->add_option("--technique", a.technique, "filter by technique id prefix, e.g. AML.T0051");
  s->add_option("--format", a.format)->check(CLI::IsMember({"table", "json"}))->capture_default_str();

  s = app.add_subcommand("coverage", "coverage reports + Navigator layer");
  s->add_option("--matrix", a.matrix)->check(CLI::IsMember({"atlas"}))->capture_default_str();
  s->add_option("--out", a.out, "report directory (default: reports/)");
  s->add_option("--layer", a.layer, "Navigator layer path (default: reports/atlas-layer.json)");

  s = app.add_subcommand("gaps", "list uncovered techniques");
  s->add_option("--tactic", a.tactic);
  s->add_option("--below", a.below, "list techniques scoring below N (default 1)")->capture_default_str();

  s = app.add_subcommand("replay", "run behaviors over a JSONL telemetry file");
  s->add_option("--fixture", a.fixture)->required();
  s->add_option("--behavior", a.behavior);
  s->add_option("--expect", a.expect)->check(CLI::IsMember({"alert", "no_alert"}));
  s->add_flag("--respond", a.respond, "plan response actions (dry-run default)");
  s->add_option("--webhook", a.webhook, "https SOAR webhook for auto-approved actions");
  s->add_option("--xsoar", a.xsoar,
                "create a Cortex XSOAR incident per alert (implies --respond); reads XSOAR_API_KEY and, for "
                "XSOAR 8, XSOAR_API_KEY_ID from the environment")
      ->option_text("URL");
  s->add_option("--xsoar-incident-type", a.xsoar_incident_type, "XSOAR incident type")->capture_default_str();

  app.add_subcommand("test", "run every behavior's declared fixture tests");

  s = app.add_subcommand("atlas-sync", "import official ATLAS release into the catalog");
  s->add_option("--file", a.file, "local ATLAS.yaml instead of downloading");

  std::vector<std::string> rev(argv.rbegin(), argv.rend());
  try {
    app.parse(rev);
  } catch (const CLI::ParseError& e) {
    int code = app.exit(e, out, err);
    return code == 0 ? 0 : 2;
  }

  const std::string cmd = app.get_subcommands().front()->get_name();
  try {
    if (cmd == "validate") return cmd_validate(a, io);
    if (cmd == "compile") return cmd_compile(a, io);
    if (cmd == "map") return cmd_map(a, io);
    if (cmd == "coverage") return cmd_coverage(a, io);
    if (cmd == "gaps") return cmd_gaps(a, io);
    if (cmd == "replay") return cmd_replay(a, io);
    if (cmd == "test") return cmd_test(a, io);
    if (cmd == "atlas-sync") return cmd_atlas_sync(a, io);
  } catch (const std::exception& e) {
    err << "abm: error: " << e.what() << "\n";
    return 1;
  }
  return 2;
}

}  // namespace abm::cli
