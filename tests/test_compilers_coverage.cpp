#include "abm/compilers.hpp"
#include "abm/coverage.hpp"
#include "abm/util/regex.hpp"
#include "abm/util/yaml.hpp"
#include "abm/validator.hpp"
#include "support.hpp"

#include <set>

using namespace abm;
using namespace abm::testing;

TEST_CASE("every behavior compiles to every target") {
  for (const auto& [id, b] : behaviors()) {
    for (const auto& t : compilers::targets()) {
      CAPTURE(t.name);
      CAPTURE(id);
      std::string out = t.compile(b);
      CHECK(out.find(b.id) != std::string::npos);
      CHECK(py::lower(out).find(py::lower(b.primary_technique())) != std::string::npos);
    }
  }
}

TEST_CASE("every sigma rule is valid YAML") {
  for (const auto& [id, b] : behaviors()) {
    CAPTURE(id);
    CHECK_NOTHROW(yaml::load_all(compilers::find_target("sigma")->compile(b)));
  }
}

TEST_CASE("sigma is valid YAML with ATLAS tags") {
  auto docs = yaml::load_all(compilers::find_target("sigma")->compile(behaviors().at("BHV-EXF-003")));
  REQUIRE(docs.size() == 2);
  CHECK(docs[0]["id"] == compilers::sigma::rule_id("BHV-EXF-003"));
  bool tagged = false;
  for (const auto& t : docs[0]["tags"]) tagged = tagged || t == "atlas.aml.t0024.002";
  CHECK(tagged);
  CHECK(docs[1]["correlation"]["condition"] == Value::parse(R"({"gt": 5000})"));
}

TEST_CASE("sigma rule ids are stable uuid5 values") {
  // uuid.uuid5(uuid.UUID("8a3c0e1e-6c1f-4b7a-9d42-41b8a7d0a7f1"), "BHV-EXF-003") from the Python build
  CHECK(compilers::sigma::rule_id("BHV-EXF-003").size() == 36);
  CHECK(compilers::sigma::rule_id("BHV-EXF-003")[14] == '5');
}

TEST_CASE("kql threshold shape") {
  std::string q = compilers::find_target("kql")->compile(behaviors().at("BHV-EXF-003"));
  CHECK(q.find("summarize") != std::string::npos);
  CHECK(q.find("bin(TimeGenerated, 1h)") != std::string::npos);
  CHECK(q.find("RequestCount > 5000") != std::string::npos);
  CHECK(q.find(R"(PrincipalId !in ("sp-batch-eval")") != std::string::npos);
}

TEST_CASE("seed repo validates clean") {
  auto findings = validate(load_behaviors(root() / "behaviors"), catalog(), root());
  std::vector<std::string> errors;
  for (const auto& f : findings)
    if (f.level == "error") errors.push_back(f.str());
  CHECK_MESSAGE(errors.empty(), py::join(errors, "\n"));
}

TEST_CASE("drift detected against catalog without technique") {
  AtlasCatalog pruned = catalog();
  pruned.techniques.erase("AML.T0029");
  auto findings = validate(load_behaviors(root() / "behaviors"), pruned, root());
  bool found = false;
  for (const auto& f : findings)
    if (f.level == "error" && f.message.find("AML.T0029") != std::string::npos) found = true;
  CHECK(found);
}

TEST_CASE("coverage scores") {
  auto cov = compute(behavior_list(), catalog(), root());
  CHECK(cov.at("AML.T0024.002").score == 3);  // stable + auto response + replay passing
  CHECK(cov.at("AML.T0053").score == 2);      // test status
  CHECK(cov.at("AML.T0034").score == 1);      // experimental w/ mitigations
  CHECK(cov.at("AML.T0040").score == 0);      // precondition-only refs do not count
  for (const auto& g : gaps(cov)) CHECK(g.score == 0);
}

TEST_CASE("navigator layer") {
  Value layer = navigator_layer(compute(behavior_list(), catalog(), root()), catalog());
  CHECK_NOTHROW(py::json_dumps(layer));
  std::set<std::string> ids;
  for (const auto& t : layer["techniques"]) ids.insert(t["techniqueID"].get<std::string>());
  CHECK(ids.count("AML.T0051.000") == 1);
  CHECK(ids.count("AML.T0040") == 0);
}

TEST_CASE("atlas-data import parses matrix layout") {
  Value data = Value::parse(R"({
    "id": "ATLAS", "version": "9.9.9",
    "matrices": [{
      "tactics": [{"id": "AML.TA0010", "name": "Exfiltration"}],
      "techniques": [
        {"id": "AML.T0024", "name": "Exfil via API", "tactics": ["AML.TA0010"]},
        {"id": "AML.T0024.002", "name": "Extract Model", "specializes": "AML.T0024"}
      ],
      "mitigations": [{"id": "AML.M0004", "name": "Restrict Queries"}]
    }]
  })");
  AtlasCatalog cat = AtlasCatalog::from_atlas_data(yaml::dump(data));
  CHECK(cat.version == "9.9.9");
  CHECK(cat.tactics_for("AML.T0024.002") == std::vector<std::string>{"AML.TA0010"});  // inherited from parent
  CHECK(cat.name("AML.T0024.002") == "Exfil via API: Extract Model");
}

TEST_CASE("README coverage table matches behaviors") {
  std::string readme = yaml::read_text(root() / "README.md");
  auto start = readme.find("## Coverage Snapshot");
  auto end = readme.find("## Repository Structure");
  REQUIRE(start != std::string::npos);
  REQUIRE(end != std::string::npos);
  std::set<std::string> listed;
  static const Regex row(R"(^\| (BHV-[A-Z]+-\d{3}) \|)");
  for (const auto& line : lines(readme.substr(start, end - start))) {
    if (auto m = row.search_groups(line)) listed.insert(*(*m)[1]);
  }
  std::set<std::string> ids;
  for (const auto& [id, b] : behaviors()) ids.insert(id);
  CHECK(listed == ids);
}
