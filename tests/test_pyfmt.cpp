// The Python-compatibility layer: expected values were produced by CPython 3.12+.
#include "abm/util/hash.hpp"
#include "abm/util/pyfmt.hpp"
#include "abm/util/regex.hpp"
#include "abm/util/timeutil.hpp"
#include "abm/util/yaml.hpp"
#include "support.hpp"

using namespace abm;

TEST_CASE("float repr") {
  CHECK(py::float_repr(5000.0) == "5000.0");
  CHECK(py::float_repr(0.15) == "0.15");
  CHECK(py::float_repr(0.1 + 0.2) == "0.30000000000000004");
  CHECK(py::float_repr(1e16) == "1e+16");
  CHECK(py::float_repr(1e15) == "1000000000000000.0");
  CHECK(py::float_repr(0.0001) == "0.0001");
  CHECK(py::float_repr(0.00001) == "1e-05");
  CHECK(py::float_repr(-2.5) == "-2.5");
  CHECK(py::float_repr(123456789.125) == "123456789.125");
}

TEST_CASE("format g / f / round") {
  CHECK(py::format_g(5000.0) == "5000");
  CHECK(py::format_g(0.15) == "0.15");
  CHECK(py::format_g(0.0123456, 4) == "0.01235");
  CHECK(py::format_g(1234567.0) == "1.23457e+06");
  CHECK(py::format_f(66.5, 0) == "66");
  CHECK(py::round(0.1234565, 6) == 0.123456);
}

TEST_CASE("json.dumps") {
  // (escapes spelled with "\\u" because compilers expand \u inside raw string literals)
  Value v = Value::parse("{\"b\": [1, 2.0, true, null], \"a\": \"\\u00e9\\n\"}");
  CHECK(py::json_dumps(v) == "{\"b\": [1, 2.0, true, null], \"a\": \"\\u00e9\\n\"}");
  CHECK(py::json_dumps(v, -1, true) == "{\"a\": \"\\u00e9\\n\", \"b\": [1, 2.0, true, null]}");
  CHECK(py::json_dumps(Value::parse(R"({"a": [1], "e": []})"), 2) == "{\n  \"a\": [\n    1\n  ],\n  \"e\": []\n}");
}

TEST_CASE("repr") {
  CHECK(py::repr(Value::parse(R"({"event_type": "tool_call", "risk": {"in": ["high", 2, null, true]}})")) ==
        "{'event_type': 'tool_call', 'risk': {'in': ['high', 2, None, True]}}");
  CHECK(py::repr_str("it's") == "\"it's\"");
  CHECK(py::repr_str("a\\b") == "'a\\\\b'");
}

TEST_CASE("hashes and uuid5") {
  CHECK(hash::sha256_hex("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
  // uuid.uuid5(uuid.NAMESPACE_DNS, "python.org")
  CHECK(hash::uuid5("6ba7b810-9dad-11d1-80b4-00c04fd430c8", "python.org") == "886313e1-3b8a-5372-9b90-0c9aee199e5d");
}

TEST_CASE("timestamps") {
  CHECK(timeutil::parse_iso_timestamp("2026-10-01T14:00:00Z") == 1790863200.0);
  CHECK(timeutil::parse_iso_timestamp("2026-10-01T14:00:00.600000Z") == 1790863200.6);
  CHECK(timeutil::parse_iso_timestamp("2026-10-01T16:00:00+02:00") == 1790863200.0);
  CHECK(timeutil::parse_iso_timestamp("2026-10-01 14:00:00") == 1790863200.0);
  CHECK_THROWS_AS(timeutil::parse_iso_timestamp("not a date"), std::invalid_argument);
  CHECK(timeutil::iso_from_epoch(1790863200) == "2026-10-01T14:00:00+00:00");
}

TEST_CASE("YAML 1.1 implicit typing like PyYAML") {
  Value v = yaml::load("a: yes\nb: 010\nc: 1_000\nd: 1.5\ne: 1e5\nf: ~\ng: '1'\nh: 1:30\ni: .inf\n");
  CHECK(v["a"] == true);
  CHECK(v["b"] == 8);
  CHECK(v["c"] == 1000);
  CHECK(v["d"] == 1.5);
  CHECK(v["e"] == "1e5");  // PyYAML requires a dot for floats
  CHECK(v["f"].is_null());
  CHECK(v["g"] == "1");
  CHECK(v["h"] == 90);
  CHECK(v["i"].get<double>() > 1e308);
}

TEST_CASE("YAML dump round-trips and quotes ambiguous scalars") {
  Value v = Value::parse(R"({"s": "yes", "n": "5.6", "t": "2026-10-29T13:29:53+00:00", "r": "(?i)\\bx: y",
                             "l": ["a", {"k": "v"}], "e": [], "m": {"x": 1}})");
  std::string out = yaml::dump(v);
  CHECK(out.find("s: 'yes'") != std::string::npos);
  CHECK(out.find("n: '5.6'") != std::string::npos);
  CHECK(out.find("t: '2026-10-29T13:29:53+00:00'") != std::string::npos);
  CHECK(yaml::load(out) == v);
}

TEST_CASE("regex: Python syntax on PCRE2") {
  CHECK(Regex(R"((?i)\bignore\s+previous\b)").search("Please IGNORE   previous instructions"));
  CHECK_FALSE(Regex(R"(\bfoo\b)").search("foobar"));
  CHECK(Regex(R"(é)").search("caf\xC3\xA9"));
  CHECK_THROWS_AS(Regex("("), RegexError);
}
