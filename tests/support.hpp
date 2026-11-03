// Shared fixtures for the doctest suite (the counterpart of tests/conftest.py).
#pragma once

#include "abm/catalog.hpp"
#include "abm/cli.hpp"
#include "abm/loader.hpp"
#include "abm/util/http.hpp"

#include <doctest/doctest.h>

#include <cstdlib>
#include <filesystem>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <vector>

namespace abm::testing {

inline std::filesystem::path root() { return std::filesystem::path(ABM_SOURCE_DIR); }

inline const AtlasCatalog& catalog() {
  static const AtlasCatalog cat = AtlasCatalog::load(root() / "atlas" / "catalog.yaml");
  return cat;
}

inline const std::map<std::string, Behavior>& behaviors() {
  static const std::map<std::string, Behavior> by_id = [] {
    LoadResult res = load_behaviors(root() / "behaviors");
    REQUIRE_MESSAGE(res.errors.empty(), (res.errors.empty() ? "" : res.errors.front().message));
    return res.by_id();
  }();
  return by_id;
}

inline std::vector<Behavior> behavior_list() {
  std::vector<Behavior> out;
  for (const auto& [k, b] : behaviors()) out.push_back(b);
  return out;
}

struct CliResult {
  int code;
  std::string out;
  std::string err;
};

inline CliResult run_cli(const std::vector<std::string>& args) {
  std::ostringstream out, err;
  int code = cli::run(args, out, err);
  return {code, out.str(), err.str()};
}

inline std::vector<std::string> lines(const std::string& s) {
  std::vector<std::string> out;
  std::istringstream in(s);
  std::string line;
  while (std::getline(in, line))
    if (!line.empty()) out.push_back(line);
  return out;
}

inline void set_env(const std::string& name, const std::string& value) {
#ifdef _WIN32
  _putenv_s(name.c_str(), value.c_str());
#else
  setenv(name.c_str(), value.c_str(), 1);
#endif
}

inline void unset_env(const std::string& name) {
#ifdef _WIN32
  _putenv_s(name.c_str(), "");
#else
  unsetenv(name.c_str());
#endif
}

// Records requests instead of sending them (the monkeypatched urlopen of the Python tests).
class FakeTransport : public http::Transport {
 public:
  explicit FakeTransport(long status = 201, std::string body = R"({"id": "4711"})", bool fail = false)
      : status_(status), body_(std::move(body)), fail_(fail) {}

  http::Response send(const http::Request& req) override {
    std::lock_guard<std::mutex> lock(mu_);
    sent.push_back(req);
    if (fail_) throw http::TransportError("OSError", "unreachable");
    return {status_, body_};
  }

  std::vector<http::Request> sent;

 private:
  long status_;
  std::string body_;
  bool fail_;
  std::mutex mu_;
};

// Installs a transport for the lifetime of the guard, then restores the platform default.
struct TransportGuard {
  explicit TransportGuard(std::shared_ptr<http::Transport> t) { http::set_default_transport(std::move(t)); }
  ~TransportGuard() { http::set_default_transport(nullptr); }
};

inline std::string header_value(const http::Request& req, const std::string& name) {
  for (const auto& [k, v] : req.headers)
    if (k == name) return v;
  return {};
}

inline bool has_header(const http::Request& req, const std::string& name) {
  for (const auto& [k, v] : req.headers)
    if (k == name) return true;
  return false;
}

}  // namespace abm::testing
