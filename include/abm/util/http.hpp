// Minimal HTTPS client used by the webhook / XSOAR executors and `abm atlas-sync`.
// The transport is injectable so tests can capture requests without network access.
#pragma once

#include <memory>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace abm::http {

using Headers = std::vector<std::pair<std::string, std::string>>;

struct Request {
  std::string method;  // GET | POST
  std::string url;
  Headers headers;
  std::string body;
  int timeout_seconds = 30;
};

struct Response {
  long status = 0;
  std::string body;
};

// Raised when no HTTP response was received (DNS, TLS, connect, timeout...). `kind` mirrors the
// Python exception class name reported in action statuses, e.g. "URLError" or "TimeoutError".
class TransportError : public std::runtime_error {
 public:
  TransportError(std::string kind, const std::string& message)
      : std::runtime_error(message), kind_(std::move(kind)) {}
  const std::string& kind() const { return kind_; }

 private:
  std::string kind_;
};

class Transport {
 public:
  virtual ~Transport() = default;
  virtual Response send(const Request& req) = 0;
};

// Process-wide transport (WinHTTP on Windows, libcurl elsewhere). Tests may replace it.
std::shared_ptr<Transport> default_transport();
void set_default_transport(std::shared_ptr<Transport> t);
std::shared_ptr<Transport> platform_transport();

}  // namespace abm::http
