#include "abm/util/http.hpp"

#include <mutex>

#if defined(ABM_HTTP_WINHTTP)
#include <windows.h>
#include <winhttp.h>
#elif defined(ABM_HTTP_CURL)
#include <curl/curl.h>
#endif

namespace abm::http {
namespace {

std::mutex g_mu;
std::shared_ptr<Transport> g_transport;

#if defined(ABM_HTTP_WINHTTP)

std::wstring widen(const std::string& s) {
  if (s.empty()) return {};
  int n = MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), nullptr, 0);
  std::wstring w(static_cast<std::size_t>(n), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()), w.data(), n);
  return w;
}

struct Handle {
  HINTERNET h = nullptr;
  explicit Handle(HINTERNET x) : h(x) {}
  ~Handle() {
    if (h) WinHttpCloseHandle(h);
  }
  Handle(const Handle&) = delete;
  Handle& operator=(const Handle&) = delete;
};

[[noreturn]] void fail(const char* what) {
  DWORD err = GetLastError();
  std::string kind = err == ERROR_WINHTTP_TIMEOUT ? "TimeoutError" : "URLError";
  throw TransportError(kind, std::string(what) + " failed (WinHTTP error " + std::to_string(err) + ")");
}

class WinHttpTransport : public Transport {
 public:
  Response send(const Request& req) override {
    std::wstring url = widen(req.url);
    URL_COMPONENTS uc{};
    uc.dwStructSize = sizeof uc;
    wchar_t host[256], path[4096];
    uc.lpszHostName = host;
    uc.dwHostNameLength = 256;
    uc.lpszUrlPath = path;
    uc.dwUrlPathLength = 4096;
    wchar_t extra[4096];
    uc.lpszExtraInfo = extra;
    uc.dwExtraInfoLength = 4096;
    if (!WinHttpCrackUrl(url.c_str(), 0, 0, &uc)) fail("WinHttpCrackUrl");
    std::wstring object = std::wstring(path, uc.dwUrlPathLength) + std::wstring(extra, uc.dwExtraInfoLength);
    if (object.empty()) object = L"/";

    const std::wstring agent = widen(std::string("atlas-behavior-map/") + ABM_VERSION);
    Handle session(WinHttpOpen(agent.c_str(), WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0));
    if (!session.h) fail("WinHttpOpen");
    const int ms = req.timeout_seconds * 1000;
    WinHttpSetTimeouts(session.h, ms, ms, ms, ms);
    Handle conn(WinHttpConnect(session.h, std::wstring(host, uc.dwHostNameLength).c_str(), uc.nPort, 0));
    if (!conn.h) fail("WinHttpConnect");
    DWORD flags = uc.nScheme == INTERNET_SCHEME_HTTPS ? WINHTTP_FLAG_SECURE : 0;
    Handle request(WinHttpOpenRequest(conn.h, widen(req.method).c_str(), object.c_str(), nullptr,
                                      WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, flags));
    if (!request.h) fail("WinHttpOpenRequest");
    std::wstring headers;
    for (const auto& [k, v] : req.headers) headers += widen(k) + L": " + widen(v) + L"\r\n";
    if (!WinHttpSendRequest(request.h, headers.empty() ? WINHTTP_NO_ADDITIONAL_HEADERS : headers.c_str(),
                            headers.empty() ? 0 : static_cast<DWORD>(-1L),
                            req.body.empty() ? WINHTTP_NO_REQUEST_DATA : const_cast<char*>(req.body.data()),
                            static_cast<DWORD>(req.body.size()), static_cast<DWORD>(req.body.size()), 0))
      fail("WinHttpSendRequest");
    if (!WinHttpReceiveResponse(request.h, nullptr)) fail("WinHttpReceiveResponse");
    DWORD status = 0, size = sizeof status;
    WinHttpQueryHeaders(request.h, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        WINHTTP_HEADER_NAME_BY_INDEX, &status, &size, WINHTTP_NO_HEADER_INDEX);
    Response resp;
    resp.status = static_cast<long>(status);
    for (;;) {
      DWORD avail = 0;
      if (!WinHttpQueryDataAvailable(request.h, &avail)) fail("WinHttpQueryDataAvailable");
      if (avail == 0) break;
      std::string chunk(avail, '\0');
      DWORD read = 0;
      if (!WinHttpReadData(request.h, chunk.data(), avail, &read)) fail("WinHttpReadData");
      resp.body.append(chunk.data(), read);
    }
    return resp;
  }
};

#elif defined(ABM_HTTP_CURL)

std::size_t on_body(char* ptr, std::size_t size, std::size_t n, void* user) {
  static_cast<std::string*>(user)->append(ptr, size * n);
  return size * n;
}

class CurlTransport : public Transport {
 public:
  CurlTransport() { curl_global_init(CURL_GLOBAL_DEFAULT); }
  Response send(const Request& req) override {
    CURL* c = curl_easy_init();
    if (!c) throw TransportError("URLError", "curl_easy_init failed");
    Response resp;
    curl_slist* hdrs = nullptr;
    for (const auto& [k, v] : req.headers) hdrs = curl_slist_append(hdrs, (k + ": " + v).c_str());
    curl_easy_setopt(c, CURLOPT_URL, req.url.c_str());
    curl_easy_setopt(c, CURLOPT_HTTPHEADER, hdrs);
    curl_easy_setopt(c, CURLOPT_TIMEOUT, static_cast<long>(req.timeout_seconds));
    curl_easy_setopt(c, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(c, CURLOPT_USERAGENT, "atlas-behavior-map/" ABM_VERSION);
    curl_easy_setopt(c, CURLOPT_WRITEFUNCTION, on_body);
    curl_easy_setopt(c, CURLOPT_WRITEDATA, &resp.body);
    if (req.method == "POST") {
      curl_easy_setopt(c, CURLOPT_POST, 1L);
      curl_easy_setopt(c, CURLOPT_POSTFIELDS, req.body.data());
      curl_easy_setopt(c, CURLOPT_POSTFIELDSIZE, static_cast<long>(req.body.size()));
    }
    CURLcode rc = curl_easy_perform(c);
    if (rc == CURLE_OK) curl_easy_getinfo(c, CURLINFO_RESPONSE_CODE, &resp.status);
    curl_slist_free_all(hdrs);
    curl_easy_cleanup(c);
    if (rc != CURLE_OK) {
      throw TransportError(rc == CURLE_OPERATION_TIMEDOUT ? "TimeoutError" : "URLError",
                           curl_easy_strerror(rc));
    }
    return resp;
  }
};

#else

class NoTransport : public Transport {
 public:
  Response send(const Request&) override {
    throw TransportError("URLError", "HTTP support was not compiled in (libcurl not found)");
  }
};

#endif

}  // namespace

std::shared_ptr<Transport> platform_transport() {
#if defined(ABM_HTTP_WINHTTP)
  return std::make_shared<WinHttpTransport>();
#elif defined(ABM_HTTP_CURL)
  return std::make_shared<CurlTransport>();
#else
  return std::make_shared<NoTransport>();
#endif
}

std::shared_ptr<Transport> default_transport() {
  std::lock_guard<std::mutex> lock(g_mu);
  if (!g_transport) g_transport = platform_transport();
  return g_transport;
}

void set_default_transport(std::shared_ptr<Transport> t) {
  std::lock_guard<std::mutex> lock(g_mu);
  g_transport = std::move(t);
}

}  // namespace abm::http
