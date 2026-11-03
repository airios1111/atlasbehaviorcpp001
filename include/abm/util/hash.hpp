// SHA-1 / SHA-256 digests and RFC 4122 name-based (v5) UUIDs.
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace abm::hash {

std::array<std::uint8_t, 20> sha1(std::string_view data);
std::array<std::uint8_t, 32> sha256(std::string_view data);
std::string sha256_hex(std::string_view data);

// uuid.uuid5(uuid.UUID(namespace_uuid), name) -> canonical lowercase string
std::string uuid5(std::string_view namespace_uuid, std::string_view name);

}  // namespace abm::hash
