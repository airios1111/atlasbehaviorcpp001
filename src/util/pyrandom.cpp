#include "abm/util/pyrandom.hpp"

#include <stdexcept>

namespace abm::py {
namespace {
constexpr int N = 624;
constexpr int M = 397;
constexpr std::uint32_t MATRIX_A = 0x9908b0dfU;
constexpr std::uint32_t UPPER_MASK = 0x80000000U;
constexpr std::uint32_t LOWER_MASK = 0x7fffffffU;
}  // namespace

Random::Random(std::uint64_t seed) {
  // random_seed(): the absolute value of an int seed split into 32-bit little-endian words
  std::vector<std::uint32_t> key;
  do {
    key.push_back(static_cast<std::uint32_t>(seed & 0xffffffffU));
    seed >>= 32;
  } while (seed);
  init_by_array(key);
}

void Random::init_genrand(std::uint32_t s) {
  mt_[0] = s;
  for (mti_ = 1; mti_ < N; ++mti_) {
    mt_[mti_] = 1812433253U * (mt_[mti_ - 1] ^ (mt_[mti_ - 1] >> 30)) + static_cast<std::uint32_t>(mti_);
  }
}

void Random::init_by_array(const std::vector<std::uint32_t>& key) {
  init_genrand(19650218U);
  std::size_t i = 1, j = 0;
  const std::size_t len = key.size();
  for (std::size_t k = (N > len ? N : len); k; --k) {
    mt_[i] = (mt_[i] ^ ((mt_[i - 1] ^ (mt_[i - 1] >> 30)) * 1664525U)) + key[j] + static_cast<std::uint32_t>(j);
    ++i;
    ++j;
    if (i >= N) {
      mt_[0] = mt_[N - 1];
      i = 1;
    }
    if (j >= len) j = 0;
  }
  for (std::size_t k = N - 1; k; --k) {
    mt_[i] = (mt_[i] ^ ((mt_[i - 1] ^ (mt_[i - 1] >> 30)) * 1566083941U)) - static_cast<std::uint32_t>(i);
    ++i;
    if (i >= N) {
      mt_[0] = mt_[N - 1];
      i = 1;
    }
  }
  mt_[0] = 0x80000000U;
}

std::uint32_t Random::genrand_uint32() {
  static const std::uint32_t mag01[2] = {0x0U, MATRIX_A};
  std::uint32_t y;
  if (mti_ >= N) {
    int kk;
    for (kk = 0; kk < N - M; ++kk) {
      y = (mt_[kk] & UPPER_MASK) | (mt_[kk + 1] & LOWER_MASK);
      mt_[kk] = mt_[kk + M] ^ (y >> 1) ^ mag01[y & 0x1U];
    }
    for (; kk < N - 1; ++kk) {
      y = (mt_[kk] & UPPER_MASK) | (mt_[kk + 1] & LOWER_MASK);
      mt_[kk] = mt_[kk + (M - N)] ^ (y >> 1) ^ mag01[y & 0x1U];
    }
    y = (mt_[N - 1] & UPPER_MASK) | (mt_[0] & LOWER_MASK);
    mt_[N - 1] = mt_[M - 1] ^ (y >> 1) ^ mag01[y & 0x1U];
    mti_ = 0;
  }
  y = mt_[mti_++];
  y ^= (y >> 11);
  y ^= (y << 7) & 0x9d2c5680U;
  y ^= (y << 15) & 0xefc60000U;
  y ^= (y >> 18);
  return y;
}

double Random::random() {
  const std::uint32_t a = genrand_uint32() >> 5, b = genrand_uint32() >> 6;
  return (a * 67108864.0 + b) * (1.0 / 9007199254740992.0);
}

double Random::uniform(double a, double b) { return a + (b - a) * random(); }

std::uint32_t Random::getrandbits(int k) {
  if (k <= 0 || k > 32) throw std::invalid_argument("getrandbits supports 1..32 bits");
  return genrand_uint32() >> (32 - k);
}

std::uint64_t Random::randbelow(std::uint64_t n) {
  int k = 0;
  for (std::uint64_t x = n; x; x >>= 1) ++k;  // n.bit_length()
  if (k > 32) throw std::invalid_argument("randbelow range too large");
  std::uint64_t r = getrandbits(k);
  while (r >= n) r = getrandbits(k);
  return r;
}

std::int64_t Random::randint(std::int64_t a, std::int64_t b) {
  if (b < a) throw std::invalid_argument("empty range for randint");
  return a + static_cast<std::int64_t>(randbelow(static_cast<std::uint64_t>(b - a + 1)));
}

}  // namespace abm::py
