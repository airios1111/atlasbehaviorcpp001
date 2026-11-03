// Bit-exact port of CPython's random.Random (MT19937) for the subset used by the fixture
// generators, so `random.Random(seed)` sequences — and therefore generated fixtures — match.
#pragma once

#include <cstdint>
#include <vector>

namespace abm::py {

class Random {
 public:
  explicit Random(std::uint64_t seed);

  double random();                                  // [0.0, 1.0) with 53-bit precision
  double uniform(double a, double b);               // a + (b - a) * random()
  std::int64_t randint(std::int64_t a, std::int64_t b);  // inclusive
  std::uint32_t getrandbits(int k);                 // 1 <= k <= 32

 private:
  void init_genrand(std::uint32_t s);
  void init_by_array(const std::vector<std::uint32_t>& key);
  std::uint32_t genrand_uint32();
  std::uint64_t randbelow(std::uint64_t n);

  std::uint32_t mt_[624];
  int mti_ = 625;
};

}  // namespace abm::py
