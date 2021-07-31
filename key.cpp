#include "key.h"

namespace xtea {

round_keys expand_key(const key &k) {
  round_keys expanded;

  for (uint32_t i = 0, sum = 0, next_sum = sum + delta; i < expanded.size();
       i += 2, sum = next_sum, next_sum += delta) {
    expanded[i] = sum + k[sum & 3];
    expanded[i + 1] = next_sum + k[(next_sum >> 11) & 3];
  }

  return expanded;
}

round_keys_v2 expand_key_v2(const key &k) {
  round_keys_v2 expanded;

  for (uint32_t i = 0, sum = 0, next_sum = sum + delta; i < expanded.size();
       ++i, sum = next_sum, next_sum += delta) {
    expanded[i] =
        std::make_pair(sum + k[sum & 3], next_sum + k[(next_sum >> 11) & 3]);
  }

  return expanded;
}

} // namespace xtea