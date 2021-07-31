#pragma once

#include <array>
#include <stdint.h>

namespace xtea {

using key = std::array<uint32_t, 4>;
using round_keys = std::array<uint32_t, 64>;
using round_keys_v2 = std::array<std::pair<uint32_t, uint32_t>, 32>;

constexpr uint32_t delta = 0x9e3779b9;

round_keys expand_key(const key &k);
round_keys_v2 expand_key_v2(const key &k);

} // namespace xtea