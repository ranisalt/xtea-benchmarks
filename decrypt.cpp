#include "decrypt.h"
#include <cstring> // memcpy
#include <range/v3/view/reverse.hpp>

namespace xtea {

void decrypt_reinterpret(uint8_t *data, std::size_t length, const key &k) {
  for (auto j = 0u; j < length; j += 8) {
    uint32_t &v0 = *reinterpret_cast<uint32_t *>(data + j),
             &v1 = *reinterpret_cast<uint32_t *>(data + j + 4);

    for (uint32_t i = 0u, sum = delta * 32u; i < 32u; ++i) {
      v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[(sum >> 11) & 3]);
      sum -= delta;
      v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]);
    }
  }
}

void decrypt_memcpy(uint8_t *data, std::size_t length, const key &k) {
  for (auto j = 0u; j < length; j += 8) {
    uint32_t v0, v1;
    std::memcpy(&v0, data + j, 4);
    std::memcpy(&v1, data + j + 4, 4);

    for (uint32_t i = 0u, sum = delta * 32u; i < 32u; ++i) {
      v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[(sum >> 11) & 3]);
      sum -= delta;
      v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]);
    }

    std::memcpy(data + j, &v0, 4);
    std::memcpy(data + j + 4, &v1, 4);
  }
}

void decrypt_reinterpret_interleaved(uint8_t *data, std::size_t length,
                                     const key &k) {
  for (uint32_t i = 0u, sum = delta * 32u; i < 32u; ++i) {
    for (auto j = 0u; j < length; j += 8) {
      uint32_t &v0 = *reinterpret_cast<uint32_t *>(data + j),
               &v1 = *reinterpret_cast<uint32_t *>(data + j + 4);

      v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[(sum >> 11) & 3]);
      sum -= delta;
      v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]);
    }
  }
}

void decrypt_memcpy_interleaved(uint8_t *data, std::size_t length,
                                const key &k) {
  for (uint32_t i = 0u, sum = delta * 32u; i < 32u; ++i) {
    for (auto j = 0u; j < length; j += 8) {
      uint32_t v0, v1;
      std::memcpy(&v0, data + j, 4);
      std::memcpy(&v1, data + j + 4, 4);

      v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[(sum >> 11) & 3]);
      sum -= delta;
      v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]);

      std::memcpy(data + j, &v0, 4);
      std::memcpy(data + j + 4, &v1, 4);
    }
  }
}

void decrypt_reinterpret_precomputed(uint8_t *data, std::size_t length,
                                     const round_keys &k) {
  for (auto j = 0u; j < length; j += 8) {
    uint32_t &v0 = *reinterpret_cast<uint32_t *>(data + j),
             &v1 = *reinterpret_cast<uint32_t *>(data + j + 4);

    for (auto i = k.size(); i > 0u; i -= 2u) {
      v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ k[i - 1];
      v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ k[i - 2];
    }
  }
}

void decrypt_memcpy_precomputed(uint8_t *data, std::size_t length,
                                const round_keys &k) {
  for (auto j = 0u; j < length; j += 8) {
    uint32_t v0, v1;
    std::memcpy(&v0, data + j, 4);
    std::memcpy(&v1, data + j + 4, 4);

    for (auto i = k.size(); i > 0u; i -= 2u) {
      v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ k[i - 1];
      v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ k[i - 2];
    }

    std::memcpy(data + j, &v0, 4);
    std::memcpy(data + j + 4, &v1, 4);
  }
}

void decrypt_reinterpret_interleaved_precomputed(uint8_t *data,
                                                 std::size_t length,
                                                 const round_keys &k) {
  for (auto i = k.size(); i > 0u; i -= 2u) {
    for (auto j = 0u; j < length; j += 8) {
      uint32_t &v0 = *reinterpret_cast<uint32_t *>(data + j),
               &v1 = *reinterpret_cast<uint32_t *>(data + j + 4);

      v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ k[i - 1];
      v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ k[i - 2];
    }
  }
}

void decrypt_memcpy_interleaved_precomputed(uint8_t *data, std::size_t length,
                                            const round_keys &k) {
  for (auto i = k.size(); i > 0u; i -= 2u) {
    for (auto j = 0u; j < length; j += 8) {
      uint32_t v0, v1;
      std::memcpy(&v0, data + j, 4);
      std::memcpy(&v1, data + j + 4, 4);

      v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ k[i - 1];
      v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ k[i - 2];

      std::memcpy(data + j, &v0, 4);
      std::memcpy(data + j + 4, &v1, 4);
    }
  }
}

void decrypt_reinterpret_keypair(uint8_t *data, std::size_t length,
                                 const round_keys_v2 &k) {
  for (auto j = 0u; j < length; j += 8) {
    uint32_t &v0 = *reinterpret_cast<uint32_t *>(data + j),
             &v1 = *reinterpret_cast<uint32_t *>(data + j + 4);

    for (auto [k0, k1] : k | ranges::views::reverse) {
      v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ k1;
      v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ k0;
    }
  }
}

void decrypt_memcpy_keypair(uint8_t *data, std::size_t length,
                            const round_keys_v2 &k) {
  for (auto j = 0u; j < length; j += 8) {
    uint32_t v0, v1;
    std::memcpy(&v0, data + j, 4);
    std::memcpy(&v1, data + j + 4, 4);

    for (auto [k0, k1] : k | ranges::views::reverse) {
      v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ k1;
      v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ k0;
    }

    std::memcpy(data + j, &v0, 4);
    std::memcpy(data + j + 4, &v1, 4);
  }
}

void decrypt_reinterpret_interleaved_keypair(uint8_t *data, std::size_t length,
                                             const round_keys_v2 &k) {
  for (auto [k0, k1] : k | ranges::views::reverse) {
    for (auto j = 0u; j < length; j += 8) {
      uint32_t &v0 = *reinterpret_cast<uint32_t *>(data + j),
               &v1 = *reinterpret_cast<uint32_t *>(data + j + 4);

      v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ k1;
      v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ k0;
    }
  }
}

void decrypt_memcpy_interleaved_keypair(uint8_t *data, std::size_t length,
                                        const round_keys_v2 &k) {
  for (auto [k0, k1] : k | ranges::views::reverse) {
    for (auto j = 0u; j < length; j += 8) {
      uint32_t v0, v1;
      std::memcpy(&v0, data + j, 4);
      std::memcpy(&v1, data + j + 4, 4);

      v1 -= ((v0 << 4 ^ v0 >> 5) + v0) ^ k1;
      v0 -= ((v1 << 4 ^ v1 >> 5) + v1) ^ k0;

      std::memcpy(data + j, &v0, 4);
      std::memcpy(data + j + 4, &v1, 4);
    }
  }
}

} // namespace xtea