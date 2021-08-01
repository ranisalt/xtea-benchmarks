#include "encrypt.h"
#include <cstring> // memcpy
#include <memory>  // make_unique

namespace xtea {

void encrypt(uint8_t *data, std::size_t length, const key &k) {
  for (auto it = data, last = data + length; it < last; it += 8) {
    uint32_t v0, v1;
    std::memcpy(&v0, it, 4);
    std::memcpy(&v1, it + 4, 4);

    for (uint32_t i = 0u, sum = 0u; i < 32u; ++i) {
      v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]);
      sum += delta;
      v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[(sum >> 11) & 3]);
    }

    std::memcpy(it, &v0, 4);
    std::memcpy(it + 4, &v1, 4);
  }
}

void encrypt_interleaved(uint8_t *data, std::size_t length, const key &k) {
  for (uint32_t i = 0u, sum = 0u; i < 32u; ++i) {
    for (auto it = data, last = data + length; it < last; it += 8) {
      uint32_t v0, v1;
      std::memcpy(&v0, it, 4);
      std::memcpy(&v1, it + 4, 4);

      v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]);
      sum += delta;
      v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[(sum >> 11) & 3]);

      std::memcpy(it, &v0, 4);
      std::memcpy(it + 4, &v1, 4);
    }
  }
}

void encrypt_precomputed(uint8_t *data, std::size_t length,
                         const round_keys &k) {
  for (auto it = data, last = data + length; it < last; it += 8) {
    uint32_t v0, v1;
    std::memcpy(&v0, it, 4);
    std::memcpy(&v1, it + 4, 4);

    for (auto i = 0u; i < k.size(); i += 2u) {
      v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ k[i];
      v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ k[i + 1];
    }

    std::memcpy(it, &v0, 4);
    std::memcpy(it + 4, &v1, 4);
  }
}

void encrypt_tfs(uint8_t *data, std::size_t length, const round_keys &k) {
  for (auto i = 0u; i < k.size(); i += 2u) {
    for (auto it = data, last = data + length; it < last; it += 8) {
      uint32_t v0 = it[0] | it[1] << 8u | it[2] << 16u | it[3] << 24u,
               v1 = it[4] | it[5] << 8u | it[6] << 16u | it[7] << 24u;

      v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ k[i];
      v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ k[i + 1];

      it[0] = static_cast<uint8_t>(v0);
      it[1] = static_cast<uint8_t>(v0 >> 8u);
      it[2] = static_cast<uint8_t>(v0 >> 16u);
      it[3] = static_cast<uint8_t>(v0 >> 24u);
      it[4] = static_cast<uint8_t>(v1);
      it[5] = static_cast<uint8_t>(v1 >> 8u);
      it[6] = static_cast<uint8_t>(v1 >> 16u);
      it[7] = static_cast<uint8_t>(v1 >> 24u);
    }
  }
}

void encrypt_interleaved_precomputed(uint8_t *data, std::size_t length,
                                     const round_keys &k) {
  for (auto i = 0u; i < k.size(); i += 2u) {
    for (auto it = data, last = data + length; it < last; it += 8) {
      uint32_t v0, v1;
      std::memcpy(&v0, it, 4);
      std::memcpy(&v1, it + 4, 4);

      v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ k[i];
      v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ k[i + 1];

      std::memcpy(it, &v0, 4);
      std::memcpy(it + 4, &v1, 4);
    }
  }
}

void encrypt_keypair(uint8_t *data, std::size_t length,
                     const round_keys_v2 &k) {
  for (auto it = data, last = data + length; it < last; it += 8) {
    uint32_t v0, v1;
    std::memcpy(&v0, it, 4);
    std::memcpy(&v1, it + 4, 4);

    for (auto [k0, k1] : k) {
      v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ k0;
      v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ k1;
    }

    std::memcpy(it, &v0, 4);
    std::memcpy(it + 4, &v1, 4);
  }
}

void encrypt_interleaved_keypair(uint8_t *data, std::size_t length,
                                 const round_keys_v2 &k) {
  for (auto [k0, k1] : k) {
    for (auto it = data, last = data + length; it < last; it += 8) {
      uint32_t v0, v1;
      std::memcpy(&v0, it, 4);
      std::memcpy(&v1, it + 4, 4);

      v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ k0;
      v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ k1;

      std::memcpy(it, &v0, 4);
      std::memcpy(it + 4, &v1, 4);
    }
  }
}

} // namespace xtea