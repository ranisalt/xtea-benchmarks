#include "encrypt.h"
#include <cstring> // memcpy
#include <memory>  // make_unique

namespace xtea {

void encrypt_reinterpret(uint8_t *data, std::size_t length, const key &k) {
  for (auto j = 0u; j < length; j += 8) {
    uint32_t &v0 = *reinterpret_cast<uint32_t *>(data + j),
             &v1 = *reinterpret_cast<uint32_t *>(data + j + 4);

    for (uint32_t i = 0u, sum = 0u; i < 32u; ++i) {
      v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]);
      sum += delta;
      v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[(sum >> 11) & 3]);
    }
  }
}

void encrypt_memcpy(uint8_t *data, std::size_t length, const key &k) {
  for (auto j = 0u; j < length; j += 8) {
    uint32_t v0, v1;
    std::memcpy(&v0, data + j, 4);
    std::memcpy(&v1, data + j + 4, 4);

    for (uint32_t i = 0u, sum = 0u; i < 32u; ++i) {
      v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]);
      sum += delta;
      v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[(sum >> 11) & 3]);
    }

    std::memcpy(data + j, &v0, 4);
    std::memcpy(data + j + 4, &v1, 4);
  }
}

void encrypt_reinterpret_interleaved(uint8_t *data, std::size_t length,
                                     const key &k) {
  for (uint32_t i = 0u, sum = 0u; i < 32u; ++i) {
    for (auto j = 0u; j < length; j += 8) {
      uint32_t &v0 = *reinterpret_cast<uint32_t *>(data + j),
               &v1 = *reinterpret_cast<uint32_t *>(data + j + 4);

      v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]);
      sum += delta;
      v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[(sum >> 11) & 3]);
    }
  }
}

void encrypt_memcpy_interleaved(uint8_t *data, std::size_t length,
                                const key &k) {
  for (uint32_t i = 0u, sum = 0u; i < 32u; ++i) {
    for (auto j = 0u; j < length; j += 8) {
      uint32_t v0, v1;
      std::memcpy(&v0, data + j, 4);
      std::memcpy(&v1, data + j + 4, 4);

      v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]);
      sum += delta;
      v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[(sum >> 11) & 3]);

      std::memcpy(data + j, &v0, 4);
      std::memcpy(data + j + 4, &v1, 4);
    }
  }
}

void encrypt_reinterpret_precomputed(uint8_t *data, std::size_t length,
                                     const round_keys &k) {
  for (auto j = 0u; j < length; j += 8) {
    uint32_t &v0 = *reinterpret_cast<uint32_t *>(data + j),
             &v1 = *reinterpret_cast<uint32_t *>(data + j + 4);

    for (auto i = 0u; i < k.size(); i += 2u) {
      v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ k[i];
      v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ k[i + 1];
    }
  }
}

void encrypt_memcpy_precomputed(uint8_t *data, std::size_t length,
                                const round_keys &k) {
  for (auto j = 0u; j < length; j += 8) {
    uint32_t v0, v1;
    std::memcpy(&v0, data + j, 4);
    std::memcpy(&v1, data + j + 4, 4);

    for (auto i = 0u; i < k.size(); i += 2u) {
      v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ k[i];
      v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ k[i + 1];
    }

    std::memcpy(data + j, &v0, 4);
    std::memcpy(data + j + 4, &v1, 4);
  }
}

void encrypt_reinterpret_interleaved_precomputed(uint8_t *data,
                                                 std::size_t length,
                                                 const round_keys &k) {
  for (auto i = 0u; i < k.size(); i += 2u) {
    for (auto j = 0u; j < length; j += 8) {
      uint32_t &v0 = *reinterpret_cast<uint32_t *>(data + j),
               &v1 = *reinterpret_cast<uint32_t *>(data + j + 4);

      v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ k[i];
      v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ k[i + 1];
    }
  }
}

void encrypt_memcpy_interleaved_precomputed(uint8_t *data, std::size_t length,
                                            const round_keys &k) {
  for (auto i = 0u; i < k.size(); i += 2u) {
    for (auto j = 0u; j < length; j += 8) {
      uint32_t v0, v1;
      std::memcpy(&v0, data + j, 4);
      std::memcpy(&v1, data + j + 4, 4);

      v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ k[i];
      v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ k[i + 1];

      std::memcpy(data + j, &v0, 4);
      std::memcpy(data + j + 4, &v1, 4);
    }
  }
}

void encrypt_reinterpret_keypair(uint8_t *data, std::size_t length,
                                 const round_keys_v2 &k) {
  for (auto j = 0u; j < length; j += 8) {
    uint32_t &v0 = *reinterpret_cast<uint32_t *>(data + j),
             &v1 = *reinterpret_cast<uint32_t *>(data + j + 4);

    for (auto [k0, k1] : k) {
      v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ k0;
      v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ k1;
    }
  }
}

void encrypt_memcpy_keypair(uint8_t *data, std::size_t length,
                            const round_keys_v2 &k) {
  for (auto j = 0u; j < length; j += 8) {
    uint32_t v0, v1;
    std::memcpy(&v0, data + j, 4);
    std::memcpy(&v1, data + j + 4, 4);

    for (auto [k0, k1] : k) {
      v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ k0;
      v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ k1;
    }

    std::memcpy(data + j, &v0, 4);
    std::memcpy(data + j + 4, &v1, 4);
  }
}

void encrypt_reinterpret_interleaved_keypair(uint8_t *data, std::size_t length,
                                             const round_keys_v2 &k) {
  for (auto [k0, k1] : k) {
    for (auto j = 0u; j < length; j += 8) {
      uint32_t &v0 = *reinterpret_cast<uint32_t *>(data + j),
               &v1 = *reinterpret_cast<uint32_t *>(data + j + 4);

      v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ k0;
      v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ k1;
    }
  }
}

void encrypt_memcpy_interleaved_keypair(uint8_t *data, std::size_t length,
                                        const round_keys_v2 &k) {
  for (auto [k0, k1] : k) {
    for (auto j = 0u; j < length; j += 8) {
      uint32_t v0, v1;
      std::memcpy(&v0, data + j, 4);
      std::memcpy(&v1, data + j + 4, 4);

      v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ k0;
      v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ k1;

      std::memcpy(data + j, &v0, 4);
      std::memcpy(data + j + 4, &v1, 4);
    }
  }
}

} // namespace xtea