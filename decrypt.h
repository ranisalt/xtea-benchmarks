#pragma once

#include "key.h"

namespace xtea {

void decrypt_reinterpret(uint8_t *data, std::size_t length, const key &key);

void decrypt_memcpy(uint8_t *data, std::size_t length, const key &key);

void decrypt_reinterpret_interleaved(uint8_t *data, std::size_t length,
                                     const key &key);

void decrypt_memcpy_interleaved(uint8_t *data, std::size_t length,
                                const key &key);

void decrypt_reinterpret_precomputed(uint8_t *data, std::size_t length,
                                     const round_keys &key);

void decrypt_memcpy_precomputed(uint8_t *data, std::size_t length,
                                const round_keys &key);

void decrypt_reinterpret_interleaved_precomputed(uint8_t *data,
                                                 std::size_t length,
                                                 const round_keys &key);

void decrypt_memcpy_interleaved_precomputed(uint8_t *data, std::size_t length,
                                            const round_keys &key);

void decrypt_reinterpret_keypair(uint8_t *data, std::size_t length,
                                 const round_keys_v2 &key);

void decrypt_memcpy_keypair(uint8_t *data, std::size_t length,
                            const round_keys_v2 &key);

void decrypt_reinterpret_interleaved_keypair(uint8_t *data, std::size_t length,
                                             const round_keys_v2 &key);

void decrypt_memcpy_interleaved_keypair(uint8_t *data, std::size_t length,
                                        const round_keys_v2 &key);

} // namespace xtea