#pragma once

#include "key.h"

namespace xtea {

void encrypt(uint8_t *data, std::size_t length, const key &key);

void encrypt_interleaved(uint8_t *data, std::size_t length, const key &key);

void encrypt_precomputed(uint8_t *data, std::size_t length,
                         const round_keys &key);

void encrypt_tfs(uint8_t *data, std::size_t length, const round_keys &k);

void encrypt_interleaved_precomputed(uint8_t *data, std::size_t length,
                                     const round_keys &key);

void encrypt_keypair(uint8_t *data, std::size_t length,
                     const round_keys_v2 &key);

void encrypt_interleaved_keypair(uint8_t *data, std::size_t length,
                                 const round_keys_v2 &key);

} // namespace xtea