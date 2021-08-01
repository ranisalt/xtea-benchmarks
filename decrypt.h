#pragma once

#include "key.h"

namespace xtea {

void decrypt(uint8_t *data, std::size_t length, const key &key);

void decrypt_interleaved(uint8_t *data, std::size_t length, const key &key);

void decrypt_precomputed(uint8_t *data, std::size_t length,
                         const round_keys &key);

void decrypt_interleaved_precomputed(uint8_t *data, std::size_t length,
                                     const round_keys &key);

void decrypt_keypair(uint8_t *data, std::size_t length,
                     const round_keys_v2 &key);

void decrypt_interleaved_keypair(uint8_t *data, std::size_t length,
                                 const round_keys_v2 &key);

} // namespace xtea