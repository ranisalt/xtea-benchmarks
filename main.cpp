#include "decrypt.h"
#include "encrypt.h"
#include "key.h"
#include <benchmark/benchmark.h>
#include <chrono>
#include <memory>

#include <stdint.h>

namespace {

constexpr auto max_length = 24590u;

constexpr auto deadbeef =
    xtea::key{0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF, 0xDEADBEEF};

template <bool decrypt, class Fn, class Key>
static void bench(Fn fn, Key key, benchmark::State &state) {
  std::array<uint8_t, 8> m = {0xEF, 0xBE, 0xAD, 0xDE, 0xEF, 0xBE, 0xAD, 0xDE},
                         c = {0xB5, 0x8C, 0xF2, 0xFA, 0xE0, 0xC0, 0x40, 0x09};
  if (decrypt) {
    fn(c.data(), c.size(), key);
  } else {
    fn(m.data(), m.size(), key);
  }

  if (c != m) {
    state.SkipWithError("Failed to encrypt/decrypt");
  }

  using namespace std::chrono;

  auto length = state.range(0) & ~7u;

  for (auto _ : state) {
    auto p1 = std::make_unique<uint8_t[]>(length);
    std::generate_n(p1.get(), length, std::rand);

    auto start = high_resolution_clock::now();
    fn(p1.get(), length, key);
    auto end = high_resolution_clock::now();

    benchmark::DoNotOptimize(p1);

    auto elapsed = duration_cast<duration<double>>(end - start);
    state.SetIterationTime(elapsed.count());
  }

  state.SetBytesProcessed(length * state.iterations());
}

#define BM(x) BENCHMARK(x)->Range(8, max_length)->UseManualTime();

static void encrypt_reinterpret(benchmark::State &state) {
  bench<false>(xtea::encrypt_reinterpret, deadbeef, state);
}
BM(encrypt_reinterpret);

static void encrypt_memcpy(benchmark::State &state) {
  bench<false>(xtea::encrypt_memcpy, deadbeef, state);
}
BM(encrypt_memcpy);

static void encrypt_reinterpret_interleaved(benchmark::State &state) {
  bench<false>(xtea::encrypt_reinterpret_interleaved, deadbeef, state);
}
BM(encrypt_reinterpret_interleaved);

static void encrypt_memcpy_interleaved(benchmark::State &state) {
  bench<false>(xtea::encrypt_memcpy_interleaved, deadbeef, state);
}
BM(encrypt_memcpy_interleaved);

static void encrypt_reinterpret_precomputed(benchmark::State &state) {
  auto ek0 = xtea::expand_key(deadbeef);
  bench<false>(xtea::encrypt_reinterpret_precomputed, ek0, state);
}
BM(encrypt_reinterpret_precomputed);

static void encrypt_memcpy_precomputed(benchmark::State &state) {
  auto ek0 = xtea::expand_key(deadbeef);
  bench<false>(xtea::encrypt_memcpy_precomputed, ek0, state);
}
BM(encrypt_memcpy_precomputed);

static void
encrypt_reinterpret_interleaved_precomputed(benchmark::State &state) {
  auto ek0 = xtea::expand_key(deadbeef);
  bench<false>(xtea::encrypt_reinterpret_interleaved_precomputed, ek0, state);
}
BM(encrypt_reinterpret_interleaved_precomputed);

static void encrypt_memcpy_interleaved_precomputed(benchmark::State &state) {
  auto ek0 = xtea::expand_key(deadbeef);
  bench<false>(xtea::encrypt_memcpy_interleaved_precomputed, ek0, state);
}
BM(encrypt_memcpy_interleaved_precomputed);

static void encrypt_reinterpret_keypair(benchmark::State &state) {
  auto ek1 = xtea::expand_key_v2(deadbeef);
  bench<false>(xtea::encrypt_reinterpret_keypair, ek1, state);
}
BM(encrypt_reinterpret_keypair);

static void encrypt_memcpy_keypair(benchmark::State &state) {
  auto ek1 = xtea::expand_key_v2(deadbeef);
  bench<false>(xtea::encrypt_memcpy_keypair, ek1, state);
}
BM(encrypt_memcpy_keypair);

static void encrypt_reinterpret_interleaved_keypair(benchmark::State &state) {
  auto ek1 = xtea::expand_key_v2(deadbeef);
  bench<false>(xtea::encrypt_reinterpret_interleaved_keypair, ek1, state);
}
BM(encrypt_reinterpret_interleaved_keypair);

static void encrypt_memcpy_interleaved_keypair(benchmark::State &state) {
  auto ek1 = xtea::expand_key_v2(deadbeef);
  bench<false>(xtea::encrypt_memcpy_interleaved_keypair, ek1, state);
}
BM(encrypt_memcpy_interleaved_keypair);

static void decrypt_reinterpret(benchmark::State &state) {
  bench<true>(xtea::decrypt_reinterpret, deadbeef, state);
}
BM(decrypt_reinterpret);

static void decrypt_memcpy(benchmark::State &state) {
  bench<true>(xtea::decrypt_memcpy, deadbeef, state);
}
BM(decrypt_memcpy);

static void decrypt_reinterpret_interleaved(benchmark::State &state) {
  bench<true>(xtea::decrypt_reinterpret_interleaved, deadbeef, state);
}
BM(decrypt_reinterpret_interleaved);

static void decrypt_memcpy_interleaved(benchmark::State &state) {
  bench<true>(xtea::decrypt_memcpy_interleaved, deadbeef, state);
}
BM(decrypt_memcpy_interleaved);

static void decrypt_reinterpret_precomputed(benchmark::State &state) {
  auto ek0 = xtea::expand_key(deadbeef);
  bench<true>(xtea::decrypt_reinterpret_precomputed, ek0, state);
}
BM(decrypt_reinterpret_precomputed);

static void decrypt_memcpy_precomputed(benchmark::State &state) {
  auto ek0 = xtea::expand_key(deadbeef);
  bench<true>(xtea::decrypt_memcpy_precomputed, ek0, state);
}
BM(decrypt_memcpy_precomputed);

static void
decrypt_reinterpret_interleaved_precomputed(benchmark::State &state) {
  auto ek0 = xtea::expand_key(deadbeef);
  bench<true>(xtea::decrypt_reinterpret_interleaved_precomputed, ek0, state);
}
BM(decrypt_reinterpret_interleaved_precomputed);

static void decrypt_memcpy_interleaved_precomputed(benchmark::State &state) {
  auto ek0 = xtea::expand_key(deadbeef);
  bench<true>(xtea::decrypt_memcpy_interleaved_precomputed, ek0, state);
}
BM(decrypt_memcpy_interleaved_precomputed);

static void decrypt_reinterpret_keypair(benchmark::State &state) {
  auto ek1 = xtea::expand_key_v2(deadbeef);
  bench<true>(xtea::decrypt_reinterpret_keypair, ek1, state);
}
BM(decrypt_reinterpret_keypair);

static void decrypt_memcpy_keypair(benchmark::State &state) {
  auto ek1 = xtea::expand_key_v2(deadbeef);
  bench<true>(xtea::decrypt_memcpy_keypair, ek1, state);
}
BM(decrypt_memcpy_keypair);

static void decrypt_reinterpret_interleaved_keypair(benchmark::State &state) {
  auto ek1 = xtea::expand_key_v2(deadbeef);
  bench<true>(xtea::decrypt_reinterpret_interleaved_keypair, ek1, state);
}
BM(decrypt_reinterpret_interleaved_keypair);

static void decrypt_memcpy_interleaved_keypair(benchmark::State &state) {
  auto ek1 = xtea::expand_key_v2(deadbeef);
  bench<true>(xtea::decrypt_memcpy_interleaved_keypair, ek1, state);
}
BM(decrypt_memcpy_interleaved_keypair);

} // namespace

BENCHMARK_MAIN();