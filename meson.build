project('xtea-benchmarks', 'cpp',
    license: ['unlicense'],
    default_options: ['b_lto=true', 'cpp_std=c++17']
)

headers = files('decrypt.h', 'encrypt.h', 'key.h')
sources = files('decrypt.cpp', 'encrypt.cpp', 'key.cpp', 'main.cpp')

benchmark_dep = dependency('benchmark', fallback: ['google-benchmark'])

run_target('format',
    command: ['clang-format', '-i', '-style=llvm', headers, sources]
)

bench = executable('bench', sources,
    cpp_args: ['-march=native', '-fdata-sections', '-ffunction-sections', '-fno-plt', '-fvisibility=hidden', '-Wconversion', '-Wextra', '-Wpedantic', '-Wshadow'],
    link_args: '-Wl,-O4,--sort-common,-z,relro,-z,now',
    dependencies: [benchmark_dep]
)
