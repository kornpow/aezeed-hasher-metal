# aezeed-hasher-metal

Rust recreation of `chantools vanitygen`, with an Apple Metal compute backend.
Searches for an LND node identity **public key hex prefix**, then produces the
24-word aezeed that restores to that identity. The CPU backend works without Metal.

```sh
git clone https://github.com/kornpow/aezeed-hasher-metal.git
cd aezeed-hasher-metal
cargo build --release
cargo run --release -- vanitygen --prefix 022222 --backend metal
```

Prefixes must start with `02` or `03` and contain 4–16 hex digits in whole bytes.
Use `--network mainnet` (default), `testnet`, `testnet4`, `signet`, or `regtest`.
The corresponding identity path is `m/1017'/coin_type'/6'/0/0`.
Output is the compressed public key and its aezeed, with an empty passphrase.
Every GPU match is rederived on the CPU, and its mnemonic is decoded and rederived
again before it is printed. Ctrl-C stops after the current batch.

```sh
# CPU search
cargo run --release -- vanitygen --prefix 02ab --backend cpu --threads 4

# Throughput includes random entropy generation and candidate derivation
cargo run --release -- benchmark --backend cpu --seconds 5 --threads 4
cargo run --release -- benchmark --backend metal --seconds 5

# Compare every GPU intermediate key and chain code against the CPU
cargo run --release -- verify-gpu --samples 256

# Diagnose the node key for known test entropy
cargo run --release -- derive --entropy 000102030405060708090a0b0c0d0e0f
```

The GPU runs HMAC-SHA512, BIP32 private derivation, secp256k1 public key generation,
and prefix comparison. Rust generates batches of independent 128-bit entropy
using the operating system RNG and supplies reusable shared Metal buffers.
The curve code uses 8 × 32-bit limbs, Jacobian coordinates, a preweighted
generator table with a selectable 2-, 4-, or 8-bit window, and an addition chain
for field inversion. The default window is eight bits, selected from M4 Max
measurements.
Scrypt, AEZv5, birthday encoding, CRC32C and mnemonic conversion run in Rust only
for a match. No Go executable is required to use the tool.

`--batch-size` controls the number of candidates per dispatch (default: 16384 for
Metal, 4096 for CPU).
`--threadgroup-size` defaults to the pipeline's execution width. GPU setup and
shader compilation are excluded from benchmark timing; output verification and
mnemonic encoding occur after the search. Search probability uses
`1 - (1 - 2^-bits)^attempts`, with one bit for the `02`/`03` parity byte.
Use `--window-bits 2`, `4`, or `8` to compare curve tables of 24 KiB, 60 KiB,
or 510 KiB. Wider windows need fewer point additions but use larger tables;
the best choice must be measured on the actual GPU.
Benchmark mode uses a real, difficult public key prefix so the complete
derivation and prefix check remain part of the workload.

## Validation

```sh
# CPU/BIP32, official LND aezeed vectors, production roundtrip
cargo test --release --lib -- --skip gpu::tests

# Native GPU tests: require an accessible Metal device
cargo test --release --lib gpu::tests -- --nocapture

# Run the complete suite, including CPU and native GPU tests
cargo test --release

# Compile the shader without requiring an accessible GPU
xcrun metal -c shaders/search.metal -o /tmp/aezeed-search.air

# Supplemental check of the exact shader arithmetic using C++ and Python
python3 scripts/check-shader.py

# Independent chantools restore checks, CPU comparison, and GPU validation/tuning
python3 scripts/compare-chantools.py --chantools /path/to/chantools --metal
python3 scripts/compare-chantools.py --chantools /path/to/chantools --tune
```

The Python oracle uses standard-library HMAC and independent affine curve
arithmetic. It compiles the Metal arithmetic as C++ and checks intermediate
results. This is supplemental evidence and does not replace native GPU tests.
`compare-chantools.py` uses newly generated disposable mnemonics to check identity
restoration on mainnet and testnet, and independently serializes BIP32 master
keys for 16 fixed entropy vectors checked against chantools. Those vectors are
retained in `data/identity-vectors.tsv` and exercised by Rust tests.
With `--metal`, it also restores GPU-generated mnemonics through chantools.
With `--tune`, it varies batch size, threadgroup size, and curve table window,
verifies each supported GPU configuration, and records repeated timings and the
best measured arguments as JSON. Use `--seconds` and `--repeats` to control timing
(defaults: five seconds and three samples per configuration).
To extend the tuning range, pass `--batches`, `--windows`, and `--threadgroups`:

```sh
python3 scripts/compare-chantools.py --chantools /path/to/chantools --tune \
  --windows 8 --batches 8192 16384 32768 65536 --threadgroups 32 64 128
```

Initial validation on the M4 Max: Rust CPU comparisons pass at all six BIP32
stages for 1,024 candidates. Official LND aezeed vectors pass using LND's reduced
test scrypt parameters; production encoding always uses N=32768, r=8, p=1.
Restoring production-generated mnemonics with chantools v0.14.3 also passes.
The Metal shader compiles. The independent checks pass for 4,352 arithmetic
cases, 71 inverses, and 396 derivations across all three table windows, including
every intermediate key, final public key and prefix matching.

Native GPU tests pass on the Apple M4 Max for both coin types and all three table
windows, including prefix matches, no-match batches, and simultaneous contenders
for the winner slot. GPU-generated mnemonics restore correctly through chantools
on mainnet and testnet. The complete Rust test suite and Clippy pass; see
`validation/native-tests.log` and `validation/clippy.log`.

Tuning tested batches from 1024 through 131072 candidates. The best measured
batch size was 16384 with an 8-bit table, at approximately **1.2 million seeds/s**.
Threadgroup sizes 32 and 128 differed by less than 0.1% at that setting, so the
default remains the pipeline's execution width (32 on this Mac).
The four-thread Rust CPU backend measured about 127k seeds/s and four-thread
chantools about 60k seeds/s. Final repeated measurements are in
`validation/benchmarks.json`; the tuning sweeps are in `validation/gpu-tuning.json`,
`validation/gpu-large-batch-tuning.json`, and `validation/gpu-table-confirmation.json`.
These measurements apply to this Mac and these worker counts.

A follow-up CPU scaling check measured chantools at 60k candidates/s with four
threads, 135k with ten, and 147k with all fourteen CPU cores. A fresh GPU median
was 1.226 million candidates/s, or **8.3× the fourteen-thread chantools rate**.
Thus the roughly 20× figure describes the default four-thread comparison.
See `validation/chantools-cpu-scaling.json` for the three-repeat measurements.

Rust 1.88 or later and Xcode command line tools are required for development.
Shader source is embedded and compiled at runtime. The Metal backend needs an
execution environment that exposes the GPU; an agent sandbox may hide Metal
devices. Tests were run successfully after enabling Full access.

Upstream reference projects are
[chantools](https://github.com/lightninglabs/chantools) and
[cryptography-toolkit](https://github.com/guggero/cryptography-toolkit).
They are not build dependencies. Source references and license notices are in
`NOTICE.md` and `licenses/`.
