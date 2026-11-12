# Implementation and validation status

The attached six-step plan is implemented and validated on the Apple M4 Max.
GPU access was restored by changing the session to Full access.

| Plan requirement | Current evidence |
| --- | --- |
| Rust CPU derivation and invalid child handling | `src/derive.rs`; 1,024 candidates compared against Rust Bitcoin at all six stages; explicit invalid-scalar/zero-child tests pass |
| Network selection and prefix validation | Unit tests plus actual CLI checks for mainnet, testnet, testnet4, signet and regtest in `integration.json` |
| Metal hashing, curve arithmetic, full BIP32 derivation and matching | `shaders/search.metal`, `src/gpu.rs`; native GPU tests pass for both coin types and all 2/4/8-bit windows; positive, no-match and concurrent winner cases pass |
| Secure candidate generation and reusable buffers | `OsRng` produces fresh 128-bit candidates; `MetalSearch` reuses shared input/output/prefix/winner/table buffers; native tests reuse them across successive dispatches |
| Complete aezeed output | Rust scrypt N=32768/r=8/p=1, AEZv5 Tiny, birthday/version, salt, CRC32C and 24-word encoding; official LND reduced-parameter vectors and production roundtrip tests pass |
| Independent match verification | Every result is rederived on CPU before display; its mnemonic is decoded and rederived again |
| Fixed entropy compatibility | 16 vectors checked against chantools v0.14.3, saved in `data/identity-vectors.tsv` and tested by Rust |
| Actual GPU/CPU intermediate comparison | Native unit tests compare every key and chain code; benchmark harness verifies each supported configuration before timing |
| Independent mnemonic restoration | CPU and GPU mnemonics restore to the same identities through chantools on mainnet/testnet; the exact intended Cargo command was also checked through chantools |
| CPU/GPU/original performance and tuning | Repeated measurements in `benchmarks.json`; table/batch/threadgroup sweeps in `gpu-tuning.json`, `gpu-large-batch-tuning.json`, `gpu-table-confirmation.json` |
| CLI, progress and cancellation | Actual Cargo command succeeds; benchmark progress captured in `benchmark-output.log`; CPU and GPU SIGINT checks pass in `integration.json` |

Final five-second samples, three repetitions, median candidate throughput:

| Backend | Candidates/s |
| --- | ---: |
| Metal GPU | 1,227,355 |
| Rust CPU, four threads | 126,342 |
| chantools v0.14.3, four threads | 59,600 |

GPU is 20.6 times the four-thread chantools rate and 9.7 times
the four-thread Rust CPU rate in this measurement. CPU counts are explicit;
these are measurements on this Mac, not portable guarantees.

Chosen Metal defaults: 16384 candidates, eight-bit table, pipeline execution
width (32 here). Increasing the batch to 32768/65536/131072 was slower.
At 16384, threadgroups 32 and 128 differed by less than 0.1%, so the automatic
pipeline width was retained. CPU keeps its 4096-candidate default.

`native-tests.log`: full Cargo test suite, six tests pass with no skips.
`clippy.log`: all targets checked with warnings denied. Formatting passes.
Local workspace paths in the compilation logs are normalized to `.` for publication.
`integration.json`: actual command, device/defaults, all network flags, seed
restoration, cancellation and source/binary SHA-256 values.
`benchmarks.json` records the same executable hash as the integration checks.
The supplemental C++/Python shader check passed 4352 field/scalar cases,
71 inverses and 396 full derivations across all three table windows.

The reference release archive SHA-256 matched its published manifest:
`75bd418e0385ed99a16298ba7f407881dfc3954371142f81b8ef4f115dde8f1f`.
The reference executable hash is recorded in `benchmarks.json`.

No validation or implementation step from the plan remains pending.

Follow-up CPU scaling (2026-11-11): chantools medians were 60,000 / 135,000 /
147,333 candidates/s at 4 / 10 / 14 threads. A fresh GPU median was 1,226,091,
which is 8.32 times the fourteen-thread rate. The earlier 20.6-times figure is
specifically against four-thread chantools. Evidence and executable hash are in
`chantools-cpu-scaling.json`; the binary matches the original validated build.
