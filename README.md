# risc0-crypto-shootout

Cycle-count benchmarks comparing [risc0-crypto] head-to-head against patched
alternatives on the RISC Zero zkVM. Each benchmark runs the same revm-precompile
interface against both implementations and asserts they agree on the result.

| Benchmark        | risc0-crypto      | Counterpart            |
|------------------|-------------------|------------------------|
| `ecrecover`      | secp256k1         | `k256`                 |
| `p256verify`     | secp256r1 (P-256) | `p256`                 |
| `eip196/add`     | BN254 G1          | `substrate-bn`         |
| `eip196/mul`     | BN254 G1          | `substrate-bn`         |
| `eip2537/add`    | BLS12-381 G1      | `blst`                 |
| `eip2537/msm`    | BLS12-381 G1      | `blst`                 |
| `modexp/256bit`  | EIP-198 modexp    | `aurora-engine-modexp` |
| `sha256/64B`     | risc0-zkp SHA-256 | `sha2`                 |

Each counterpart is wired in through `[patch.crates-io]` to its [risc0 fork][forks]
(zkVM-accelerated builds of `k256`, `p256`, `sha2`, `substrate-bn`, and `blst`),
so the numbers compare risc0-crypto against the best-tuned zkVM build of each
library. The exception is `modexp`: revm's `DefaultCrypto::modexp` falls through
to `aurora-engine-modexp`, which has no risc0 fork — it stands in as the
unaccelerated reference.

## Latest results

Refreshed by [`.github/workflows/bench.yml`](.github/workflows/bench.yml) on
every push to `main`, weekly, and on manual dispatch. The workflow opens (or
force-updates) a single `ci/bench-update` PR; merge it to land the new numbers.
`Ratio` is `Counterpart ÷ risc0-crypto` — larger means risc0-crypto is faster.

<!-- BENCH-START -->
| Benchmark | risc0-crypto | Counterpart | Library | Ratio |
|-----------|-------------:|------------:|---------|------:|
| `ecrecover` | 120,300 | 569,207 | `k256` | 4.73× |
| `p256verify` | 82,667 | 192,713 | `p256` | 2.33× |
| `eip196/add` | 2,282 | 9,552 | `substrate-bn` | 4.19× |
| `eip196/mul` | 68,496 | 1,302,678 | `substrate-bn` | 19.02× |
| `eip2537/add` | 3,394 | 13,625 | `blst` | 4.01× |
| `eip2537/msm/1` | 189,395 | 1,316,098 | `blst` | 6.95× |
| `eip2537/msm/128` | 19,412,368 | 69,095,044 | `blst` | 3.56× |
| `modexp/256bit` | 30,566 | 851,596 | `aurora` | 27.86× |
| `sha256/64B` | 535 | 1,152 | `sha2` | 2.15× |

_risc0-crypto rev [`4042fe89`](https://github.com/boundless-xyz/risc0-crypto/commit/4042fe8933cd71b36e0969c6e7d52c994cc43f86)_
<!-- BENCH-END -->

## Run

```bash
cargo run --release
cargo run --release -- --json results.json
cargo run --release -- --markdown results.md
```

Requires the `rzup`-managed `r0vm` toolchain (see the risc0-crypto README for
setup).

[risc0-crypto]: https://github.com/boundless-xyz/risc0-crypto
[forks]: https://github.com/risc0
