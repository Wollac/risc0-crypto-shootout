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
| `sha256/256B`    | risc0-zkp SHA-256 | `sha2`                 |

The counterparts are pulled from the [risc0 RustCrypto/blst forks][forks] via
`[patch.crates-io]`, so the numbers reflect each library's best-tuned zkVM build.
The exception is `modexp`: revm's `DefaultCrypto::modexp` falls through to
`aurora-engine-modexp`, which has no risc0 fork - it stands in as the
unaccelerated reference.

## Run

```bash
cargo run --release
cargo run --release -- --json results.json
```

Requires the `rzup`-managed `r0vm` toolchain (see the risc0-crypto README for
setup).

[risc0-crypto]: https://github.com/boundless-xyz/risc0-crypto
[forks]: https://github.com/risc0
