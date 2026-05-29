# Rare Bullet — Bulletproof CosmWasm Contract

## Overview

A CosmWasm smart contract implementing the Rare Bullet protocol's on-chain zero-knowledge state machine. The contract performs aggregated ($m{=}2$) Bulletproof verification over 64 total bits ($2 \times 32$-bit dynamic boundaries via homomorphic shifting) natively within the CosmWasm WebAssembly runtime via native Rust compilation. This approach completely bypasses EVM pre-compile limitations, enabling gas-efficient deployment of unmodified, modern Rust cryptographic libraries on-chain.

Upon successful verification, the contract atomically mints Data-Backed Range Tokens (CW-20) to data sellers. The fully-loaded Deposit state machine consumes ~631K gas (4.8× compute multiplier relative to a canonical CW-20 transfer baseline). Trusted Execution Environments (TEEs) are strictly used for off-chain data ingestion (TLS oracle) and Phase 4 threshold key custody—not for computational proof verification.

## Features

- **Aggregated Bulletproof Verification**: Native on-chain aggregated ($m{=}2$) Bulletproof verification over 64 total bits via homomorphic shifting of Range Bucket boundaries
- **Data-Backed Range Token Minting**: Atomic CW-20 minting upon successful proof verification
- **Nullifier-Based Sybil Resistance**: Deterministic payload nullifiers prevent duplicate data submissions
- **O(1) Vault Selection**: Swap-and-pop algorithm over indexed CosmWasm storage maps for efficient burn-to-claim
- **Oracle-Driven Randomness**: Two-phase asynchronous BurnAndRequest/FulfillRandomness architecture

## Messages

### InstantiateMsg
```json
{
  "token_name": "RangeBucket90-100",
  "token_symbol": "RB90",
  "token_decimals": 6,
  "min_vault_depth": 5,
  "fallback_timeout_blocks": 100000,
  "oracle_address": "wasm1...",
  "oracle_timeout_blocks": 100800
}
```

### ExecuteMsg — Deposit
```json
{
  "deposit": {
    "proof_hex": "<hex-encoded aggregated Bulletproof bytes>",
    "commitment_hex": "<hex-encoded Pedersen commitment, 32 bytes>",
    "num_bits": 32,
    "ipfs_cid_hash": "<CID for encrypted payload on DA layer>",
    "ct_key_hash": "<encrypted symmetric key identifier>",
    "oracle_signature": "<hex-encoded oracle attestation>",
    "payload_nullifier": "<64-char hex SHA-256 of plaintext data>"
  }
}
```

### ExecuteMsg — BurnAndRequest
```json
{
  "burn_and_request": {
    "buyer_x25519_pubkey": "<hex-encoded X25519 public key>"
  }
}
```

## Dependencies

- `bulletproofs` v4.0.0 - Bulletproof range proof implementation
- `curve25519-dalek-ng` v4.1.1 - Elliptic curve operations
- `merlin` v3 - Transcript-based proof protocol
- `cosmwasm-std` v1.5 - CosmWasm standard library

## Building

```bash
brew install binaryen

rustup override set 1.76.0

rustup target add wasm32-unknown-unknown

cargo update -p base64ct --precise 1.6.0

# 1. Compile to Wasm using Rust's maximum speed profile (opt-level = 3)
cargo build --release --target wasm32-unknown-unknown

# 2. Optimize the Wasm payload for maximum execution speed, ignoring file size
wasm-opt -O3 target/wasm32-unknown-unknown/release/bulletproof_contract.wasm -o artifacts/bulletproof_contract.wasm
```

## Proof Generation

The Bulletproof proof is generated off-chain using the standard `bulletproofs` Rust crate compiled via native Rust compilation. The Rare Bullet protocol uses aggregated ($m{=}2$) verification with homomorphic shifting to enforce Range Bucket boundaries. The prover derives two committed values via homomorphic shifting:

- **C1** = `secret_value - bucket_floor` (lower bound proof)
- **C2** = `(bucket_ceiling - 1) - secret_value` (upper bound proof)

```rust
use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use curve25519_dalek_ng::traits::MultiscalarMul;
use merlin::Transcript;
use rand::thread_rng;

let pc_gens = PedersenGens::default();
let bp_gens = BulletproofGens::new(32, 2); // 32-bit per commitment, m=2 aggregated
let secret_value = 95u64; // Score within Range Bucket [90, 100)
let bucket_floor = 90u64;
let bucket_ceiling = 100u64;
let mut rng = thread_rng();
let blinding = Scalar::random(&mut rng);

// Derive shifted values and blindings for aggregated (m=2) proof
let v1 = secret_value - bucket_floor;       // lower bound: 95 - 90 = 5
let v2 = (bucket_ceiling - 1) - secret_value; // upper bound: 99 - 95 = 4
let r1 = blinding;
let r2 = -blinding;

// Transcript must mirror on-chain verifier (including context bindings)
let mut prover_transcript = Transcript::new(b"PrivateDataExchange_RangeProof_v1");
// In production: append contract address, nullifier, sender, floor, ceiling

let (proof, _shifted_commitments) = RangeProof::prove_multiple_with_rng(
    &bp_gens, &pc_gens, &mut prover_transcript,
    &[v1, v2], &[r1, r2], 32, &mut rng,
).expect("aggregated proof generation failed");

// Submit the raw (unshifted) commitment: C = secret_value*G + blinding*H
let raw_commitment = RistrettoPoint::multiscalar_mul(
    &[Scalar::from(secret_value), blinding],
    &[pc_gens.B, pc_gens.B_blinding],
).compress();
```

The serialized proof (`proof.to_bytes()`) and raw Pedersen commitment (`raw_commitment.to_bytes()`) are submitted to the contract's `Deposit` entry point. The contract reconstructs C1 and C2 on-chain via homomorphic shifting and verifies the aggregated proof against both derived commitments.
