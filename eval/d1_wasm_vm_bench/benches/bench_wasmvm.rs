//! # Rare Bullet — CosmWasm VM CPU Overhead Micro-Benchmark (Criterion)
//!
//! Measures the **pure WASM VM execution overhead** of each CosmWasm smart
//! contract entry point in the Rare Bullet protocol, fully isolated from any
//! networking, P2P gossip, or PBFT/Tendermint consensus overhead. The native
//! CosmWasm WebAssembly runtime enables native Rust compilation of the standard
//! `bulletproofs` crate, completely bypassing EVM pre-compile limitations.
//!
//! ## Compiler Backend
//!
//! This benchmark uses the **Cranelift** compiler backend (`cosmwasm-vm`
//! feature `"cranelift"`), matching production `wasmd` nodes.  Without this
//! feature, `cosmwasm-vm` defaults to Singlepass — a fast-compile /
//! slow-execute JIT that inflates execution timings by ~10–20× vs Cranelift
//! for compute-intensive workloads like aggregated ($m{=}2$) Bulletproof
//! verification over 64 total bits.
//!
//! ## Methodology — Eliminating Benchmark Artefacts
//!
//! This benchmark uses `iter_custom` with **manual `Instant` timing** so that
//! only the actual contract call is measured.  Three classic Criterion pitfalls
//! are explicitly avoided:
//!
//! 1. **Drop Penalty** — With `iter_batched`, the Wasmer `Instance` destructor
//!    (memory unmap, page deallocation) runs inside the timed region.  On a
//!    typical x86-64 host this adds ~30 ms of phantom overhead per iteration
//!    that has nothing to do with contract execution.  By using `iter_custom`
//!    we stop the timer *before* the instance is dropped.
//!
//! 2. **Cold-Start Memory Penalty** — `mock_instance_with_options` compiles
//!    the WASM bytecode from scratch every call (no module caching).  This
//!    means the first `call_execute` after instance creation runs against cold
//!    TLBs and L1/L2 caches, inflating the result.  In production wasmd the
//!    module is compiled once and cached; subsequent TX executions reuse the
//!    warm compiled module.  Our benchmarks mitigate this by performing a
//!    **warm-up call** (excluded from timing) before the measured call where
//!    feasible.
//!
//! 3. **Compiler Backend Mismatch** — `cosmwasm-vm` defaults to the
//!    Singlepass compiler which performs zero register-allocation optimisation.
//!    Production `wasmd` uses Cranelift.  This feature is now enabled
//!    explicitly.
//!
//! For the `Deposit` benchmark, multiple deposits are executed sequentially
//! on the **same warm instance** (after a warm-up deposit excluded from
//! timing), mirroring production `FinalizeBlock` where hundreds of TXs share
//! warm L1i/L1d caches and branch predictor state.  A rotating pool of
//! pre-generated Bulletproof proofs ensures each iteration verifies a
//! cryptographically distinct proof, preventing branch-prediction bias and
//! internal verifier state reuse from inflating throughput.
//!
//! ## Entry Points Benchmarked
//!
//! | Benchmark                     | Entry Point         | What It Measures                                   |
//! |-------------------------------|---------------------|----------------------------------------------------|
//! | `wasmvm_instantiate`          | `instantiate`       | CW20 + vault config initialisation                 |
//! | `wasmvm_execute_deposit`      | `execute(Deposit)`  | Aggregated ($m{=}2$) BP verification (64 bits) + CW20 mint + nullifier |
//! | `wasmvm_execute_transfer`     | `execute(Transfer)` | CW20 token transfer (warm instance)                |
//! | `wasmvm_execute_burn_request` | `execute(BurnAndRequest)` | CW20 burn + oracle request emit              |
//! | `wasmvm_execute_fulfill`      | `execute(FulfillRandomness)` | O(1) swap-and-pop vault selection          |
//! | `wasmvm_query_active_count`   | `query(ActiveCount)`| Storage read for active vault count (warm instance) |
//!
//! ## Empirical Metrics (from paper §8)
//!
//! | Metric | Value |
//! |--------|-------|
//! | Fully-loaded Deposit state machine | ~631K gas |
//! | Relative compute efficiency (vs CW-20 baseline) | 4.8× multiplier |
//! | Isolated WASM execution latency | 30.2 ms |
//! | Systemic testnet throughput (100M block gas limit) | 26 TPS |
//!
//! ## Reproducibility
//!
//! All inputs are deterministic (seeded RNG for Bulletproof proofs).  The WASM
//! binary is loaded from `../d1_bulletproof_cosmwasm/bulletproof_contract.wasm`
//! (the Docker-optimised artifact checked into the repository).
//!
//! Run:
//! ```bash
//! cd eval/d1_wasm_vm_bench
//! cargo bench
//! ```
//!
//! ## CPU Specification Variance
//!
//! Absolute wall-clock numbers will vary across hardware.  Key factors:
//!
//! - **Micro-architecture & IPC:** Deposit (aggregated Bulletproof verification)
//!   is dominated by Ristretto255 multi-scalar multiplication — a long chain
//!   of dependent 64-bit integer multiplies and conditional moves.  CPUs
//!   with wider issue width and deeper out-of-order buffers (e.g., Apple
//!   M-series, AMD Zen 4) will complete this faster than narrower cores
//!   (e.g., AWS Graviton 2).  Expect ~1.5–3× variation across mainstream
//!   server and desktop CPUs.
//!
//! - **L1 instruction-cache pressure:** The compiled Bulletproof verifier
//!   has a large instruction footprint (~32 KB hot loop).  CPUs with
//!   smaller L1i (32 KB, common on ARM Cortex-A55 / Graviton 2) may see
//!   elevated L1i miss rates vs. CPUs with 64 KB+ L1i (Apple M-series,
//!   AMD Zen 4).  The warm-instance methodology mitigates this by priming
//!   caches before measurement.
//!
//! - **Memory subsystem & TLB reach:** Wasmer's linear memory is backed
//!   by mmap'd 4 KB pages.  CPUs with larger TLBs or transparent huge
//!   page support will have fewer TLB misses during the multi-scalar
//!   multiply's random-access table lookups.
//!
//! - **CPU frequency scaling:** Dynamic frequency governors (Intel
//!   Turbo Boost, AMD Precision Boost) inflate single-threaded results
//!   on lightly loaded machines.  CI runners on shared infrastructure
//!   (GitHub Actions) may not sustain peak turbo, adding ~5–15% noise.
//!   For reproducible results, pin the CPU governor to `performance`
//!   (`cpupower frequency-set -g performance`) when running locally.
//!
//! - **CI vs. bare-metal:** GitHub Actions runners use shared vCPUs
//!   (AMD EPYC / Intel Xeon, 2-core).  Expect 2–4× slower absolute
//!   times and higher variance (~10–20% CoV) compared to dedicated
//!   bare-metal or M-series laptops.  Use CI results for
//!   regression detection (relative change), not absolute reporting.
//!
//! **Recommendation for paper figures:** Report results from a
//! dedicated machine with a fixed CPU frequency governor and record
//! the exact CPU model, core count, and clock speed.  CI results are
//! best used for automated regression detection between commits.

// ---------------------------------------------------------------------------
// Workaround: wasmer-vm (used by cosmwasm-vm 1.5.x) references the
// __rust_probestack symbol which was removed in Rust >= 1.89.
// Provide a minimal stub. On x86-64 the singlepass compiler never
// actually invokes this function.
// See: https://github.com/wasmerio/wasmer/issues/5610
//
// Guard: ELF-only (Linux / FreeBSD). The .type / .size directives are ELF-
// specific and will fail on macOS Mach-O or Windows PE.  On those platforms
// the symbol is either still provided by the toolchain or wasmer-vm is not
// linked with singlepass.
// ---------------------------------------------------------------------------
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
core::arch::global_asm!(
    ".globl __rust_probestack",
    ".type __rust_probestack, @function",
    "__rust_probestack:",
    "ret",
    ".size __rust_probestack, .-__rust_probestack",
);

use criterion::{criterion_group, criterion_main, Criterion};
use std::hint::black_box;
use std::time::{Duration, Instant};

use cosmwasm_std::Empty;
use cosmwasm_vm::testing::{
    mock_env, mock_info, mock_instance_with_options, MockApi, MockInstanceOptions, MockQuerier,
    MockStorage,
};
use cosmwasm_vm::{call_execute, call_instantiate, call_query};

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek_ng::traits::MultiscalarMul;
use merlin::Transcript;
use rand::{rngs::StdRng, SeedableRng};

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Candidate paths searched for the optimised WASM binary (relative to this crate's root).
const WASM_CANDIDATE_PATHS: &[&str] = &[
    "../d1_bulletproof_cosmwasm/bulletproof-contract/bulletproof_contract.wasm",
    "../d1_bulletproof_cosmwasm/bulletproof-contract/bulletproof-contract/artifacts/bulletproof_contract.wasm",
    "../d1_bulletproof_cosmwasm/bulletproof-contract/bulletproof-contract/target/wasm32-unknown-unknown/release/bulletproof_contract.wasm",
];

/// Contract address used by `cosmwasm-vm` mock environment.
const MOCK_CONTRACT_ADDR: &str = "cosmos2contract";

/// Number of unique proofs pre-generated for the Deposit benchmark pool.
/// Each proof has its own blinding factor, nullifier, and commitment —
/// preventing branch-prediction bias across Criterion iterations.
const DEPOSIT_POOL_SIZE: usize = 64;

/// RNG seed offset to ensure each pool entry gets a distinct, reproducible seed.
const SEED_OFFSET: u64 = 1000;

/// Hardcoded bucket bounds matching the contract's PoC configuration.
const BUCKET_FLOOR: u64 = 90;
const BUCKET_CEILING: u64 = 100;
const SECRET_VALUE: u64 = 95;

/// CosmWasm gas limit — set to half of `u64::MAX` to give effectively
/// unlimited gas without risking overflow in wasmer's internal gas
/// accounting (which may add values together).  The Bulletproof verification
/// step consumes billions of metered WASM instructions per deposit, and the
/// warm-instance batching strategy runs 20+ deposits on a single instance.
const GAS_LIMIT: u64 = 9_223_372_036_854_775_807; // u64::MAX / 2

// ---------------------------------------------------------------------------
// Helpers — proof generation (mirrors contract's on-chain verifier transcript)
// ---------------------------------------------------------------------------

/// A pre-generated Deposit payload ready to be sent as a raw JSON byte slice.
struct DepositPayload {
    /// JSON-encoded `ExecuteMsg::Deposit { ... }` bytes.
    json: Vec<u8>,
}

/// Generate a pool of valid, unique Deposit payloads.
///
/// Each entry has a deterministically seeded Bulletproof proof whose Merlin
/// transcript is bound to `MOCK_CONTRACT_ADDR` and a unique nullifier, exactly
/// mirroring the contract's on-chain verifier.
fn generate_deposit_pool(pool_size: usize, sender_addr: &str) -> Vec<DepositPayload> {
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(32, 2);

    (0..pool_size)
        .map(|idx| {
            let mut rng = StdRng::seed_from_u64(idx as u64 + SEED_OFFSET);
            let blinding = Scalar::random(&mut rng);

            let v1 = SECRET_VALUE - BUCKET_FLOOR;
            let v2 = (BUCKET_CEILING - 1) - SECRET_VALUE;
            let r1 = blinding;
            let r2 = -blinding;

            let nullifier_hex = format!("{:064x}", idx as u64 + SEED_OFFSET);

            let mut prover_transcript =
                Transcript::new(b"PrivateDataExchange_RangeProof_v1");
            prover_transcript.append_message(b"contract", MOCK_CONTRACT_ADDR.as_bytes());
            prover_transcript.append_message(b"nullifier", nullifier_hex.as_bytes());
            // ADD the sender binding exactly where your smart contract expects it!
            prover_transcript.append_message(b"sender", sender_addr.as_bytes());
            prover_transcript.append_u64(b"floor", BUCKET_FLOOR);
            prover_transcript.append_u64(b"ceiling", BUCKET_CEILING);

            let (proof, _) = RangeProof::prove_multiple_with_rng(
                &bp_gens,
                &pc_gens,
                &mut prover_transcript,
                &[v1, v2],
                &[r1, r2],
                32,
                &mut rng,
            )
            .expect("proof generation must succeed");

            let raw_commitment = RistrettoPoint::multiscalar_mul(
                &[Scalar::from(SECRET_VALUE), blinding],
                &[pc_gens.B, pc_gens.B_blinding],
            )
            .compress();

            let proof_hex = hex::encode(proof.to_bytes());
            let commitment_hex = hex::encode(raw_commitment.to_bytes());

            let json = serde_json::json!({
                "deposit": {
                    "proof_hex": proof_hex,
                    "commitment_hex": commitment_hex,
                    "num_bits": 32,
                    "ipfs_cid_hash": format!("QmBench_{}", idx),
                    "ct_key_hash": format!("CtBench_{}", idx),
                    "oracle_signature": "deadbeef",
                    "payload_nullifier": nullifier_hex
                }
            });

            DepositPayload {
                json: serde_json::to_vec(&json).unwrap(),
            }
        })
        .collect()
}

/// JSON for `InstantiateMsg` with oracle address configured.
fn instantiate_msg_json() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "token_name": "RangeBucket90-100",
        "token_symbol": "RB90",
        "token_decimals": 6,
        "min_vault_depth": 5,
        "fallback_timeout_blocks": 100000,
        "oracle_address": "oracle_relayer",
        "oracle_timeout_blocks": 50
    }))
    .unwrap()
}

/// JSON for `ExecuteMsg::Transfer` to the default "buyer" recipient.
fn transfer_msg_json() -> Vec<u8> {
    transfer_msg_to_json("buyer")
}

/// JSON for `ExecuteMsg::Transfer` to a specific recipient.
fn transfer_msg_to_json(recipient: &str) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "transfer": {
            "recipient": recipient,
            "amount": "1000000"
        }
    }))
    .unwrap()
}

/// JSON for `ExecuteMsg::BurnAndRequest`.
fn burn_and_request_msg_json() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "burn_and_request": {
            "buyer_x25519_pubkey": "aa".repeat(32)
        }
    }))
    .unwrap()
}

/// JSON for `ExecuteMsg::FulfillRandomness`.
fn fulfill_randomness_msg_json() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "fulfill_randomness": {
            "buyer_address": "buyer",
            "random_seed": "12345678901234"
        }
    }))
    .unwrap()
}

/// JSON for `QueryMsg::ActiveCount`.
fn query_active_count_json() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "active_count": {}
    }))
    .unwrap()
}

// ---------------------------------------------------------------------------
// Helper — create a fresh WASM VM instance and optionally seed state
// ---------------------------------------------------------------------------

type VmInstance =
    cosmwasm_vm::Instance<cosmwasm_vm::testing::MockApi, cosmwasm_vm::testing::MockStorage, cosmwasm_vm::testing::MockQuerier>;

/// Load WASM bytecode, searching multiple candidate paths.
fn load_wasm() -> Vec<u8> {
    for path in WASM_CANDIDATE_PATHS {
        if let Ok(wasm) = std::fs::read(path) {
            return wasm;
        }
    }

    let paths = WASM_CANDIDATE_PATHS
        .iter()
        .map(|p| format!("  - {}", p))
        .collect::<Vec<_>>()
        .join("\n");

    panic!(
        "Failed to read WASM binary. Searched:\n{}\n\n\
         Build it first:\n  cd ../d1_bulletproof_cosmwasm/bulletproof-contract && \
         cargo build --release --target wasm32-unknown-unknown\n\
         Or with Docker optimizer:\n  docker run --rm -v \"$(pwd)\":/code \
         cosmwasm/optimizer:0.16.1",
        paths
    );
}

/// Create a fresh VM instance from WASM bytecode.
fn fresh_instance(wasm: &[u8]) -> VmInstance {
    mock_instance_with_options(
        wasm,
        MockInstanceOptions {
            gas_limit: GAS_LIMIT,
            ..Default::default()
        },
    )
}

/// Create a VM instance that has already been instantiated (contract state
/// initialised).  Returns the instance ready for execute/query calls.
fn instantiated_instance(wasm: &[u8]) -> VmInstance {
    let mut instance = fresh_instance(wasm);
    let env = mock_env();
    let info = mock_info("creator", &[]);
    let msg = instantiate_msg_json();
    call_instantiate::<MockApi, MockStorage, MockQuerier, Empty>(&mut instance, &env, &info, &msg)
        .expect("instantiate must succeed in VM")
        .into_result()
        .expect("instantiate contract result must be Ok");
    instance
}

/// Seed `count` deposits into an already-instantiated instance.
/// Uses deterministic proofs with index offsets starting at `start_idx`.
fn seed_deposits(instance: &mut VmInstance, pool: &[DepositPayload], count: usize, start_idx: usize) {
    let env = mock_env();
    let info = mock_info("seller", &[]);
    for i in 0..count {
        let payload = &pool[(start_idx + i) % pool.len()];
        call_execute::<MockApi, MockStorage, MockQuerier, Empty>(instance, &env, &info, &payload.json)
            .expect("deposit must succeed in VM")
            .into_result()
            .expect("deposit contract result must be Ok");
    }
}

// ---------------------------------------------------------------------------
// Benchmarks — all use iter_custom to avoid the Drop Penalty
// ---------------------------------------------------------------------------

/// **Benchmark 1: `instantiate`**
///
/// Measures the pure WASM VM overhead of the contract's `instantiate` entry
/// point.  Uses `iter_custom` so that Instance::drop() is excluded from the
/// timed region.
fn bench_instantiate(c: &mut Criterion) {
    let wasm = load_wasm();
    let msg = instantiate_msg_json();
    let env = mock_env();
    let info = mock_info("creator", &[]);

    c.bench_function("wasmvm_instantiate", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let mut instance = fresh_instance(&wasm);

                let start = Instant::now();
                let res = call_instantiate::<MockApi, MockStorage, MockQuerier, Empty>(
                    &mut instance, &env, &info, &msg,
                )
                .expect("instantiate must succeed")
                .into_result()
                .expect("instantiate result must be Ok");
                total += start.elapsed();
                black_box(res);

                // instance drops here — outside the timed region
            }
            total
        })
    });
}

/// **Benchmark 2: `execute(Deposit)` — warm-instance steady-state**
///
/// Measures the most expensive contract operation: on-chain Bulletproof
/// range-proof verification (aggregated m=2, 32-bit) + CW20 atomic mint +
/// nullifier/commitment replay checks + vault storage write.
///
/// **Warm-instance methodology:** In production `wasmd`, a single
/// `FinalizeBlock` processes hundreds of deposit TXs sequentially on the
/// same compiled module; by TX #2 the hot Bulletproof inner loop is resident
/// in L1i and the branch predictor has converged.  This benchmark mirrors
/// that by executing multiple deposits on the **same instance**, with the
/// first deposit serving as an untimed warm-up call.
///
/// When the pool of unique proofs/nullifiers on the current instance is
/// exhausted, a new instance is created (the creation cost is excluded from
/// timing).  A rotating pool of `DEPOSIT_POOL_SIZE` pre-generated proofs
/// ensures each iteration verifies a cryptographically distinct proof.
fn bench_deposit(c: &mut Criterion) {
    let wasm = load_wasm();
    let pool = generate_deposit_pool(DEPOSIT_POOL_SIZE, "seller");
    let env = mock_env();
    let info = mock_info("seller", &[]);

    let mut group = c.benchmark_group("deposit");
    group.measurement_time(Duration::from_secs(30));
    group.sample_size(10);

    // How many measured deposits per warm instance.  After the warm-up
    // deposit (pool[0]), we run up to this many measured deposits using
    // pool[1..=deposits_per_batch].  Each deposit uses a unique nullifier
    // so we must not exceed pool.len() - 1 per instance.
    let deposits_per_batch: u64 = 20;

    group.bench_function("wasmvm_execute_deposit", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            let mut remaining = iters;

            while remaining > 0 {
                // --- create a fresh instance (outside timed region) ---
                let mut instance = instantiated_instance(&wasm);

                // Warm-up deposit (excluded from timing) — primes L1i/L1d
                // and branch predictor for the Bulletproof inner loop.
                // Uses pool[0]; measured deposits use pool[1..].
                call_execute::<MockApi, MockStorage, MockQuerier, Empty>(
                    &mut instance, &env, &info, &pool[0].json,
                )
                .expect("warmup deposit must succeed")
                .into_result()
                .expect("warmup deposit result must be Ok");

                // Measured deposits on this warm instance.
                // Each uses a unique nullifier from pool[1..].
                // Note: across instance boundaries the same pool indices are
                // reused, but each fresh instance has an empty nullifier set,
                // so duplicates across instances are fine.  Within a single
                // instance each index is unique.
                let batch = remaining.min(deposits_per_batch);
                for j in 0..batch {
                    let idx = 1 + (j as usize);  // pool[1], pool[2], ...

                    let start = Instant::now();
                    let res = call_execute::<MockApi, MockStorage, MockQuerier, Empty>(
                        &mut instance, &env, &info, &pool[idx].json,
                    )
                    .expect("deposit must succeed")
                    .into_result()
                    .expect("deposit result must be Ok");
                    total += start.elapsed();
                    black_box(res);
                }
                remaining -= batch;
                // instance drops here — outside the timed region
            }
            total
        })
    });
    group.finish();
}

/// **Benchmark 3: `execute(Transfer)`**
///
/// Measures CW20 token transfer overhead on a **warm** instance.  The VM is
/// instantiated once per batch, seeded with deposits to give the seller
/// tokens, and then reused for many iterations.
///
/// A warm-up transfer is performed before timing begins to prime the TLB
/// and CPU caches.  When tokens are exhausted, a fresh instance is created.
fn bench_transfer(c: &mut Criterion) {
    let wasm = load_wasm();
    // 7 deposits: 1 consumed by warm-up transfer, 5 available for measured iterations,
    // 1 extra headroom.  Each deposit mints 1 CW20 token.
    let pool = generate_deposit_pool(7, "seller");

    // Number of transfer iterations per warm instance before recreating.
    let transfers_per_batch: u64 = 5;

    c.bench_function("wasmvm_execute_transfer", |b| {
        b.iter_custom(|iters| {
            let env = mock_env();
            let seller_info = mock_info("seller", &[]);
            let msg = transfer_msg_json();

            let mut total = Duration::ZERO;
            let mut remaining = iters;

            while remaining > 0 {
                // Create a warm instance with minted tokens
                let mut instance = instantiated_instance(&wasm);
                seed_deposits(&mut instance, &pool, 7, 0);

                // Warm-up call (excluded from timing) — primes TLB & L1/L2
                let warmup_msg = transfer_msg_to_json("warmup_addr");
                call_execute::<MockApi, MockStorage, MockQuerier, Empty>(
                    &mut instance, &env, &seller_info, &warmup_msg,
                )
                .expect("warmup transfer must succeed")
                .into_result()
                .expect("warmup transfer result must be Ok");

                let batch = remaining.min(transfers_per_batch);
                for _ in 0..batch {
                    let start = Instant::now();
                    let res = call_execute::<MockApi, MockStorage, MockQuerier, Empty>(
                        &mut instance, &env, &seller_info, &msg,
                    )
                    .expect("transfer must succeed")
                    .into_result()
                    .expect("transfer result must be Ok");
                    total += start.elapsed();
                    black_box(res);
                }
                remaining -= batch;
            }
            total
        })
    });
}

/// **Benchmark 4: `execute(BurnAndRequest)`**
///
/// Measures Phase 1 of the two-phase oracle flow: CW20 burn + pending request
/// storage + oracle_request event emission.  Each iteration requires fresh
/// contract state (BurnAndRequest rejects duplicate pending requests), so we
/// use `iter_custom` to exclude instance setup and drop from the measurement.
fn bench_burn_and_request(c: &mut Criterion) {
    let wasm = load_wasm();
    let pool = generate_deposit_pool(6, "seller");
    let msg = burn_and_request_msg_json();
    let env = mock_env();
    let buyer_info = mock_info("buyer", &[]);

    c.bench_function("wasmvm_execute_burn_request", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let mut instance = instantiated_instance(&wasm);
                seed_deposits(&mut instance, &pool, 6, 0);
                // Transfer 1 token from seller → buyer
                let xfer = transfer_msg_json();
                let seller_info = mock_info("seller", &[]);
                call_execute::<MockApi, MockStorage, MockQuerier, Empty>(
                    &mut instance, &env, &seller_info, &xfer,
                )
                .expect("transfer setup must succeed")
                .into_result()
                .expect("transfer result must be Ok");

                let start = Instant::now();
                let res = call_execute::<MockApi, MockStorage, MockQuerier, Empty>(
                    &mut instance, &env, &buyer_info, &msg,
                )
                .expect("burn_and_request must succeed")
                .into_result()
                .expect("burn_and_request result must be Ok");
                total += start.elapsed();
                black_box(res);
            }
            total
        })
    });
}

/// **Benchmark 5: `execute(FulfillRandomness)`**
///
/// Measures Phase 2 of the two-phase oracle flow: O(1) swap-and-pop vault
/// selection + payload claim recording.  Each iteration requires fresh state
/// (a pending BurnAndRequest), so `iter_custom` excludes the lifecycle setup.
fn bench_fulfill_randomness(c: &mut Criterion) {
    let wasm = load_wasm();
    let pool = generate_deposit_pool(6, "seller");
    let msg = fulfill_randomness_msg_json();
    let env = mock_env();
    let oracle_info = mock_info("oracle_relayer", &[]);

    c.bench_function("wasmvm_execute_fulfill", |b| {
        b.iter_custom(|iters| {
            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let mut instance = instantiated_instance(&wasm);
                seed_deposits(&mut instance, &pool, 6, 0);
                // Transfer seller → buyer
                let xfer = transfer_msg_json();
                let seller_info = mock_info("seller", &[]);
                call_execute::<MockApi, MockStorage, MockQuerier, Empty>(
                    &mut instance, &env, &seller_info, &xfer,
                )
                .expect("transfer setup must succeed")
                .into_result()
                .expect("transfer result must be Ok");
                // BurnAndRequest (buyer)
                let req = burn_and_request_msg_json();
                let buyer_info = mock_info("buyer", &[]);
                call_execute::<MockApi, MockStorage, MockQuerier, Empty>(
                    &mut instance, &env, &buyer_info, &req,
                )
                .expect("burn_and_request setup must succeed")
                .into_result()
                .expect("burn_and_request result must be Ok");

                let start = Instant::now();
                let res = call_execute::<MockApi, MockStorage, MockQuerier, Empty>(
                    &mut instance, &env, &oracle_info, &msg,
                )
                .expect("fulfill must succeed")
                .into_result()
                .expect("fulfill result must be Ok");
                total += start.elapsed();
                black_box(res);
            }
            total
        })
    });
}

/// **Benchmark 6: `query(ActiveCount)`**
///
/// Measures read-only storage query overhead on a **warm** instance.  Since
/// queries don't mutate state, we create one instance, seed it, and reuse it
/// for all iterations.  A warm-up query primes the caches first.
fn bench_query_active_count(c: &mut Criterion) {
    let wasm = load_wasm();
    let pool = generate_deposit_pool(6, "seller");
    let msg = query_active_count_json();
    let env = mock_env();

    c.bench_function("wasmvm_query_active_count", |b| {
        b.iter_custom(|iters| {
            let mut instance = instantiated_instance(&wasm);
            seed_deposits(&mut instance, &pool, 6, 0);

            // Warm-up query (excluded from timing)
            call_query::<MockApi, MockStorage, MockQuerier>(&mut instance, &env, &msg)
                .expect("warmup query must succeed")
                .into_result()
                .expect("warmup query result must be Ok");

            let mut total = Duration::ZERO;
            for _ in 0..iters {
                let start = Instant::now();
                let res = call_query::<MockApi, MockStorage, MockQuerier>(&mut instance, &env, &msg)
                    .expect("query must succeed")
                    .into_result()
                    .expect("query result must be Ok");
                total += start.elapsed();
                black_box(res);
            }
            total
        })
    });
}

// ---------------------------------------------------------------------------
// Criterion harness
//
// Configuration notes for academic reproducibility:
//   - significance_level = 0.05 → 95% confidence intervals (two-tailed).
//   - noise_threshold = 0.02 → suppress "change" reports for <2% shifts,
//     which is within typical OS scheduling jitter on shared CI runners.
//   - warm_up_time = 5 s → ensures Cranelift JIT, branch predictor, and
//     L1i/L1d caches are fully warmed before Criterion starts sampling.
//     This is especially important for the Deposit benchmark whose
//     Bulletproof inner loop has a large instruction footprint.
//   - configure_from_args() is deliberately NOT used here because it
//     replaces the custom config above; Criterion does not merge the two.
//     To override settings from the command line, modify the config below
//     or use environment variables (CRITERION_HOME, etc.).
// ---------------------------------------------------------------------------

criterion_group! {
    name = wasmvm_benches;
    config = Criterion::default()
        .significance_level(0.05)
        .noise_threshold(0.02)
        .warm_up_time(Duration::from_secs(5));
    targets =
        bench_instantiate,
        bench_deposit,
        bench_transfer,
        bench_burn_and_request,
        bench_fulfill_randomness,
        bench_query_active_count
}

criterion_main!(wasmvm_benches);
