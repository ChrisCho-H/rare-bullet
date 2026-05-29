//! # End-to-End Experiment: Unified CosmWasm Contract with Mocked F_beacon
//!
//! This test module provides provable, reproducible measurements of the full
//! Rare Bullet protocol lifecycle implemented as a single CosmWasm smart
//! contract, using a mocked ideal randomness functionality (F_beacon) in
//! place of a production VRF / TEE threshold committee.
//!
//! ## State Transition & Lifecycle Simulation
//!
//! 1. **Instantiate** — deploy contract with CW20 token config
//! 2. **Deposit (×N)** — native Bulletproof verification + atomic CW20 mint + vault store
//! 3. **CW20 Transfer** — standard token transfer (AMM composability proof)
//! 4. **BurnAndClaim** — CW20 burn + mocked F_beacon random selection + vault claim
//!
//! ## Reproducibility
//!
//! All measurements use deterministic inputs (pre-generated Bulletproof proof).
//! Wall-clock timings are CPU-bound and reflect algorithmic execution cost;
//! on-chain gas costs were measured separately via a live CosmWasm testnet
//! deployment (see Section 8.4 of the accompanying paper).

use cosmwasm_std::{Addr, Empty, Uint128};
use curve25519_dalek_ng::{ristretto::RistrettoPoint, traits::MultiscalarMul};
use cw_multi_test::{App, ContractWrapper, Executor};

use bulletproof_contract::msg::{
    ActiveCountResponse, ClaimedPayloadsResponse, ExecuteMsg, InstantiateMsg, QueryMsg,
};
use rand::Rng;

// ---------------------------------------------------------------------------
// Test data
// ---------------------------------------------------------------------------

const MIN_VAULT_DEPTH: u64 = 5;

fn contract_wrapper() -> Box<dyn cw_multi_test::Contract<Empty>> {
    Box::new(ContractWrapper::new(
        bulletproof_contract::contract::execute,
        bulletproof_contract::contract::instantiate,
        bulletproof_contract::contract::query,
    ))
}

fn deposit_one(app: &mut App, contract: &Addr, sender: &Addr, idx: u64) {
    use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
    use curve25519_dalek_ng::scalar::Scalar;
    use merlin::Transcript;
    use rand::{rngs::StdRng, SeedableRng};

    // hardcoded bucket bounds for this PoC. In production, these should be derived from the proof or passed as parameters.
    let bucket_floor = 90_u64;
    let bucket_ceiling = 100_u64;
    let secret_value = 95u64; // Example valid value within [floor, ceiling)

    // 1. Use a deterministic RNG seeded by the deposit index
    let mut rng = StdRng::seed_from_u64(idx);

    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(32, 2);
    let blinding = Scalar::random(&mut rng);

    // --- LEAP: Derived Aggregation Arrays ---
    let v1 = secret_value - bucket_floor;
    let v2 = (bucket_ceiling - 1) - secret_value;
    let r1 = blinding;
    let r2 = -blinding;

    // 2. Generate a valid 64-character hex string for the nullifier directly
    // This perfectly mimics the SHA-256 output expected by the contract.
    let nullifier_hex = format!("{:064x}", idx); // "00..00", "00..01", etc.

    let mut prover_transcript = Transcript::new(b"PrivateDataExchange_RangeProof_v1");

    // 3. Bind the exact string bytes that the contract will see.
    //    The `sender` binding mirrors the on-chain verifier and prevents
    //    mempool front-running of the (proof, commitment, nullifier) tuple.
    prover_transcript.append_message(b"contract", contract.as_bytes());
    prover_transcript.append_message(b"nullifier", nullifier_hex.as_bytes());
    prover_transcript.append_message(b"sender", sender.as_bytes());
    prover_transcript.append_u64(b"floor", bucket_floor);
    prover_transcript.append_u64(b"ceiling", bucket_ceiling);

    // --- LEAP: Aggregated Proof Generation ---
    // Note: Standard dalek uses `prove_multiple` directly with slices.
    let (proof, _shifted_commitments) = RangeProof::prove_multiple_with_rng(
        &bp_gens,
        &pc_gens,
        &mut prover_transcript,
        &[v1, v2],
        &[r1, r2],
        32,
        &mut rng,
    )
    .unwrap();

    // --- LEAP: Original Commitment Reconstruction ---
    // The contract expects the raw/unshifted commitment to perform the homomorphic
    // shifts on-chain. We calculate C = (secret_value * G) + (blinding * H) manually.
    let raw_commitment = RistrettoPoint::multiscalar_mul(
        &[Scalar::from(secret_value), blinding],
        &[pc_gens.B, pc_gens.B_blinding],
    )
    .compress();
    let proof_hex = hex::encode(proof.to_bytes());
    let commitment_hex = hex::encode(raw_commitment.to_bytes());

    app.execute_contract(
        sender.clone(),
        contract.clone(),
        &ExecuteMsg::Deposit {
            proof_hex: proof_hex,
            commitment_hex: commitment_hex,
            num_bits: 32,
            ipfs_cid_hash: format!("QmCID_{}", idx),
            ct_key_hash: format!("CtKey_{}", idx),
            oracle_signature: "deadbeef".to_string(),
            payload_nullifier: nullifier_hex, // Pass the exact hex string
        },
        &[],
    )
    .expect("deposit must succeed");
}

// ---------------------------------------------------------------------------
// E2E Experiment — Full Lifecycle with Mocked F_beacon Randomness
// ---------------------------------------------------------------------------

// DEPRECATED: e2e_full_lifecycle_experiment (used legacy BurnAndClaim)
// This test has been replaced by e2e_two_phase_oracle_lifecycle which tests
// the production-ready asynchronous two-phase oracle flow.
//
// #[test]
// fn e2e_full_lifecycle_experiment() {
//     ... (test commented out - see git history for original implementation)
// }

// ---------------------------------------------------------------------------
// E2E Experiment — Two-Phase Asynchronous Oracle Flow
// ---------------------------------------------------------------------------

#[test]
fn e2e_two_phase_oracle_lifecycle() {
    println!("\n{}", "=".repeat(72));
    println!("  Two-Phase Asynchronous Oracle Flow: Simulated Relayer Bot");
    println!("{}\n", "=".repeat(72));

    let mut app = App::default();
    let code_id = app.store_code(contract_wrapper());
    let creator = Addr::unchecked("creator");
    let seller = Addr::unchecked("seller");
    let buyer = Addr::unchecked("buyer");
    let oracle = Addr::unchecked("oracle_relayer");

    // ── 1. Instantiate with oracle address ─────────────────────────────
    let t0 = std::time::Instant::now();
    let contract = app
        .instantiate_contract(
            code_id,
            creator.clone(),
            &InstantiateMsg {
                token_name: "RangeBucket90-100".into(),
                token_symbol: "RB90".into(),
                token_decimals: 6,
                min_vault_depth: MIN_VAULT_DEPTH,
                fallback_timeout_blocks: Some(100_000),
                oracle_address: Some("oracle_relayer".into()),
                oracle_timeout_blocks: Some(50),
            },
            &[],
            "rare-bullet-oracle-e2e",
            None,
        )
        .unwrap();
    let t_inst = t0.elapsed();
    println!("  [1] instantiate (w/ oracle) {:>10.3?}", t_inst);

    // ── 2. Deposit ×6 ──────────────────────────────────────────────────
    let num_deposits = MIN_VAULT_DEPTH + 1;
    let t1 = std::time::Instant::now();
    for i in 0..num_deposits {
        deposit_one(&mut app, &contract, &seller, i);
    }
    let t_dep = t1.elapsed();
    println!(
        "  [2] deposit x{}            {:>10.3?}",
        num_deposits, t_dep
    );

    // ── 3. CW20 Transfer (seller → buyer) ──────────────────────────────
    let t2 = std::time::Instant::now();
    app.execute_contract(
        seller.clone(),
        contract.clone(),
        &ExecuteMsg::Transfer {
            recipient: buyer.to_string(),
            amount: Uint128::new(1_000_000),
        },
        &[],
    )
    .unwrap();
    let t_xfer = t2.elapsed();
    println!("  [3] CW20 transfer        {:>10.3?}", t_xfer);

    // ── 4. Phase 1: BurnAndRequest (buyer) ─────────────────────────────
    let t3 = std::time::Instant::now();
    let request_res = app
        .execute_contract(
            buyer.clone(),
            contract.clone(),
            &ExecuteMsg::BurnAndRequest {
                buyer_x25519_pubkey: "aa".repeat(32),
            },
            &[],
        )
        .unwrap();
    let t_request = t3.elapsed();

    let action = request_res
        .events
        .iter()
        .flat_map(|e| &e.attributes)
        .find(|a| a.key == "action")
        .map(|a| a.value.clone())
        .unwrap();
    assert_eq!(action, "burn_and_request");

    // Verify oracle_request event was emitted.
    let has_oracle_event = request_res
        .events
        .iter()
        .any(|e| e.ty.contains("oracle_request"));
    assert!(has_oracle_event, "oracle_request event must be emitted");

    println!("  [4] BurnAndRequest       {:>10.3?}", t_request);

    // Verify token was burned.
    let buyer_bal: cw20::BalanceResponse = app
        .wrap()
        .query_wasm_smart(
            contract.clone(),
            &QueryMsg::Balance {
                address: buyer.to_string(),
            },
        )
        .unwrap();
    assert_eq!(buyer_bal.balance, Uint128::zero());
    println!("      buyer CW20 after burn = {}", buyer_bal.balance);

    // Verify pending request exists.
    let pending: bulletproof_contract::msg::PendingRequestResponse = app
        .wrap()
        .query_wasm_smart(
            contract.clone(),
            &QueryMsg::GetPendingRequest {
                buyer: buyer.to_string(),
            },
        )
        .unwrap();
    assert!(pending.found);
    println!(
        "      pending request: bucket_id={}, height={}",
        pending.range_bucket_id.unwrap(),
        pending.request_height.unwrap()
    );

    // ── 5. Phase 2: FulfillRandomness (oracle relayer) ─────────────────
    let t4 = std::time::Instant::now();
    let fulfill_res = app
        .execute_contract(
            oracle.clone(),
            contract.clone(),
            &ExecuteMsg::FulfillRandomness {
                buyer_address: buyer.to_string(),
                random_seed: "12345678901234".to_string(),
            },
            &[],
        )
        .unwrap();
    let t_fulfill = t4.elapsed();

    let payload_index = fulfill_res
        .events
        .iter()
        .flat_map(|e| &e.attributes)
        .find(|a| a.key == "payload_index")
        .map(|a| a.value.clone())
        .unwrap();
    println!(
        "  [5] FulfillRandomness    {:>10.3?}   payload_index={}",
        t_fulfill, payload_index
    );

    // ── 6. Verify final state consistency ──────────────────────────────
    let active: ActiveCountResponse = app
        .wrap()
        .query_wasm_smart(contract.clone(), &QueryMsg::ActiveCount {})
        .unwrap();
    assert_eq!(active.count, num_deposits - 1);
    println!(
        "      active vault entries = {} (one claimed)",
        active.count
    );

    let claimed: ClaimedPayloadsResponse = app
        .wrap()
        .query_wasm_smart(
            contract.clone(),
            &QueryMsg::GetClaimedPayloads {
                buyer: buyer.to_string(),
            },
        )
        .unwrap();
    assert_eq!(claimed.payload_indices.len(), 1);
    println!(
        "      buyer claimed indices = {:?}",
        claimed.payload_indices
    );

    // Verify pending request was consumed.
    let pending: bulletproof_contract::msg::PendingRequestResponse = app
        .wrap()
        .query_wasm_smart(
            contract.clone(),
            &QueryMsg::GetPendingRequest {
                buyer: buyer.to_string(),
            },
        )
        .unwrap();
    assert!(!pending.found);
    println!("      pending request consumed = true");

    // ── Summary ────────────────────────────────────────────────────────
    let total = t_inst + t_dep + t_xfer + t_request + t_fulfill;
    println!("\n{}", "-".repeat(72));
    println!("  TWO-PHASE ORACLE FLOW SUMMARY");
    println!("  (cw-multi-test: validates correctness, not gas metering)");
    println!("{}", "-".repeat(72));
    println!("  instantiate (w/ oracle)  {:>10.3?}", t_inst);
    println!("  deposit x{}              {:>10.3?}", num_deposits, t_dep);
    println!("  CW20 transfer            {:>10.3?}", t_xfer);
    println!("  Phase 1: BurnAndRequest  {:>10.3?}", t_request);
    println!("  Phase 2: FulfillRandomn. {:>10.3?}", t_fulfill);
    println!("  total                    {:>10.3?}", total);
    println!("{}", "-".repeat(72));
    println!("  Architecture: two-phase oracle-driven claim");
    println!("  Randomness: off-chain relayer bot (crypto.randomBytes)");
    println!("  Phase 1: burn → emit oracle_request (single tx)");
    println!("  Phase 2: oracle fulfills → O(1) swap-and-pop (single tx)");
    println!("{}\n", "=".repeat(72));
}
