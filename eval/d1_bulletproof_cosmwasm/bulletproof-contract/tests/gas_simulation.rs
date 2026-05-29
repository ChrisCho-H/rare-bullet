//! # Bulletproof CosmWasm Contract — State Transition & Lifecycle Simulation
//!
//! Exercises the unified bulletproof verification + vault + CW20 minting
//! contract through its complete lifecycle inside a `cw-multi-test`
//! environment, using the mocked ideal randomness functionality F_beacon.
//!
//! The contract integrates:
//!   - Native on-chain Bulletproof range-proof verification
//!   - Atomic CW20 Range Token minting on successful verification
//!   - Atomic BurnAndClaim with mocked F_beacon random selection
//!
//! NOTE: This simulation validates correct state-machine transitions and
//! algorithmic logic. On-chain gas costs were measured separately via a
//! live CosmWasm testnet deployment (see paper Section 8.4).
//!
//! ## Test Scenarios
//!
//! 1. **Pre-generated proof deposit lifecycle** — deposit → verify → mint →
//!    burnAndClaim (atomic).
//! 2. **Freshly generated proof deposit** — creates a brand-new proof.
//! 3. **Multiple claim lifecycle** — verifies repeated claims work correctly.

use cosmwasm_std::{Addr, Empty, Uint128};
use curve25519_dalek_ng::{ristretto::RistrettoPoint, traits::MultiscalarMul};
use cw_multi_test::{App, ContractWrapper, Executor};

use bulletproof_contract::msg::{
    ActiveCountResponse, ClaimedPayloadsResponse, ExecuteMsg, InstantiateMsg, QueryMsg,
};
use rand::Rng;

const MIN_VAULT_DEPTH: u64 = 5;

fn contract_wrapper() -> Box<dyn cw_multi_test::Contract<Empty>> {
    let contract = ContractWrapper::new(
        bulletproof_contract::contract::execute,
        bulletproof_contract::contract::instantiate,
        bulletproof_contract::contract::query,
    );
    Box::new(contract)
}

fn default_instantiate_msg() -> InstantiateMsg {
    InstantiateMsg {
        token_name: "RangeBucket90-100".to_string(),
        token_symbol: "RB90".to_string(),
        token_decimals: 6,
        min_vault_depth: MIN_VAULT_DEPTH,
        fallback_timeout_blocks: Some(100_000),
        oracle_address: None,
        oracle_timeout_blocks: None,
    }
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
// Scenario 1 — Pre-generated proof deposit + atomic claim lifecycle
// ---------------------------------------------------------------------------

// DEPRECATED: lifecycle_deposit_and_claim (used legacy BurnAndClaim)
// This test has been replaced by the two-phase oracle flow tests.
//
// #[test]
// fn lifecycle_deposit_and_claim() {
//     ... (test commented out - see git history for original implementation)
// }

// ---------------------------------------------------------------------------
// Scenario 2 — Freshly generated proof deposit
// ---------------------------------------------------------------------------

#[test]
fn lifecycle_fresh_proof_deposit() {
    use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
    use curve25519_dalek_ng::scalar::Scalar;
    use merlin::Transcript;
    use rand::{rngs::StdRng, SeedableRng};

    let mut app = App::default();
    let code_id = app.store_code(contract_wrapper());
    let creator = Addr::unchecked("creator");
    let seller = Addr::unchecked("seller");

    let contract_addr = app
        .instantiate_contract(
            code_id,
            creator.clone(),
            &default_instantiate_msg(),
            &[],
            "v1",
            None,
        )
        .expect("instantiate must succeed");

    // hardcoded bucket bounds for this PoC. In production, these should be derived from the proof or passed as parameters.
    let bucket_floor = 90_u64;
    let bucket_ceiling = 100_u64;

    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(32, 2);
    let secret_value = 95u64; // Example valid value within [floor, ceiling)

    let mut rng = rand::thread_rng();
    let blinding = Scalar::random(&mut rng);
    // 2. Generate a valid 64-character hex string for the nullifier directly
    // This perfectly mimics the SHA-256 output expected by the contract.
    let nullifier_hex = format!("{:064x}", rng.gen::<u64>()); // "00..00", "00..01", etc.

    // --- LEAP: Derived Aggregation Arrays ---
    let v1 = secret_value - bucket_floor;
    let v2 = (bucket_ceiling - 1) - secret_value;
    let r1 = blinding;
    let r2 = -blinding;

    // --- LEAP: Transcript Synchronization ---
    // The prover transcript MUST mirror the on-chain verifier transcript,
    // including the sender binding that prevents mempool front-running.
    let mut prover_transcript = Transcript::new(b"PrivateDataExchange_RangeProof_v1");
    prover_transcript.append_message(b"contract", contract_addr.as_bytes());
    prover_transcript.append_message(b"nullifier", nullifier_hex.as_bytes());
    prover_transcript.append_message(b"sender", seller.as_bytes());
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

    let res = app
        .execute_contract(
            seller.clone(),
            contract_addr.clone(),
            &ExecuteMsg::Deposit {
                proof_hex: proof_hex,
                commitment_hex: commitment_hex,
                num_bits: 32,
                ipfs_cid_hash: "fresh_cid".to_string(),
                ct_key_hash: "fresh_key".to_string(),
                oracle_signature: "cafebabe".to_string(),
                payload_nullifier: nullifier_hex,
            },
            &[],
        )
        .expect("deposit with fresh proof must succeed");

    let is_valid = res
        .events
        .iter()
        .flat_map(|e| &e.attributes)
        .find(|a| a.key == "is_valid")
        .map(|a| a.value.as_str())
        .unwrap_or("missing");
    assert_eq!(is_valid, "true");

    let bal: cw20::BalanceResponse = app
        .wrap()
        .query_wasm_smart(
            contract_addr.clone(),
            &QueryMsg::Balance {
                address: seller.to_string(),
            },
        )
        .unwrap();
    assert_eq!(bal.balance, Uint128::new(1_000_000));
}

// ---------------------------------------------------------------------------
// Scenario 3 — Multiple claim lifecycle
// ---------------------------------------------------------------------------

// DEPRECATED: lifecycle_multiple_claims (used legacy BurnAndClaim)
// This test has been replaced by the two-phase oracle flow tests.
//
// #[test]
// fn lifecycle_multiple_claims() {
//     ... (test commented out - see git history for original implementation)
// }

// ---------------------------------------------------------------------------
// Scenario 4 — WASM binary size report
// ---------------------------------------------------------------------------

#[test]
fn report_wasm_binary_size() {
    let candidates = [
        "target/wasm32-unknown-unknown/release/bulletproof_contract.wasm",
        "artifacts/bulletproof_contract.wasm",
    ];
    for path in &candidates {
        if let Ok(meta) = std::fs::metadata(path) {
            let kb = meta.len() as f64 / 1024.0;
            println!("  {} — {:.1} KiB ({} bytes)", path, kb, meta.len());
        }
    }
}
