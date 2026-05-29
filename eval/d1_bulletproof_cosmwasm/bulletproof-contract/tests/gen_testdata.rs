//! # Test Data Generator for wasmd Benchmark & Gas Estimation
//!
//! Generates JSON-encoded CosmWasm execute messages (Deposit, BurnAndClaim,
//! Transfer) and writes them to `test_tx_data/` for consumption by the
//! benchmark scripts (`setup_singlenode_bench.sh`, `wasmd_gas_estimate.sh`).
//!
//! ## Benchmark mode (when `NUM_LOAD_ACCOUNTS` and `NUM_BURSTS` are set)
//!
//! Generates one unique (proof, commitment, nullifier) tuple per transaction:
//!
//!   deposit_b{burst}_u{user}.json   (e.g. deposit_b1_u42.json)
//!
//! The nullifiers are deterministic SHA-256 hashes matching the pattern used
//! by the benchmark script:
//!
//!   SHA256("singlenode-bench-b{burst}-u{user}")
//!
//! This ensures the Merlin transcript binds each proof to the exact nullifier
//! used on-chain, preventing verification failures from transcript mismatch.
//!
//! ## Legacy mode (fallback, when env vars are absent)
//!
//! Generates 7 deposit files (`deposit_0.json` through `deposit_6.json`) for
//! backward compatibility with the gas estimation script.
//!
//! Run: `cargo test --test gen_testdata -- --nocapture --ignored`

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::ristretto::RistrettoPoint;
use curve25519_dalek_ng::scalar::Scalar;
use curve25519_dalek_ng::traits::MultiscalarMul;
use merlin::Transcript;
use rand::{CryptoRng, Rng};
use sha2::{Digest, Sha256};
use std::fs;

#[test]
#[ignore] // Run explicitly: cargo test --test gen_testdata -- --ignored --nocapture
fn generate_wasmd_test_data() {
    let out_dir = std::path::Path::new("test_tx_data");
    fs::create_dir_all(out_dir).expect("create output dir");

    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(32, 2); // m=2 aggregated proof
    let mut rng = rand::thread_rng();

    // Allow the bash script to pass the real contract address in.
    // If running locally, defaults to a placeholder so the JSON still generates.
    let contract_addr =
        std::env::var("CONTRACT_ADDR").unwrap_or_else(|_| "cosmos2contract".to_string());

    // ── Sender binding: load per-user bech32 addresses ────────────────
    // The on-chain verifier binds `info.sender` into the Bulletproof Merlin
    // transcript to defeat mempool front-running. The prover therefore needs
    // to know the sender bech32 address that will broadcast each transaction.
    //
    //   * Benchmark mode: `LOAD_USER_ADDRS_FILE` is a path to a file with one
    //     "{user_idx} {bech32_addr}" pair per line. The companion shell script
    //     (`setup_singlenode_bench.sh`) writes this file from `LOAD_ADDRS[]`
    //     immediately before invoking this generator.
    //   * Legacy mode: `SENDER_ADDR` overrides the single-sender used for all
    //     deposit_*.json files (defaults to a placeholder).
    let load_user_addrs: std::collections::HashMap<u64, String> =
        match std::env::var("LOAD_USER_ADDRS_FILE") {
            Ok(path) if !path.is_empty() => {
                let content = fs::read_to_string(&path)
                    .expect("LOAD_USER_ADDRS_FILE must be readable");
                content
                    .lines()
                    .filter_map(|line| {
                        let mut it = line.split_whitespace();
                        let idx = it.next()?.parse::<u64>().ok()?;
                        let addr = it.next()?.to_string();
                        Some((idx, addr))
                    })
                    .collect()
            }
            _ => std::collections::HashMap::new(),
        };
    let default_sender =
        std::env::var("SENDER_ADDR").unwrap_or_else(|_| "cosmos2sender".to_string());

    // Hardcoded bucket bounds matching the on-chain contract.
    let bucket_floor = 90_u64;
    let bucket_ceiling = 100_u64;
    let secret_value = 95_u64;

    println!("Generating proofs bound to contract: {}", contract_addr);
    println!(
        "  Bucket: [{}, {}), secret_value: {}",
        bucket_floor, bucket_ceiling, secret_value
    );
    if !load_user_addrs.is_empty() {
        println!("  Loaded {} per-user sender addresses", load_user_addrs.len());
    } else {
        println!("  Default sender (legacy/single mode): {}", default_sender);
    }

    // ── Determine generation mode ─────────────────────────────────────
    let num_accounts: u64 = std::env::var("NUM_LOAD_ACCOUNTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);
    let num_bursts: u64 = std::env::var("NUM_BURSTS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    if num_accounts > 0 && num_bursts > 0 {
        // ── Benchmark mode: one unique proof per (burst, user) ────────
        let total = num_accounts * num_bursts;
        println!(
            "  Benchmark mode: {} accounts × {} bursts = {} unique proofs",
            num_accounts, num_bursts, total
        );

        for burst in 1..=num_bursts {
            for user in 1..=num_accounts {
                let sender = load_user_addrs
                    .get(&user)
                    .cloned()
                    .unwrap_or_else(|| default_sender.clone());
                let deposit_msg = generate_single_deposit(
                    &pc_gens,
                    &bp_gens,
                    &mut rng,
                    &contract_addr,
                    &sender,
                    bucket_floor,
                    bucket_ceiling,
                    secret_value,
                    burst,
                    user,
                );
                let path = out_dir.join(format!("deposit_b{}_u{}.json", burst, user));
                fs::write(&path, serde_json::to_string_pretty(&deposit_msg).unwrap())
                    .expect("write deposit json");
            }
            // Progress indicator every burst.
            println!(
                "  Burst {}/{}: {} deposit files written",
                burst, num_bursts, num_accounts
            );
        }
    } else {
        // ── Legacy mode: 7 deposit files for gas estimation ───────────
        println!("  Legacy mode: generating 7 deposit files");
        for i in 0..7u64 {
            let nullifier_hex = format!("{:064x}", i);
            let deposit_msg = generate_deposit_with_nullifier(
                &pc_gens,
                &bp_gens,
                &mut rng,
                &contract_addr,
                &default_sender,
                bucket_floor,
                bucket_ceiling,
                secret_value,
                &nullifier_hex,
                0, i, // legacy mode: burst=0, user=i
            );
            let path = out_dir.join(format!("deposit_{}.json", i));
            fs::write(&path, serde_json::to_string_pretty(&deposit_msg).unwrap())
                .expect("write deposit json");
            println!("  wrote {}", path.display());
        }
    }

    // ── Non-deposit messages (always generated) ───────────────────────
    write_support_messages(out_dir);
    println!("\n  All test data written to {}/", out_dir.display());
}

/// Generate a deposit message for benchmark mode.
/// The nullifier is deterministically derived as SHA256("singlenode-bench-b{burst}-u{user}")
/// to match the benchmark script's expectations.
fn generate_single_deposit(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    rng: &mut (impl Rng + CryptoRng),
    contract_addr: &str,
    sender_addr: &str,
    bucket_floor: u64,
    bucket_ceiling: u64,
    secret_value: u64,
    burst: u64,
    user: u64,
) -> serde_json::Value {
    // Deterministic nullifier matching the benchmark script pattern.
    // This must be refreshed everytime if used in testnet e2e test like hippod-send-tx.sh
    let seed = format!("singlenode-bench-b{}-u{}", burst, user);
    let nullifier_hex = hex::encode(Sha256::digest(seed.as_bytes()));

    generate_deposit_with_nullifier(
        pc_gens,
        bp_gens,
        rng,
        contract_addr,
        sender_addr,
        bucket_floor,
        bucket_ceiling,
        secret_value,
        &nullifier_hex,
        burst, user,
    )
}

/// Generate a single deposit message with the given nullifier.
fn generate_deposit_with_nullifier(
    pc_gens: &PedersenGens,
    bp_gens: &BulletproofGens,
    rng: &mut (impl Rng + CryptoRng),
    contract_addr: &str,
    sender_addr: &str,
    bucket_floor: u64,
    bucket_ceiling: u64,
    secret_value: u64,
    nullifier_hex: &str,
    id_burst: u64,
    id_user: u64,
) -> serde_json::Value {
    let blinding = Scalar::random(rng);

    // Derived values for the two-sided boundary constraint.
    // v1 proves (secret_value - floor) >= 0     (lower bound)
    // v2 proves ((ceiling-1) - secret_value) >= 0 (upper bound)
    let v1 = secret_value - bucket_floor;
    let v2 = (bucket_ceiling - 1) - secret_value;
    let r1 = blinding;
    let r2 = -blinding; // negated so C2 blinding cancels

    // Transcript must exactly mirror the on-chain verifier's transcript,
    // including the sender binding that defeats mempool front-running.
    let mut prover_transcript = Transcript::new(b"PrivateDataExchange_RangeProof_v1");
    prover_transcript.append_message(b"contract", contract_addr.as_bytes());
    prover_transcript.append_message(b"nullifier", nullifier_hex.as_bytes());
    prover_transcript.append_message(b"sender", sender_addr.as_bytes());
    prover_transcript.append_u64(b"floor", bucket_floor);
    prover_transcript.append_u64(b"ceiling", bucket_ceiling);

    // Aggregated proof generation (m=2 values).
    let (proof, _shifted_commitments) = RangeProof::prove_multiple_with_rng(
        bp_gens,
        pc_gens,
        &mut prover_transcript,
        &[v1, v2],
        &[r1, r2],
        32,
        rng,
    )
    .expect("aggregated proof generation must succeed");

    // Reconstruct the raw/unshifted commitment: C = secret_value*G + blinding*H.
    // The on-chain verifier derives C1 and C2 from this via homomorphic shifts.
    let raw_commitment = RistrettoPoint::multiscalar_mul(
        &[Scalar::from(secret_value), blinding],
        &[pc_gens.B, pc_gens.B_blinding],
    )
    .compress();

    let proof_hex = hex::encode(proof.to_bytes());
    let commitment_hex = hex::encode(raw_commitment.to_bytes());

    serde_json::json!({
        "deposit": {
            "proof_hex": proof_hex,
            "commitment_hex": commitment_hex,
            "num_bits": 32,
            "ipfs_cid_hash": format!("QmCID_b{}_u{}", id_burst, id_user),
            "ct_key_hash": format!("CtKey_b{}_u{}", id_burst, id_user),
            "oracle_signature": "deadbeef",
            "payload_nullifier": nullifier_hex
        }
    })
}

/// Write non-deposit support messages (instantiate, burn_and_request, etc.).
fn write_support_messages(out_dir: &std::path::Path) {
    // Instantiate message.
    // oracle_address is intentionally omitted; the shell script injects the
    // real oracle bech32 address dynamically via python3.
    let init_msg = serde_json::json!({
        "token_name": "RangeBucket90-100",
        "token_symbol": "RB90",
        "token_decimals": 6,
        "min_vault_depth": 5,
        "fallback_timeout_blocks": 100000
    });
    let path = out_dir.join("instantiate.json");
    fs::write(&path, serde_json::to_string_pretty(&init_msg).unwrap())
        .expect("write instantiate json");
    println!("  wrote {}", path.display());

    // BurnAndRequest message (Phase 1 of two-phase oracle flow).
    let request_msg = serde_json::json!({
        "burn_and_request": {
            "buyer_x25519_pubkey": "aa".repeat(32)
        }
    });
    let path = out_dir.join("burn_and_request.json");
    fs::write(&path, serde_json::to_string_pretty(&request_msg).unwrap())
        .expect("write burn_and_request json");
    println!("  wrote {}", path.display());

    // FulfillRandomness message (Phase 2 of two-phase oracle flow).
    let fulfill_msg = serde_json::json!({
        "fulfill_randomness": {
            "buyer_address": "BUYER_ADDR_PLACEHOLDER",
            "random_seed": "12345678901234"
        }
    });
    let path = out_dir.join("fulfill_randomness.json");
    fs::write(&path, serde_json::to_string_pretty(&fulfill_msg).unwrap())
        .expect("write fulfill_randomness json");
    println!("  wrote {}", path.display());

    // CW20 Transfer message.
    let transfer_msg = serde_json::json!({
        "transfer": {
            "recipient": "BUYER_ADDR_PLACEHOLDER",
            "amount": "1000000"
        }
    });
    let path = out_dir.join("transfer.json");
    fs::write(&path, serde_json::to_string_pretty(&transfer_msg).unwrap())
        .expect("write transfer json");
    println!("  wrote {}", path.display());

    // Query messages.
    let queries = vec![
        ("active_count", serde_json::json!({"active_count": {}})),
        ("get_config", serde_json::json!({"get_config": {}})),
        ("token_info", serde_json::json!({"token_info": {}})),
    ];
    for (name, msg) in queries {
        let path = out_dir.join(format!("query_{}.json", name));
        fs::write(&path, serde_json::to_string_pretty(&msg).unwrap()).expect("write query json");
        println!("  wrote {}", path.display());
    }
}
