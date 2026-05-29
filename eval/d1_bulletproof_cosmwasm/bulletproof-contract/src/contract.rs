#[cfg(not(feature = "library"))]
use cosmwasm_std::entry_point;
use cosmwasm_std::{
    to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult, Uint128,
};
use curve25519_dalek_ng::scalar::Scalar;

use crate::error::ContractError;
use crate::msg::{
    ActiveCountResponse, ClaimedPayloadsResponse, ConfigResponse, ExecuteMsg, InstantiateMsg,
    PendingRequestResponse, QueryMsg, VaultEntryResponse,
};
use crate::state::{
    Config, Payload, PendingRequest, ACTIVE_PAYLOAD_COUNT, ACTIVE_PAYLOAD_MAP, CLAIMED_PAYLOADS,
    CONFIG, ORACLE_ADDRESS, PENDING_REQUESTS, STARVATION_START_HEIGHT, USED_COMMITMENTS,
    USED_NULLIFIERS, VAULT, VAULT_COUNT,
};

use bulletproofs::{BulletproofGens, PedersenGens, RangeProof};
use curve25519_dalek_ng::ristretto::CompressedRistretto;
use merlin::Transcript;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Digest, Sha256};

// CW20 integration via cw20-base library feature.
use cw20_base::contract as cw20_contract;
use cw20_base::state::{MinterData, TokenInfo, TOKEN_INFO};

// Lazy statics for expensive-to-construct generators. These are thread-safe and
use once_cell::sync::Lazy;

/// Amount of CW20 tokens representing one Data-Backed Range Token (1_000_000 with 6 decimals).
const ONE_TOKEN: u128 = 1_000_000;

// These are calculated exactly ONCE and cached in the Wasm memory
static PC_GENS: Lazy<PedersenGens> = Lazy::new(|| PedersenGens::default());
static BP_GENS_32: Lazy<BulletproofGens> = Lazy::new(|| BulletproofGens::new(32, 2));

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute SHA-256 hash of bytes and return hex string.
fn compute_hash(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

fn verify_bulletproof(
    proof_bytes: &[u8],
    commitment_bytes: &[u8],
    num_bits: u32,
    bucket_floor: u64,   // a_k
    bucket_ceiling: u64, // b_k
    env_contract_address: &str,
    payload_nullifier: &str,
    sender: &str,
) -> Result<bool, ContractError> {
    // Use the references directly. This takes 0.001ms instead of 15ms!
    let pc_gens: &PedersenGens = &*PC_GENS;
    let bp_gens: &BulletproofGens = &*BP_GENS_32;

    let proof = RangeProof::from_bytes(proof_bytes).map_err(|e| ContractError::InvalidProof {
        reason: format!("failed to deserialize proof: {:?}", e),
    })?;

    let raw_commitment = CompressedRistretto::from_slice(commitment_bytes);
    let c_point = raw_commitment
        .decompress()
        .ok_or(ContractError::InvalidProof {
            reason: "Failed to decompress commitment".to_string(),
        })?;

    // --- HOMOMORPHIC SHIFTING (2×32-bit dynamic boundaries) ---
    // Aggregated (m=2) Bulletproof verification over 64 total bits:
    // 1. Lower Bound: C1 = C - (floor * G)
    let floor_point = pc_gens.B * Scalar::from(bucket_floor);
    let c1_point = c_point - floor_point;

    // 2. Upper Bound: C2 = ((ceiling - 1) * G) - C
    let ceiling_point = pc_gens.B * Scalar::from(bucket_ceiling - 1);
    let c2_point = ceiling_point - c_point;

    let c1 = c1_point.compress();
    let c2 = c2_point.compress();

    // --- TRANSCRIPTS ---
    let mut verifier_transcript = Transcript::new(b"PrivateDataExchange_RangeProof_v1");

    // Bind context to prevent replay attacks.
    // DO NOT append the proof here. The library will do it internally.
    verifier_transcript.append_message(b"contract", env_contract_address.as_bytes());
    verifier_transcript.append_message(b"nullifier", payload_nullifier.as_bytes());
    // Bind the transaction sender to defeat mempool front-running: an MEV
    // searcher who copies (proof, commitment, nullifier, oracle_sig) cannot
    // reuse them, because re-broadcasting under their own address derives a
    // distinct Fiat--Shamir challenge and the verifier rejects.
    verifier_transcript.append_message(b"sender", sender.as_bytes());
    // Domain Separation for boundaries
    verifier_transcript.append_u64(b"floor", bucket_floor);
    verifier_transcript.append_u64(b"ceiling", bucket_ceiling);

    // ==========================================
    // TRANSCRIPT 2: THE SECURE RNG TRANSCRIPT
    // ==========================================
    // This transcript exists SOLELY to generate secure Wasm randomness.
    let mut rng_transcript = Transcript::new(b"PrivateDataExchange_RNG_v1");

    // Absorb the public context
    rng_transcript.append_message(b"contract", env_contract_address.as_bytes());
    rng_transcript.append_message(b"nullifier", payload_nullifier.as_bytes());
    rng_transcript.append_message(b"sender", sender.as_bytes());

    // THE CRITICAL FIX: Absorb the proof and commitment into the RNG transcript.
    // Because this is a separate transcript, it won't break the library's verification state.
    rng_transcript.append_message(b"proof", proof_bytes);
    rng_transcript.append_message(b"commitment", commitment_bytes);

    // Build the secure RNG from the proof-bound transcript
    let mut dummy_rng = ChaCha20Rng::from_seed([0u8; 32]);
    let mut secure_transcript_rng = rng_transcript.build_rng().finalize(&mut dummy_rng);

    // --- AGGREGATED (m=2) BULLETPROOF VERIFICATION (64 total bits) ---
    // Pass verify_multiple with our two derived commitments (2×32-bit boundaries)
    Ok(proof
        .verify_multiple_with_rng(
            &bp_gens,
            &pc_gens,
            &mut verifier_transcript,
            &[c1, c2], // Array of derived commitments
            num_bits as usize,
            &mut secure_transcript_rng,
        )
        .is_ok())
}

/// Internal helper: mint ONE_TOKEN (Data-Backed Range Token) to `recipient`. The contract is the minter.
fn mint_cw20(deps: &mut DepsMut, env: &Env, recipient: &str) -> Result<(), ContractError> {
    let mint_info = MessageInfo {
        sender: env.contract.address.clone(),
        funds: vec![],
    };
    cw20_contract::execute_mint(
        deps.branch(),
        env.clone(),
        mint_info,
        recipient.to_string(),
        Uint128::new(ONE_TOKEN),
    )
    .map_err(ContractError::from)?;
    Ok(())
}

// ╔═══════════════════════════════════════════════════════════════════════╗
// ║                                                                       ║
// ║   ██  ORACLE SIGNATURE VERIFICATION (Semantic Binding)            ██  ║
// ║                                                                       ║
// ║   THIS IS A **MOCK / STUB** IMPLEMENTATION OF THE ORACLE SIGNATURE    ║
// ║   VERIFICATION FOR THE ACADEMIC PROOF-OF-CONCEPT.                     ║
// ║                                                                       ║
// ║   CONCEPTUAL VERIFICATION:                                            ║
// ║     verify(oracle_pubkey,                                              ║
// ║            SHA256(ipfs_cid_hash || commitment_hex || nullifier),       ║
// ║            oracle_signature) == true                                   ║
// ║                                                                       ║
// ║   The oracle (e.g., a DECO TLS oracle or TEE-attested ingestion       ║
// ║   service) signs a digest binding the data payload identifier          ║
// ║   (ipfs_cid_hash), the ZK commitment (commitment_hex), and the        ║
// ║   payload nullifier. Without this attestation, a malicious seller      ║
// ║   could encrypt garbage data, generate a valid Bulletproof for an      ║
// ║   arbitrary score, or supply a fabricated nullifier to bypass the      ║
// ║   Sybil resistance check—flooding the AMM pool with worthless tokens. ║
// ║                                                                       ║
// ║   IN A PRODUCTION DEPLOYMENT:                                         ║
// ║     1. Store the oracle's Ed25519/secp256k1 public key on-chain       ║
// ║        (in contract state or governance).                              ║
// ║     2. Reconstruct the message:                                        ║
// ║        msg = SHA256(ipfs_cid_hash || C_hex || nullifier).              ║
// ║     3. Call cosmwasm_std::ed25519_verify (or secp256k1_verify) to     ║
// ║        cryptographically verify the signature.                        ║
// ║     4. Reject deposits with invalid or missing attestations.          ║
// ║                                                                       ║
// ║   FOR THIS PoC: We accept any non-empty signature string to allow     ║
// ║   the evaluation pipeline to exercise the full deposit flow without   ║
// ║   deploying a live oracle. The check below ensures the parameter is   ║
// ║   structurally present and hex-decodable, documenting the exact       ║
// ║   location where production verification logic must be inserted.      ║
// ╚═══════════════════════════════════════════════════════════════════════╝
/// **MOCK** — Verify the oracle's attestation signature binding the data
/// payload, ZK commitment, and payload nullifier. In production, replace
/// with real ed25519_verify / secp256k1_verify against a stored oracle
/// public key.
///
/// Returns `Ok(())` if the signature is structurally valid (non-empty,
/// hex-decodable). Returns `Err(InvalidOracleSignature)` otherwise.
fn verify_oracle_signature(
    ipfs_cid_hash: &str,
    commitment_hex: &str,
    payload_nullifier: &str,
    oracle_signature: &str,
) -> Result<(), ContractError> {
    // ── Step 1: Reconstruct the signed message (always executed) ───────
    // In production the oracle attests: SHA256(ipfs_cid_hash || C_hex || nul)
    let mut hasher = Sha256::new();
    hasher.update(ipfs_cid_hash.as_bytes());
    hasher.update(commitment_hex.as_bytes());
    hasher.update(payload_nullifier.as_bytes());
    let _expected_digest = hasher.finalize();

    // ── Step 2: Decode the oracle signature from hex ──────────────────
    if oracle_signature.is_empty() {
        return Err(ContractError::InvalidOracleSignature {});
    }
    let _sig_bytes =
        hex::decode(oracle_signature).map_err(|_| ContractError::InvalidOracleSignature {})?;

    // ── Step 3: PRODUCTION TODO ───────────────────────────────────────
    // In production, insert real cryptographic verification here:
    //
    //   let oracle_pubkey = ORACLE_PUBKEY.load(deps.storage)?;
    //   let verified = deps.api.ed25519_verify(
    //       &_expected_digest,
    //       &_sig_bytes,
    //       &oracle_pubkey,
    //   )?;
    //   if !verified {
    //       return Err(ContractError::InvalidOracleSignature {});
    //   }
    //
    // For this PoC, any non-empty hex-decodable string is accepted.

    Ok(())
}

/// Validate that a payload nullifier is a 64-character lowercase hex string
/// (i.e., a valid SHA-256 digest representation). This enforces a fixed
/// format at the contract boundary consistent with the paper's definition
/// of nul = SHA256(P).
fn validate_nullifier(nullifier: &str) -> Result<(), ContractError> {
    if nullifier.len() != 64 {
        return Err(ContractError::InvalidNullifier {});
    }
    if !nullifier
        .chars()
        .all(|c| matches!(c, '0'..='9' | 'a'..='f'))
    {
        return Err(ContractError::InvalidNullifier {});
    }
    Ok(())
}

// ╔═══════════════════════════════════════════════════════════════════════╗
// ║                                                                       ║
// ║   ██  WARNING — MOCKED IDEAL RANDOMNESS FUNCTIONALITY (F_beacon)  ██  ║
// ║                                                                       ║
// ║   THIS IS A **MOCKED** IMPLEMENTATION OF THE IDEAL RANDOMNESS         ║
// ║   FUNCTIONALITY F_beacon (Definition 2.5 in the accompanying paper).  ║
// ║   IT IS PROVIDED SOLELY FOR ACADEMIC PROOF-OF-CONCEPT EVALUATION,     ║
// ║   ALLOWING RESEARCHERS TO FOCUS ON EVALUATING THE ZERO-KNOWLEDGE      ║
// ║   RANGE PROOF COMPONENTS WITHOUT REQUIRING A LIVE ASYNCHRONOUS VRF    ║
// ║   ORACLE OR TEE THRESHOLD COMMITTEE.                                  ║
// ║                                                                       ║
// ║   IN A PRODUCTION DEPLOYMENT THIS FUNCTION **MUST** BE REPLACED       ║
// ║   WITH A SECURE ASYNCHRONOUS VRF SUCH AS:                             ║
// ║     • Nois Network  (drand-based, BLS threshold signatures)           ║
// ║     • drand          (League of Entropy, publicly verifiable)          ║
// ║     • TEE threshold Ed25519 signatures  (DeCloak model)               ║
// ║                                                                       ║
// ║   ⚠  USING BLOCK VARIABLES FOR ON-CHAIN RANDOMNESS IS VULNERABLE TO: ║
// ║     • VALIDATOR / PROPOSER MANIPULATION — a malicious block proposer  ║
// ║       can choose block timestamps and ordering to bias the outcome.   ║
// ║     • MINER EXTRACTABLE VALUE (MEV) — searchers and builders can      ║
// ║       observe pending transactions and front-run or sandwich the      ║
// ║       claim to influence the random selection.                        ║
// ║     • REPLAY / PREDICTABILITY — all inputs (block.time, block.height, ║
// ║       sender) are publicly observable before execution, making the    ║
// ║       output fully predictable to any on-chain observer.             ║
// ║                                                                       ║
// ║   THIS MOCK EXISTS ONLY TO ALLOW THE ACADEMIC EVALUATION PIPELINE     ║
// ║   TO EXERCISE THE FULL BURN → RANDOM-SELECT → CLAIM PATH WITHOUT     ║
// ║   AN EXTERNAL ORACLE DEPENDENCY.                                      ║
// ║                                                                       ║
// ╚═══════════════════════════════════════════════════════════════════════╝
/// **MOCK** — Derive a pseudo-random `u64` in `[0, range_max)` by hashing
/// the current block time (nanos), block height, and sender address.
///
/// # Academic PoC Only
///
/// This mocks the ideal functionality F_beacon for local evaluation.
/// In production, use a secure VRF (Nois, drand) or TEE threshold signatures.
// ==============================================================================
// DEPRECATED: Legacy mocked randomness function (replaced by oracle-driven flow)
// ==============================================================================
// This function was used in the legacy atomic BurnAndClaim flow and is now
// deprecated in favor of the two-phase oracle-driven architecture.
// Kept for reference only.
//
// pub fn mock_get_randomness(env: &Env, sender: &str, range_max: u64) -> u64 {
//     if range_max == 0 {
//         return 0;
//     }
//     let mut hasher = Sha256::new();
//     hasher.update(env.block.time.nanos().to_be_bytes());
//     hasher.update(env.block.height.to_be_bytes());
//     hasher.update(sender.as_bytes());
//     let hash = hasher.finalize();
//     let random_val = u64::from_be_bytes(hash[..8].try_into().unwrap());
//     random_val % range_max
// }

// ---------------------------------------------------------------------------
// Instantiate
// ---------------------------------------------------------------------------

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    // Initialise CW20 token state via cw20-base.
    // Minter is set to the contract's own address so only the contract can mint/burn.
    let token_info = TokenInfo {
        name: msg.token_name.clone(),
        symbol: msg.token_symbol.clone(),
        decimals: 6,
        total_supply: Uint128::zero(),
        mint: Some(MinterData {
            minter: env.contract.address,
            cap: None,
        }),
    };
    TOKEN_INFO.save(deps.storage, &token_info)?;

    // Store contract config.
    let fallback_timeout = msg.fallback_timeout_blocks.unwrap_or(100_000);
    let oracle_timeout = msg.oracle_timeout_blocks.unwrap_or(100_800);
    CONFIG.save(
        deps.storage,
        &Config {
            min_vault_depth: msg.min_vault_depth,
            owner: info.sender.clone(),
            fallback_timeout_blocks: fallback_timeout,
            oracle_timeout_blocks: oracle_timeout,
        },
    )?;

    // Initialise counters.
    VAULT_COUNT.save(deps.storage, &0u64)?;
    ACTIVE_PAYLOAD_COUNT.save(deps.storage, &0u64)?;
    // Vault starts empty (below k), so starvation tracking is not yet active.
    // It will be set on the first deposit if the depth remains below k.
    STARVATION_START_HEIGHT.save(deps.storage, &None)?;

    // Store the oracle relayer address if provided.
    if let Some(ref oracle_addr_str) = msg.oracle_address {
        let oracle_addr = deps.api.addr_validate(oracle_addr_str)?;
        ORACLE_ADDRESS.save(deps.storage, &oracle_addr)?;
    }

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender)
        .add_attribute("token_name", msg.token_name)
        .add_attribute("token_symbol", msg.token_symbol)
        .add_attribute("min_vault_depth", msg.min_vault_depth.to_string()))
}

// ---------------------------------------------------------------------------
// Execute dispatcher
// ---------------------------------------------------------------------------

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Deposit {
            proof_hex,
            commitment_hex,
            num_bits,
            ipfs_cid_hash,
            ct_key_hash,
            oracle_signature,
            payload_nullifier,
        } => execute_deposit(
            deps,
            env,
            info,
            proof_hex,
            commitment_hex,
            num_bits,
            ipfs_cid_hash,
            ct_key_hash,
            oracle_signature,
            payload_nullifier,
        ),
        // DEPRECATED: Legacy atomic BurnAndClaim (replaced by two-phase oracle flow)
        // ExecuteMsg::BurnAndClaim {
        //     buyer_x25519_pubkey,
        // } => execute_burn_and_claim(deps, env, info, buyer_x25519_pubkey),
        ExecuteMsg::BurnAndRequest {
            buyer_x25519_pubkey,
        } => execute_burn_and_request(deps, env, info, buyer_x25519_pubkey),
        ExecuteMsg::FulfillRandomness {
            buyer_address,
            random_seed,
        } => execute_fulfill_randomness(deps, env, info, buyer_address, random_seed),
        ExecuteMsg::RecoverOracleTimeout {} => execute_recover_oracle_timeout(deps, env, info),
        // ── CW20 standard operations forwarded to cw20-base ───────────
        ExecuteMsg::Transfer { recipient, amount } => Ok(cw20_contract::execute_transfer(
            deps, env, info, recipient, amount,
        )?),
        ExecuteMsg::Send {
            contract,
            amount,
            msg: send_msg,
        } => Ok(cw20_contract::execute_send(
            deps, env, info, contract, amount, send_msg,
        )?),
        ExecuteMsg::IncreaseAllowance {
            spender,
            amount,
            expires,
        } => Ok(cw20_base::allowances::execute_increase_allowance(
            deps, env, info, spender, amount, expires,
        )?),
        ExecuteMsg::DecreaseAllowance {
            spender,
            amount,
            expires,
        } => Ok(cw20_base::allowances::execute_decrease_allowance(
            deps, env, info, spender, amount, expires,
        )?),
        ExecuteMsg::TransferFrom {
            owner,
            recipient,
            amount,
        } => Ok(cw20_base::allowances::execute_transfer_from(
            deps, env, info, owner, recipient, amount,
        )?),
        ExecuteMsg::SendFrom {
            owner,
            contract,
            amount,
            msg: send_msg,
        } => Ok(cw20_base::allowances::execute_send_from(
            deps, env, info, owner, contract, amount, send_msg,
        )?),
    }
}

// ---------------------------------------------------------------------------
// Deposit: verify aggregated (m=2) Bulletproof on-chain (64 total bits via
// 2×32-bit dynamic boundaries) -> mint CW20 Data-Backed Range Token -> store payload
// ---------------------------------------------------------------------------

pub fn execute_deposit(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    proof_hex: String,
    commitment_hex: String,
    num_bits: u32,
    ipfs_cid_hash: String,
    ct_key_hash: String,
    oracle_signature: String,
    payload_nullifier: String,
) -> Result<Response, ContractError> {
    // ── Validate nullifier format: must be 64-char lowercase hex (SHA-256) ─
    validate_nullifier(&payload_nullifier)?;

    // ── Sybil resistance: reject duplicate payload nullifiers ──────────
    if USED_NULLIFIERS
        .may_load(deps.storage, &payload_nullifier)?
        .is_some()
    {
        return Err(ContractError::NullifierAlreadyUsed {});
    }

    // ── Replay prevention: reject duplicate commitments ────────────────
    if USED_COMMITMENTS
        .may_load(deps.storage, &commitment_hex)?
        .is_some()
    {
        return Err(ContractError::CommitmentAlreadyUsed {});
    }

    // ── Oracle signature verification (semantic binding) ──────────────
    verify_oracle_signature(
        &ipfs_cid_hash,
        &commitment_hex,
        &payload_nullifier,
        &oracle_signature,
    )?;

    // Validate hex encoding.
    let proof_bytes = hex::decode(&proof_hex).map_err(|e| ContractError::InvalidProof {
        reason: format!("invalid proof hex: {}", e),
    })?;
    let commitment_bytes =
        hex::decode(&commitment_hex).map_err(|e| ContractError::InvalidProof {
            reason: format!("invalid commitment hex: {}", e),
        })?;

    if commitment_bytes.len() != 32 {
        return Err(ContractError::InvalidProof {
            reason: format!(
                "commitment must be 32 bytes, got {}",
                commitment_bytes.len()
            ),
        });
    }

    // Validate num_bits.
    //
    // The contract initializes a 32-bit `BulletproofGens` pool (see `BP_GENS_32`
    // at the top of this file). Accepting any other bit-width would either
    // panic inside the Dalek crate or silently mismatch the prover's bit-width
    // and reject every proof. Production code should accept only the bit-width
    // matching the cached generator pool, which for this PoC is 32.
    if num_bits != 32 {
        return Err(ContractError::InvalidProof {
            reason: format!(
                "num_bits must be 32 (matches the cached BulletproofGens pool), got {}",
                num_bits
            ),
        });
    }

    // Validate proof deserialisation.
    RangeProof::from_bytes(&proof_bytes).map_err(|e| ContractError::InvalidProof {
        reason: format!("proof bytes are not a valid RangeProof: {:?}", e),
    })?;

    // -- Native on-chain aggregated (m=2) Bulletproof verification --
    // Executes within the native CosmWasm WebAssembly runtime via native Rust
    // compilation, bypassing EVM pre-compile limitations. Empirical cost:
    // ~631K gas for the fully-loaded Deposit state machine (4.8x multiplier
    // vs CW-20 baseline). Isolated WASM execution latency: 30.2 ms.
    let is_valid = verify_bulletproof(
        &proof_bytes,
        &commitment_bytes,
        num_bits,
        90, // hardcoded bucket floor (a_k) for this PoC. In production, this should be derived from the proof or passed as a parameter.
        100, // hardcoded bucket ceiling (b_k) for this PoC. In production, this should be derived from the proof or passed as a parameter.
        env.contract.address.as_str(),
        &payload_nullifier,
        info.sender.as_str(),
    )?;
    if !is_valid {
        return Err(ContractError::VerificationFailed {});
    }

    // ── Mark commitment as used (replay prevention) ───────────────────
    USED_COMMITMENTS.save(deps.storage, &commitment_hex, &true)?;

    // ── Mark nullifier as used (Sybil resistance) ─────────────────────
    USED_NULLIFIERS.save(deps.storage, &payload_nullifier, &true)?;

    // Compute proof hash.
    let proof_hash = compute_hash(&proof_bytes);

    // -- Atomic CW20 Data-Backed Range Token mint --
    mint_cw20(&mut deps, &env, info.sender.as_str())?;

    // -- Store payload in vault --
    let payload_index = VAULT_COUNT.load(deps.storage)?;
    VAULT.save(
        deps.storage,
        payload_index,
        &Payload {
            ipfs_cid_hash: ipfs_cid_hash.clone(),
            ct_key_hash: ct_key_hash.clone(),
            proof_hash: proof_hash.clone(),
            num_bits,
            depositor: info.sender.clone(),
            active: true,
        },
    )?;
    VAULT_COUNT.save(deps.storage, &(payload_index + 1))?;

    // ── O(1) indexed map: append to the active map ────────────────────
    let active_count = ACTIVE_PAYLOAD_COUNT.load(deps.storage)?;
    ACTIVE_PAYLOAD_MAP.save(deps.storage, active_count, &payload_index)?;
    ACTIVE_PAYLOAD_COUNT.save(deps.storage, &(active_count + 1))?;

    // ── Track starvation start height for vault-starvation fallback ──────
    // If the new deposit pushes the vault depth to >= min_vault_depth,
    // reset starvation tracking (the vault is healthy).
    // Otherwise, if starvation tracking is not yet active, start it now.
    let config = CONFIG.load(deps.storage)?;
    let new_active_count = active_count + 1;
    if new_active_count >= config.min_vault_depth {
        STARVATION_START_HEIGHT.save(deps.storage, &None)?;
    } else {
        let current = STARVATION_START_HEIGHT.load(deps.storage)?;
        if current.is_none() {
            STARVATION_START_HEIGHT.save(deps.storage, &Some(env.block.height))?;
        }
        // If already tracking starvation, do NOT reset — this prevents
        // a griefing attack where an adversary trickles deposits to
        // perpetually reset the timer.
    }

    Ok(Response::new()
        .add_attribute("action", "deposit")
        .add_attribute("depositor", info.sender)
        .add_attribute("payload_index", payload_index.to_string())
        .add_attribute("proof_hash", proof_hash)
        .add_attribute("ipfs_cid_hash", ipfs_cid_hash)
        .add_attribute("is_valid", "true")
        .add_attribute("cw20_minted", ONE_TOKEN.to_string()))
}

// ---------------------------------------------------------------------------
// ==============================================================================
// DEPRECATED: Legacy atomic BurnAndClaim (replaced by two-phase oracle flow)
// ==============================================================================
// This function implemented an atomic single-transaction claim using mocked
// F_beacon randomness. It has been superseded by the asynchronous two-phase
// BurnAndRequest/FulfillRandomness architecture with RecoverOracleTimeout.
// Kept for reference only.
//
// pub fn execute_burn_and_claim(
//     mut deps: DepsMut,
//     env: Env,
//     info: MessageInfo,
//     buyer_x25519_pubkey: String,
// ) -> Result<Response, ContractError> {
//     // 1. Check CW20 balance >= 1 token (1_000_000 base units with 6 decimals).
//     //    AMM swaps may leave fractional dust above 1.0 token. We accept any
//     //    balance >= ONE_TOKEN and burn exactly ONE_TOKEN below, leaving any
//     //    residual dust unburned in the buyer's balance.
//     let balance = cw20_contract::query_balance(deps.as_ref(), info.sender.to_string())?;
//     if balance.balance < Uint128::new(ONE_TOKEN) {
//         return Err(ContractError::NoTokenToBurn {});
//     }
//
//     // 2. Check k-anonymity: active entries >= min_vault_depth,
//     //    UNLESS the fallback timeout has elapsed since the vault first
//     //    entered a starved state (starvation_start_height).
//     //    Unlike a last-deposit-based timer, this cannot be reset by an
//     //    adversary trickling deposits to grief buyers.
//     let config = CONFIG.load(deps.storage)?;
//     let active_count = ACTIVE_PAYLOAD_COUNT.load(deps.storage)?;
//
//     if active_count == 0 {
//         return Err(ContractError::NoActivePayloads {});
//     }
//
//     let mut fallback_elapsed = false;
//
//     // 2. Pre-Claim Starvation Check
//     let mut starvation_start_height = STARVATION_START_HEIGHT.load(deps.storage)?;
//     if active_count < config.min_vault_depth {
//         // Fail-safe: if we are starved but timer isn't set, set it now.
//         if starvation_start_height.is_none() {
//             STARVATION_START_HEIGHT.save(deps.storage, &Some(env.block.height))?;
//             starvation_start_height = Some(env.block.height);
//         }
//
//         fallback_elapsed = starvation_start_height
//             .map(|start_h| env.block.height >= start_h + config.fallback_timeout_blocks)
//             .unwrap_or(false);
//
//         if !fallback_elapsed {
//             return Err(ContractError::InsufficientVaultDepth {
//                 required: config.min_vault_depth,
//                 available: active_count,
//             });
//         }
//     }
//
//     // 3. Burn exactly ONE_TOKEN
//     let burn_info = MessageInfo {
//         sender: info.sender.clone(),
//         funds: vec![],
//     };
//     cw20_contract::execute_burn(
//         deps.branch(),
//         env.clone(),
//         burn_info,
//         Uint128::new(ONE_TOKEN),
//     )
//     .map_err(ContractError::from)?;
//
//     // 4. Random selection (Mock F_beacon)
//     let random_index = mock_get_randomness(&env, info.sender.as_str(), active_count);
//     let selected_payload_id = ACTIVE_PAYLOAD_MAP.load(deps.storage, random_index)?;
//
//     // 5. O(1) swap-and-pop
//     let last_slot = active_count - 1;
//     if random_index != last_slot {
//         // Move the last element into the vacated slot.
//         let last_payload_id = ACTIVE_PAYLOAD_MAP.load(deps.storage, last_slot)?;
//         ACTIVE_PAYLOAD_MAP.save(deps.storage, random_index, &last_payload_id)?;
//     }
//     ACTIVE_PAYLOAD_MAP.remove(deps.storage, last_slot);
//     ACTIVE_PAYLOAD_COUNT.save(deps.storage, &last_slot)?;
//
//     // 6. Mark payload as claimed.
//     let mut payload_entry = VAULT.load(deps.storage, selected_payload_id)?;
//     payload_entry.active = false;
//     VAULT.save(deps.storage, selected_payload_id, &payload_entry)?;
//
//     // 7. Record claimed payload for buyer.
//     let mut claimed = CLAIMED_PAYLOADS
//         .may_load(deps.storage, &info.sender)?
//         .unwrap_or_default();
//     claimed.push(selected_payload_id);
//     CLAIMED_PAYLOADS.save(deps.storage, &info.sender, &claimed)?;
//
//     // Load payload data for the event.
//     let payload = VAULT.load(deps.storage, selected_payload_id)?;
//
//     // 8. Post-Claim Starvation Tracker Update
//     // We base the tracker on the NEW depth of the vault after popping the item.
//     let new_active_count = active_count - 1;
//     if new_active_count < config.min_vault_depth {
//         if starvation_start_height.is_none() {
//             STARVATION_START_HEIGHT.save(deps.storage, &Some(env.block.height))?;
//         }
//     } else {
//         if starvation_start_height.is_some() {
//             STARVATION_START_HEIGHT.save(deps.storage, &None)?;
//         }
//     }
//
//     Ok(Response::new()
//         .add_attribute("action", "burn_and_claim")
//         .add_attribute("buyer", info.sender)
//         .add_attribute("buyer_x25519_pubkey", buyer_x25519_pubkey)
//         .add_attribute("payload_index", selected_payload_id.to_string())
//         .add_attribute("ipfs_cid_hash", payload.ipfs_cid_hash)
//         .add_attribute("ct_key_hash", payload.ct_key_hash)
//         .add_attribute("cw20_burned", ONE_TOKEN.to_string())
//         .add_attribute("fallback_used", fallback_elapsed.to_string()))
// }

// ---------------------------------------------------------------------------
// BurnAndRequest (Phase 1): burn CW20 -> emit oracle_request event
//
// Asynchronous oracle-driven flow. The buyer burns 1 CW20 token and a
// pending request is stored. The off-chain relayer bot observes the
// `wasm-oracle_request` event and calls `FulfillRandomness` to complete
// the vault selection.
// ---------------------------------------------------------------------------
pub fn execute_burn_and_request(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    buyer_x25519_pubkey: String,
) -> Result<Response, ContractError> {
    // 0. Ensure oracle address is configured.
    if ORACLE_ADDRESS.may_load(deps.storage)?.is_none() {
        return Err(ContractError::OracleNotConfigured {});
    }

    // 1. Revert if a request is already pending for this sender.
    if PENDING_REQUESTS
        .may_load(deps.storage, &info.sender)?
        .is_some()
    {
        return Err(ContractError::RequestAlreadyPending {});
    }

    // 2. Check CW20 balance >= 1 token.
    let balance = cw20_contract::query_balance(deps.as_ref(), info.sender.to_string())?;
    if balance.balance < Uint128::new(ONE_TOKEN) {
        return Err(ContractError::NoTokenToBurn {});
    }

    // 3. Check k-anonymity (same logic as BurnAndClaim).
    let config = CONFIG.load(deps.storage)?;
    let active_count = ACTIVE_PAYLOAD_COUNT.load(deps.storage)?;

    if active_count == 0 {
        return Err(ContractError::NoActivePayloads {});
    }

    let mut fallback_elapsed = false;
    let mut starvation_start_height = STARVATION_START_HEIGHT.load(deps.storage)?;
    if active_count < config.min_vault_depth {
        if starvation_start_height.is_none() {
            STARVATION_START_HEIGHT.save(deps.storage, &Some(env.block.height))?;
            // Update local copy to avoid a redundant storage read; the
            // fallback_elapsed computation below must see the newly written value.
            starvation_start_height = Some(env.block.height);
        }

        fallback_elapsed = starvation_start_height
            .map(|start_h| env.block.height >= start_h + config.fallback_timeout_blocks)
            .unwrap_or(false);

        if !fallback_elapsed {
            return Err(ContractError::InsufficientVaultDepth {
                required: config.min_vault_depth,
                available: active_count,
            });
        }
    }

    // 4. Burn exactly ONE_TOKEN.
    let burn_info = MessageInfo {
        sender: info.sender.clone(),
        funds: vec![],
    };
    cw20_contract::execute_burn(
        deps.branch(),
        env.clone(),
        burn_info,
        Uint128::new(ONE_TOKEN),
    )
    .map_err(ContractError::from)?;

    // 5. Save pending request.
    PENDING_REQUESTS.save(
        deps.storage,
        &info.sender,
        &PendingRequest {
            range_bucket_id: active_count,
            request_height: env.block.height,
            buyer_x25519_pubkey: buyer_x25519_pubkey.clone(),
        },
    )?;

    // 6. Emit the oracle_request event for the relayer bot.
    Ok(Response::new()
        .add_attribute("action", "burn_and_request")
        .add_attribute("buyer", info.sender.to_string())
        .add_attribute("buyer_x25519_pubkey", buyer_x25519_pubkey)
        .add_attribute("bucket_id", active_count.to_string())
        .add_attribute("cw20_burned", ONE_TOKEN.to_string())
        .add_attribute("fallback_used", fallback_elapsed.to_string())
        // Emit a typed event for the relayer bot to detect.
        .add_event(
            cosmwasm_std::Event::new("oracle_request")
                .add_attribute("buyer", info.sender.to_string())
                .add_attribute("bucket_id", active_count.to_string()),
        ))
}

// ---------------------------------------------------------------------------
// FulfillRandomness (Phase 2): oracle callback -> O(1) swap-and-pop selection
//
// Called exclusively by the authorized oracle relayer bot.
// ---------------------------------------------------------------------------
pub fn execute_fulfill_randomness(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    buyer_address: String,
    random_seed: String,
) -> Result<Response, ContractError> {
    // 1. Authentication: only the oracle address may call this.
    let oracle_addr = ORACLE_ADDRESS
        .may_load(deps.storage)?
        .ok_or(ContractError::OracleNotConfigured {})?;
    if info.sender != oracle_addr {
        return Err(ContractError::UnauthorizedOracle {});
    }

    // 2. Parse the random seed from its string representation.
    let random_seed_u64: u64 = random_seed
        .parse()
        .map_err(|_| ContractError::InvalidRandomSeed {})?;

    // 3. Load the pending request (do NOT remove yet — defer until all
    //    fallible operations succeed to prevent permanent fund loss).
    let buyer_addr = deps.api.addr_validate(&buyer_address)?;
    let pending = PENDING_REQUESTS
        .may_load(deps.storage, &buyer_addr)?
        .ok_or(ContractError::NoPendingRequest {})?;

    // 4. O(1) swap-and-pop vault selection using the provided random seed.
    let active_count = ACTIVE_PAYLOAD_COUNT.load(deps.storage)?;
    if active_count == 0 {
        return Err(ContractError::NoActivePayloads {});
    }
    let random_index = random_seed_u64 % active_count;
    let selected_payload_id = ACTIVE_PAYLOAD_MAP.load(deps.storage, random_index)?;

    // Swap-and-pop.
    let last_slot = active_count - 1;
    if random_index != last_slot {
        let last_payload_id = ACTIVE_PAYLOAD_MAP.load(deps.storage, last_slot)?;
        ACTIVE_PAYLOAD_MAP.save(deps.storage, random_index, &last_payload_id)?;
    }
    ACTIVE_PAYLOAD_MAP.remove(deps.storage, last_slot);
    ACTIVE_PAYLOAD_COUNT.save(deps.storage, &last_slot)?;

    // 5. Mark payload as claimed.
    let mut payload_entry = VAULT.load(deps.storage, selected_payload_id)?;
    payload_entry.active = false;
    VAULT.save(deps.storage, selected_payload_id, &payload_entry)?;

    // 6. Record claimed payload for buyer.
    let mut claimed = CLAIMED_PAYLOADS
        .may_load(deps.storage, &buyer_addr)?
        .unwrap_or_default();
    claimed.push(selected_payload_id);
    CLAIMED_PAYLOADS.save(deps.storage, &buyer_addr, &claimed)?;

    // 7. NOW remove the pending request — all fallible ops have succeeded.
    PENDING_REQUESTS.remove(deps.storage, &buyer_addr);

    // Load payload data for the event.
    let payload = VAULT.load(deps.storage, selected_payload_id)?;

    // 8. Post-claim starvation tracker update.
    let config = CONFIG.load(deps.storage)?;
    let starvation_start_height = STARVATION_START_HEIGHT.load(deps.storage)?;
    let new_active_count = active_count - 1;
    if new_active_count < config.min_vault_depth {
        if starvation_start_height.is_none() {
            STARVATION_START_HEIGHT.save(deps.storage, &Some(env.block.height))?;
        }
    } else if starvation_start_height.is_some() {
        STARVATION_START_HEIGHT.save(deps.storage, &None)?;
    }

    Ok(Response::new()
        .add_attribute("action", "fulfill_randomness")
        .add_attribute("buyer", buyer_address)
        .add_attribute("buyer_x25519_pubkey", pending.buyer_x25519_pubkey)
        .add_attribute("payload_index", selected_payload_id.to_string())
        .add_attribute("ipfs_cid_hash", payload.ipfs_cid_hash)
        .add_attribute("ct_key_hash", payload.ct_key_hash)
        .add_attribute("random_seed", random_seed)
        .add_attribute("request_height", pending.request_height.to_string()))
}

// ---------------------------------------------------------------------------
// RecoverOracleTimeout: buyer reclaims burned token if oracle SLA breached
//
// If the oracle relayer fails to call FulfillRandomness within
// `oracle_timeout_blocks` of the buyer's BurnAndRequest, the buyer may
// call this to re-mint their burned token and clear the pending request.
// This guarantees that a crashed/offline relayer cannot permanently
// destroy buyer funds.
// ---------------------------------------------------------------------------
pub fn execute_recover_oracle_timeout(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
) -> Result<Response, ContractError> {
    // 1. Load and verify the caller has a pending request.
    let pending = PENDING_REQUESTS
        .may_load(deps.storage, &info.sender)?
        .ok_or(ContractError::NoPendingRequest {})?;

    // 2. Check that the oracle timeout has elapsed.
    let config = CONFIG.load(deps.storage)?;
    let timeout_height = pending.request_height + config.oracle_timeout_blocks;
    if env.block.height < timeout_height {
        return Err(ContractError::OracleTimeoutNotElapsed {
            timeout_height,
            current_height: env.block.height,
        });
    }

    // 3. Remove the pending request.
    PENDING_REQUESTS.remove(deps.storage, &info.sender);

    // 4. Re-mint ONE_TOKEN back to the buyer to make them whole.
    cw20_contract::execute_mint(
        deps.branch(),
        env.clone(),
        // The minter is the contract itself (set during instantiation).
        MessageInfo {
            sender: env.contract.address.clone(),
            funds: vec![],
        },
        info.sender.to_string(),
        Uint128::new(ONE_TOKEN),
    )
    .map_err(ContractError::from)?;

    Ok(Response::new()
        .add_attribute("action", "recover_oracle_timeout")
        .add_attribute("buyer", info.sender.to_string())
        .add_attribute("request_height", pending.request_height.to_string())
        .add_attribute("timeout_height", timeout_height.to_string())
        .add_attribute("cw20_refunded", ONE_TOKEN.to_string()))
}

// ---------------------------------------------------------------------------
// Query dispatcher
// ---------------------------------------------------------------------------

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::ActiveCount {} => to_json_binary(&query_active_count(deps)?),
        QueryMsg::GetVaultEntry { index } => to_json_binary(&query_vault_entry(deps, index)?),
        QueryMsg::GetClaimedPayloads { buyer } => {
            to_json_binary(&query_claimed_payloads(deps, buyer)?)
        }
        QueryMsg::TokenInfo {} => to_json_binary(&cw20_contract::query_token_info(deps)?),
        QueryMsg::Balance { address } => {
            to_json_binary(&cw20_contract::query_balance(deps, address)?)
        }
        QueryMsg::GetConfig {} => to_json_binary(&query_config(deps)?),
        QueryMsg::GetPendingRequest { buyer } => {
            to_json_binary(&query_pending_request(deps, buyer)?)
        }
    }
}

fn query_active_count(deps: Deps) -> StdResult<ActiveCountResponse> {
    let count = ACTIVE_PAYLOAD_COUNT.load(deps.storage)?;
    Ok(ActiveCountResponse { count })
}

fn query_vault_entry(deps: Deps, index: u64) -> StdResult<VaultEntryResponse> {
    let p = VAULT.load(deps.storage, index)?;
    Ok(VaultEntryResponse {
        ipfs_cid_hash: p.ipfs_cid_hash,
        ct_key_hash: p.ct_key_hash,
        proof_hash: p.proof_hash,
        num_bits: p.num_bits,
        depositor: p.depositor.to_string(),
        active: p.active,
    })
}

fn query_claimed_payloads(deps: Deps, buyer: String) -> StdResult<ClaimedPayloadsResponse> {
    let buyer_addr = deps.api.addr_validate(&buyer)?;
    let indices = CLAIMED_PAYLOADS
        .may_load(deps.storage, &buyer_addr)?
        .unwrap_or_default();
    Ok(ClaimedPayloadsResponse {
        payload_indices: indices,
    })
}

fn query_config(deps: Deps) -> StdResult<ConfigResponse> {
    let config = CONFIG.load(deps.storage)?;
    let token_info = TOKEN_INFO.load(deps.storage)?;
    let oracle_addr = ORACLE_ADDRESS
        .may_load(deps.storage)?
        .map(|a| a.to_string());
    Ok(ConfigResponse {
        min_vault_depth: config.min_vault_depth,
        owner: config.owner.to_string(),
        token_name: token_info.name,
        token_symbol: token_info.symbol,
        token_decimals: 6,
        total_supply: token_info.total_supply,
        fallback_timeout_blocks: config.fallback_timeout_blocks,
        oracle_address: oracle_addr,
        oracle_timeout_blocks: config.oracle_timeout_blocks,
    })
}

fn query_pending_request(deps: Deps, buyer: String) -> StdResult<PendingRequestResponse> {
    let buyer_addr = deps.api.addr_validate(&buyer)?;
    match PENDING_REQUESTS.may_load(deps.storage, &buyer_addr)? {
        Some(req) => Ok(PendingRequestResponse {
            found: true,
            range_bucket_id: Some(req.range_bucket_id),
            request_height: Some(req.request_height),
        }),
        None => Ok(PendingRequestResponse {
            found: false,
            range_bucket_id: None,
            request_height: None,
        }),
    }
}

// ===========================================================================
// Unit Tests
// ===========================================================================

#[cfg(test)]
mod tests {

    use super::*;
    use cosmwasm_std::from_json;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use rand::Rng;

    fn default_instantiate_msg() -> InstantiateMsg {
        InstantiateMsg {
            token_name: "RangeBucket90-100".to_string(),
            token_symbol: "RB90".to_string(),
            token_decimals: 6,
            min_vault_depth: 5,
            fallback_timeout_blocks: Some(100_000),
            oracle_address: None,
            oracle_timeout_blocks: None,
        }
    }

    fn setup_contract(
        deps: &mut cosmwasm_std::OwnedDeps<
            cosmwasm_std::MemoryStorage,
            cosmwasm_std::testing::MockApi,
            cosmwasm_std::testing::MockQuerier,
        >,
        env: Env,
    ) {
        let msg = default_instantiate_msg();
        let info = mock_info("creator", &[]);
        instantiate(deps.as_mut(), env, info, msg).unwrap();
    }

    fn generate_proof(env: Env, sender: &str) -> (String, String, String) {
        use curve25519_dalek_ng::ristretto::RistrettoPoint;
        use curve25519_dalek_ng::scalar::Scalar;
        use curve25519_dalek_ng::traits::MultiscalarMul;

        // hardcoded bucket bounds for this PoC. In production, these should be derived from the proof or passed as parameters.
        let bucket_floor = 90_u64;
        let bucket_ceiling = 100_u64;

        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(32, 2);
        let secret_value = 95u64; // Example valid value within [floor, ceiling)

        let mut rng = rand::thread_rng();
        let blinding = Scalar::random(&mut rng);
        let nullifier = compute_hash(rng.gen::<u32>().to_string().as_bytes());

        // --- LEAP: Derived Aggregation Arrays ---
        let v1 = secret_value - bucket_floor;
        let v2 = (bucket_ceiling - 1) - secret_value;
        let r1 = blinding;
        let r2 = -blinding;

        // --- LEAP: Transcript Synchronization ---
        // The prover transcript MUST mirror the on-chain verifier transcript
        // exactly, including the sender binding that prevents mempool
        // front-running of (proof, commitment, nullifier, oracle_sig) tuples.
        let mut prover_transcript = Transcript::new(b"PrivateDataExchange_RangeProof_v1");
        prover_transcript.append_message(b"contract", env.contract.address.as_bytes());
        prover_transcript.append_message(b"nullifier", nullifier.as_bytes());
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

        (proof_hex, commitment_hex, nullifier)
    }

    fn deposit_valid(
        deps: &mut cosmwasm_std::OwnedDeps<
            cosmwasm_std::MemoryStorage,
            cosmwasm_std::testing::MockApi,
            cosmwasm_std::testing::MockQuerier,
        >,
        env: Env,
        sender: &str,
    ) {
        let (proof_hex, commitment_hex, nullifier) = generate_proof(env.clone(), sender);

        let info = mock_info(sender, &[]);
        let msg = ExecuteMsg::Deposit {
            proof_hex,
            commitment_hex,
            num_bits: 32,
            ipfs_cid_hash: "aabbccdd".to_string(),
            ct_key_hash: "11223344".to_string(),
            oracle_signature: "deadbeef".to_string(),
            payload_nullifier: nullifier,
        };
        execute(deps.as_mut(), env, info, msg).unwrap();
    }

    // ── Instantiation Tests ─────────────────────────────────────────────

    #[test]
    fn proper_instantiation() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        setup_contract(&mut deps, env.clone());

        let res = query(deps.as_ref(), env.clone(), QueryMsg::GetConfig {}).unwrap();
        let config: ConfigResponse = from_json(&res).unwrap();
        assert_eq!(config.min_vault_depth, 5);
        assert_eq!(config.token_name, "RangeBucket90-100");
        assert_eq!(config.token_symbol, "RB90");
        assert_eq!(config.token_decimals, 6);
        assert_eq!(config.total_supply, Uint128::zero());
    }

    // ── Deposit Tests ───────────────────────────────────────────────────

    #[test]
    fn deposit_stores_payload_and_mints_token() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        setup_contract(&mut deps, env.clone());

        let info = mock_info("seller", &[]);
        let (proof_hex, commitment_hex, nullifier) = generate_proof(env.clone(), "seller");
        let res = execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::Deposit {
                proof_hex: proof_hex,
                commitment_hex: commitment_hex,
                num_bits: 32,
                ipfs_cid_hash: "cid_hash_1".to_string(),
                ct_key_hash: "key_hash_1".to_string(),
                oracle_signature: "deadbeef".to_string(),
                payload_nullifier: nullifier,
            },
        )
        .unwrap();

        assert_eq!(
            res.attributes
                .iter()
                .find(|a| a.key == "action")
                .unwrap()
                .value,
            "deposit"
        );
        assert_eq!(
            res.attributes
                .iter()
                .find(|a| a.key == "is_valid")
                .unwrap()
                .value,
            "true"
        );

        let bal_res = query(
            deps.as_ref(),
            env.clone(),
            QueryMsg::Balance {
                address: "seller".to_string(),
            },
        )
        .unwrap();
        let bal: cw20::BalanceResponse = from_json(&bal_res).unwrap();
        assert_eq!(bal.balance, Uint128::new(ONE_TOKEN));

        let entry_res = query(
            deps.as_ref(),
            env.clone(),
            QueryMsg::GetVaultEntry { index: 0 },
        )
        .unwrap();
        let entry: VaultEntryResponse = from_json(&entry_res).unwrap();
        assert_eq!(entry.ipfs_cid_hash, "cid_hash_1");
        assert!(entry.active);

        let active_res = query(deps.as_ref(), env.clone(), QueryMsg::ActiveCount {}).unwrap();
        let active: ActiveCountResponse = from_json(&active_res).unwrap();
        assert_eq!(active.count, 1);
    }

    #[test]
    fn deposit_with_invalid_proof_fails() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        setup_contract(&mut deps, env.clone());
        let info = mock_info("seller", &[]);
        let (_proof_hex, commitment_hex, nullifier) = generate_proof(env.clone(), "seller");
        let res = execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::Deposit {
                proof_hex: hex::encode([0u8; 608]),
                commitment_hex: commitment_hex,
                num_bits: 32,
                ipfs_cid_hash: "cid".to_string(),
                ct_key_hash: "key".to_string(),
                oracle_signature: "deadbeef".to_string(),
                payload_nullifier: nullifier,
            },
        );
        assert!(res.is_err());
    }

    #[test]
    fn deposit_with_invalid_hex_fails() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        setup_contract(&mut deps, env.clone());
        let info = mock_info("seller", &[]);
        let (_proof_hex, commitment_hex, nullifier) = generate_proof(env.clone(), "seller");
        let res = execute(
            deps.as_mut(),
            env,
            info,
            ExecuteMsg::Deposit {
                proof_hex: "invalid_hex".to_string(),
                commitment_hex: commitment_hex,
                num_bits: 32,
                ipfs_cid_hash: "cid".to_string(),
                ct_key_hash: "key".to_string(),
                oracle_signature: "deadbeef".to_string(),
                payload_nullifier: nullifier,
            },
        );
        assert!(res.is_err());
    }

    #[test]
    fn deposit_with_invalid_bits_fails() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        setup_contract(&mut deps, env.clone());
        let info = mock_info("seller", &[]);
        let (proof_hex, commitment_hex, nullifier) = generate_proof(env.clone(), "seller");
        let res = execute(
            deps.as_mut(),
            env,
            info,
            ExecuteMsg::Deposit {
                proof_hex: proof_hex,
                commitment_hex: commitment_hex,
                num_bits: 15,
                ipfs_cid_hash: "cid".to_string(),
                ct_key_hash: "key".to_string(),
                oracle_signature: "deadbeef".to_string(),
                payload_nullifier: nullifier,
            },
        );
        assert!(res.is_err());
    }

    #[test]
    fn multiple_deposits_increment_index() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        setup_contract(&mut deps, env.clone());
        deposit_valid(&mut deps, env.clone(), "seller");
        deposit_valid(&mut deps, env.clone(), "seller");

        let active: ActiveCountResponse =
            from_json(&query(deps.as_ref(), env.clone(), QueryMsg::ActiveCount {}).unwrap())
                .unwrap();
        assert_eq!(active.count, 2);

        let bal: cw20::BalanceResponse = from_json(
            &query(
                deps.as_ref(),
                env.clone(),
                QueryMsg::Balance {
                    address: "seller".to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(bal.balance, Uint128::new(ONE_TOKEN * 2));
    }

    // ── DEPRECATED: BurnAndClaim Tests (replaced by two-phase oracle flow) ──
    //
    // #[test]
    // fn burn_and_claim_insufficient_balance() {
    //     let mut deps = mock_dependencies();
    //     let env = mock_env();
    //     setup_contract(&mut deps, env.clone());
    //     let info = mock_info("buyer", &[]);
    //     let res = execute(
    //         deps.as_mut(),
    //         env,
    //         info,
    //         ExecuteMsg::BurnAndClaim {
    //             buyer_x25519_pubkey: "aa".repeat(32),
    //         },
    //     );
    //     assert_eq!(res.unwrap_err(), ContractError::NoTokenToBurn {});
    // }
    //
    // #[test]
    // fn burn_and_claim_insufficient_vault_depth() {
    //     let mut deps = mock_dependencies();
    //     let env = mock_env();
    //     setup_contract(&mut deps, env.clone());
    //     for _ in 0..4 {
    //         deposit_valid(&mut deps, env.clone(), "seller");
    //     }
    //     let info = mock_info("seller", &[]);
    //     let res = execute(
    //         deps.as_mut(),
    //         env,
    //         info,
    //         ExecuteMsg::BurnAndClaim {
    //             buyer_x25519_pubkey: "aa".repeat(32),
    //         },
    //     );
    //     match res.unwrap_err() {
    //         ContractError::InsufficientVaultDepth {
    //             required,
    //             available,
    //         } => {
    //             assert_eq!(required, 5);
    //             assert_eq!(available, 4);
    //         }
    //         e => panic!("unexpected error: {:?}", e),
    //     }
    // }
    //
    // #[test]
    // fn burn_and_claim_succeeds_at_min_depth() {
    //     let mut deps = mock_dependencies();
    //     let env = mock_env();
    //     setup_contract(&mut deps, env.clone());
    //     // Deposit 6 entries so that after claiming one, 5 remain (k-anonymity).
    //     for i in 0..6 {
    //         deposit_valid(&mut deps, env.clone(), &format!("seller{}", i));
    //     }
    //
    //     // Transfer one token to buyer.
    //     let info = mock_info("seller0", &[]);
    //     execute(
    //         deps.as_mut(),
    //         env.clone(),
    //         info,
    //         ExecuteMsg::Transfer {
    //             recipient: "buyer".to_string(),
    //             amount: Uint128::new(ONE_TOKEN),
    //         },
    //     )
    //     .unwrap();
    //
    //     let buyer_pubkey = "bb".repeat(32);
    //     let info = mock_info("buyer", &[]);
    //     let res = execute(
    //         deps.as_mut(),
    //         env.clone(),
    //         info,
    //         ExecuteMsg::BurnAndClaim {
    //             buyer_x25519_pubkey: buyer_pubkey.clone(),
    //         },
    //     )
    //     .unwrap();
    //     assert_eq!(
    //         res.attributes
    //             .iter()
    //             .find(|a| a.key == "action")
    //             .unwrap()
    //             .value,
    //         "burn_and_claim"
    //     );
    //     assert!(res.attributes.iter().any(|a| a.key == "payload_index"));
    //     assert!(res.attributes.iter().any(|a| a.key == "ipfs_cid_hash"));
    //     assert_eq!(
    //         res.attributes
    //             .iter()
    //     //
    //     //     // Verify token was burned.
    //     //     let bal: cw20::BalanceResponse = from_json(
    //     //         &query(
    //     //             deps.as_ref(),
    //     //             env.clone(),
    //     //             QueryMsg::Balance {
    //     //                 address: "buyer".to_string(),
    //     //             },
    //     //         )
    //     //         .unwrap(),
    //     //     )
    //     //     .unwrap();
    //     //     assert_eq!(bal.balance, Uint128::zero());
    //     //
    //     //     // Verify active count decreased by 1.
    //     //     let active: ActiveCountResponse =
    //     //         from_json(&query(deps.as_ref(), env.clone(), QueryMsg::ActiveCount {}).unwrap())
    //     //             .unwrap();
    //     //     assert_eq!(active.count, 5);
    //     //
    //     //     // Verify claimed payload is recorded.
    //     //     let claimed: ClaimedPayloadsResponse = from_json(
    //     //         &query(
    //     //             deps.as_ref(),
    //     //             env.clone(),
    //     //             QueryMsg::GetClaimedPayloads {
    //     //                 buyer: "buyer".to_string(),
    //     //             },
    //     //         )
    //     //         .unwrap(),
    //     //     )
    //     //     .unwrap();
    //     //     assert_eq!(claimed.payload_indices.len(), 1);
    // }

    // ── DEPRECATED: Mock Randomness Tests ───────────────────────────────────
    //
    // #[test]
    // fn mock_get_randomness_is_deterministic() {
    //     let env = mock_env();
    //     let r1 = mock_get_randomness(&env, "buyer1", 100);
    //     let r2 = mock_get_randomness(&env, "buyer1", 100);
    //     assert_eq!(r1, r2, "same inputs must produce the same output");
    //     assert!(r1 < 100, "result must be in [0, range_max)");
    // }
    //
    // #[test]
    // fn mock_get_randomness_varies_with_sender() {
    //     let env = mock_env();
    //     let r1 = mock_get_randomness(&env, "buyer1", 1_000_000);
    //     let r2 = mock_get_randomness(&env, "buyer2", 1_000_000);
    //     // Extremely unlikely to collide for different senders with large range.
    //     assert_ne!(r1, r2, "different senders should produce different outputs");
    // }
    //
    // #[test]
    // fn mock_get_randomness_zero_range() {
    //     let env = mock_env();
    //     assert_eq!(mock_get_randomness(&env, "any", 0), 0);
    // }

    // ── Fresh Proof Generation Tests ────────────────────────────────────

    #[test]
    fn deposit_with_fresh_proof() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        setup_contract(&mut deps, env.clone());

        let (proof_hex, commitment_hex, nullifier) = generate_proof(env.clone(), "seller");

        let info = mock_info("seller", &[]);
        let res = execute(
            deps.as_mut(),
            env,
            info,
            ExecuteMsg::Deposit {
                proof_hex,
                commitment_hex,
                num_bits: 32,
                ipfs_cid_hash: "fresh_cid".to_string(),
                ct_key_hash: "fresh_key".to_string(),
                oracle_signature: "cafebabe".to_string(),
                payload_nullifier: nullifier,
            },
        )
        .unwrap();
        assert_eq!(
            res.attributes
                .iter()
                .find(|a| a.key == "is_valid")
                .unwrap()
                .value,
            "true"
        );
    }

    // ── Replay Prevention Tests ─────────────────────────────────────────

    #[test]
    fn duplicate_commitment_rejected() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        setup_contract(&mut deps, env.clone());

        let info = mock_info("seller", &[]);

        let (proof_hex, commitment_hex, nullifier) = generate_proof(env.clone(), "seller");
        execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            ExecuteMsg::Deposit {
                proof_hex: proof_hex.clone(),
                commitment_hex: commitment_hex.clone(),
                num_bits: 32,
                ipfs_cid_hash: "cid1".to_string(),
                ct_key_hash: "key1".to_string(),
                oracle_signature: "deadbeef".to_string(),
                payload_nullifier: nullifier.clone(),
            },
        )
        .unwrap();

        let (proof_hex2, _, nullifier2) = generate_proof(env.clone(), "seller");
        // Second deposit with the same commitment_hex must fail.
        let res = execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::Deposit {
                proof_hex: proof_hex2,
                commitment_hex: commitment_hex,
                num_bits: 32,
                ipfs_cid_hash: "cid2".to_string(),
                ct_key_hash: "key2".to_string(),
                oracle_signature: "deadbeef".to_string(),
                payload_nullifier: nullifier2,
            },
        );
        assert_eq!(res.unwrap_err(), ContractError::CommitmentAlreadyUsed {});
    }

    // ── Oracle Signature Tests ──────────────────────────────────────────

    #[test]
    fn empty_oracle_signature_rejected() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        setup_contract(&mut deps, env.clone());

        let info = mock_info("seller", &[]);
        let (proof_hex, commitment_hex, nullifier) = generate_proof(env.clone(), "seller");
        let res = execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::Deposit {
                proof_hex: proof_hex,
                commitment_hex: commitment_hex,
                num_bits: 32,
                ipfs_cid_hash: "cid".to_string(),
                ct_key_hash: "key".to_string(),
                oracle_signature: "".to_string(),
                payload_nullifier: nullifier,
            },
        );
        assert_eq!(res.unwrap_err(), ContractError::InvalidOracleSignature {});
    }

    #[test]
    fn non_hex_oracle_signature_rejected() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        setup_contract(&mut deps, env.clone());

        let info = mock_info("seller", &[]);
        let (proof_hex, commitment_hex, nullifier) = generate_proof(env.clone(), "seller");
        let res = execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::Deposit {
                proof_hex: proof_hex,
                commitment_hex: commitment_hex,
                num_bits: 32,
                ipfs_cid_hash: "cid".to_string(),
                ct_key_hash: "key".to_string(),
                oracle_signature: "not_valid_hex!!!".to_string(),
                payload_nullifier: nullifier,
            },
        );
        assert_eq!(res.unwrap_err(), ContractError::InvalidOracleSignature {});
    }

    // ── DEPRECATED: Vault Starvation Fallback Test (used BurnAndClaim) ──
    //
    // #[test]
    // fn burn_and_claim_bypasses_depth_after_timeout() {
    //     let mut deps = mock_dependencies();
    //     // Use min_vault_depth = 5 but only deposit 2 entries; set a short
    //     // timeout so we can test the fallback.
    //     let msg = InstantiateMsg {
    //         token_name: "RB90".to_string(),
    //         token_symbol: "RB90".to_string(),
    //         token_decimals: 6,
    //         min_vault_depth: 5,
    //         fallback_timeout_blocks: Some(10),
    //         oracle_address: None,
    //         oracle_timeout_blocks: None,
    //     };
    //     let info = mock_info("creator", &[]);
    //     let mut env = mock_env();
    //     instantiate(deps.as_mut(), env.clone(), info, msg).unwrap();
    //
    //     // Deposit 2 entries (below min_vault_depth of 5).
    //     deposit_valid(&mut deps, env.clone(), "seller0");
    //     deposit_valid(&mut deps, env.clone(), "seller1");
    //
    //     // Transfer token to buyer.
    //     let info = mock_info("seller0", &[]);
    //     execute(
    //         deps.as_mut(),
    //         env.clone(),
    //         info,
    //         ExecuteMsg::Transfer {
    //             recipient: "buyer".to_string(),
    //             amount: Uint128::new(ONE_TOKEN),
    //         },
    //     )
    //     .unwrap();
    //
    //     // Attempt claim at current block height — should fail (not enough depth, timeout not elapsed).
    //     let info = mock_info("buyer", &[]);
    //     let res = execute(
    //         deps.as_mut(),
    //         env.clone(),
    //         info,
    //         ExecuteMsg::BurnAndClaim {
    //             buyer_x25519_pubkey: "cc".repeat(32),
    //         },
    //     );
    //     assert!(matches!(
    //         res.unwrap_err(),
    //         ContractError::InsufficientVaultDepth { .. }
    //     ));
    //
    //     // Advance block height past fallback timeout and retry — should succeed.
    //     env.block.height += 100; // well past the 10-block timeout
    //     let info = mock_info("buyer", &[]);
    //     let res = execute(
    //         deps.as_mut(),
    //         env.clone(),
    //         info,
    //         ExecuteMsg::BurnAndClaim {
    //             buyer_x25519_pubkey: "cc".repeat(32),
    //         },
    //     )
    //     .unwrap();
    //     assert_eq!(
    //         res.attributes
    //             .iter()
    //             .find(|a| a.key == "fallback_used")
    //             .unwrap()
    //             .value,
    //         "true"
    //     );
    // }

    // ── Nullifier Sybil Resistance Tests ────────────────────────────────

    #[test]
    fn duplicate_nullifier_rejected() {
        // Two deposits with different commitments but the same payload_nullifier
        // must fail: this is the Sybil resistance check.
        let mut deps = mock_dependencies();
        let env = mock_env();
        setup_contract(&mut deps, env.clone());

        let (proof_hex, commitment_hex, nullifier) = generate_proof(env.clone(), "seller");

        let info = mock_info("seller", &[]);
        execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            ExecuteMsg::Deposit {
                proof_hex: proof_hex,
                commitment_hex: commitment_hex,
                num_bits: 32,
                ipfs_cid_hash: "cid_a".to_string(),
                ct_key_hash: "key_a".to_string(),
                oracle_signature: "deadbeef".to_string(),
                payload_nullifier: nullifier.clone(), // shared nullifier for both deposits
            },
        )
        .unwrap();

        let (proof_hex2, commitment_hex2, _) = generate_proof(env.clone(), "seller");

        // Second deposit — different proof + commitment, same nullifier.
        let res = execute(
            deps.as_mut(),
            env,
            info,
            ExecuteMsg::Deposit {
                proof_hex: proof_hex2,
                commitment_hex: commitment_hex2,
                num_bits: 32,
                ipfs_cid_hash: "cid_b".to_string(),
                ct_key_hash: "key_b".to_string(),
                oracle_signature: "deadbeef".to_string(),
                payload_nullifier: nullifier, // same nullifier as first deposit
            },
        );
        assert_eq!(res.unwrap_err(), ContractError::NullifierAlreadyUsed {});
    }

    #[test]
    fn invalid_nullifier_format_rejected() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        setup_contract(&mut deps, env.clone());

        let info = mock_info("seller", &[]);
        let (proof_hex, commitment_hex, _) = generate_proof(env.clone(), "seller");
        // Too short.
        let res = execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            ExecuteMsg::Deposit {
                proof_hex: proof_hex,
                commitment_hex: commitment_hex,
                num_bits: 32,
                ipfs_cid_hash: "cid".to_string(),
                ct_key_hash: "key".to_string(),
                oracle_signature: "deadbeef".to_string(),
                payload_nullifier: "abcd".to_string(), // invalid format
            },
        );
        assert_eq!(res.unwrap_err(), ContractError::InvalidNullifier {});

        // Uppercase hex characters.
        let (proof_hex, commitment_hex, _) = generate_proof(env.clone(), "seller");

        let res = execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            ExecuteMsg::Deposit {
                proof_hex: proof_hex,
                commitment_hex: commitment_hex,
                num_bits: 32,
                ipfs_cid_hash: "cid".to_string(),
                ct_key_hash: "key".to_string(),
                oracle_signature: "deadbeef".to_string(),
                payload_nullifier:
                    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
            },
        );
        assert_eq!(res.unwrap_err(), ContractError::InvalidNullifier {});

        // Non-hex characters.
        let (proof_hex, commitment_hex, _) = generate_proof(env.clone(), "seller");
        let res = execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::Deposit {
                proof_hex: proof_hex,
                commitment_hex: commitment_hex,
                num_bits: 32,
                ipfs_cid_hash: "cid".to_string(),
                ct_key_hash: "key".to_string(),
                oracle_signature: "deadbeef".to_string(),
                payload_nullifier:
                    "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz".to_string(),
            },
        );
        assert_eq!(res.unwrap_err(), ContractError::InvalidNullifier {});
    }

    // ── Asynchronous Oracle Flow Tests ──────────────────────────────────

    fn setup_contract_with_oracle(
        deps: &mut cosmwasm_std::OwnedDeps<
            cosmwasm_std::MemoryStorage,
            cosmwasm_std::testing::MockApi,
            cosmwasm_std::testing::MockQuerier,
        >,
        env: Env,
    ) {
        let msg = InstantiateMsg {
            token_name: "RangeBucket90-100".to_string(),
            token_symbol: "RB90".to_string(),
            token_decimals: 6,
            min_vault_depth: 5,
            fallback_timeout_blocks: Some(100_000),
            oracle_address: Some("oracle_relayer".to_string()),
            oracle_timeout_blocks: Some(50),
        };
        let info = mock_info("creator", &[]);
        instantiate(deps.as_mut(), env, info, msg).unwrap();
    }

    #[test]
    fn burn_and_request_emits_oracle_event() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        setup_contract_with_oracle(&mut deps, env.clone());

        // Deposit 6 entries.
        for i in 0..6 {
            deposit_valid(&mut deps, env.clone(), &format!("seller{}", i));
        }

        // Transfer token to buyer.
        let info = mock_info("seller0", &[]);
        execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::Transfer {
                recipient: "buyer".to_string(),
                amount: Uint128::new(ONE_TOKEN),
            },
        )
        .unwrap();

        // BurnAndRequest.
        let info = mock_info("buyer", &[]);
        let res = execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::BurnAndRequest {
                buyer_x25519_pubkey: "aa".repeat(32),
            },
        )
        .unwrap();

        // Check action attribute.
        assert_eq!(
            res.attributes
                .iter()
                .find(|a| a.key == "action")
                .unwrap()
                .value,
            "burn_and_request"
        );

        // Check oracle_request event was emitted.
        let oracle_event = res
            .events
            .iter()
            .find(|e| e.ty == "oracle_request")
            .expect("oracle_request event must be emitted");
        assert!(oracle_event
            .attributes
            .iter()
            .any(|a| a.key == "buyer" && a.value == "buyer"));
        assert!(oracle_event
            .attributes
            .iter()
            .any(|a| a.key == "bucket_id"));

        // Verify token was burned.
        let bal: cw20::BalanceResponse = from_json(
            &query(
                deps.as_ref(),
                env.clone(),
                QueryMsg::Balance {
                    address: "buyer".to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(bal.balance, Uint128::zero());

        // Verify pending request exists.
        let pending: PendingRequestResponse = from_json(
            &query(
                deps.as_ref(),
                env.clone(),
                QueryMsg::GetPendingRequest {
                    buyer: "buyer".to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert!(pending.found);
        assert_eq!(pending.range_bucket_id, Some(6));
    }

    #[test]
    fn fulfill_randomness_completes_claim() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        setup_contract_with_oracle(&mut deps, env.clone());

        for i in 0..6 {
            deposit_valid(&mut deps, env.clone(), &format!("seller{}", i));
        }

        let info = mock_info("seller0", &[]);
        execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::Transfer {
                recipient: "buyer".to_string(),
                amount: Uint128::new(ONE_TOKEN),
            },
        )
        .unwrap();

        // Phase 1: BurnAndRequest.
        let info = mock_info("buyer", &[]);
        execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::BurnAndRequest {
                buyer_x25519_pubkey: "aa".repeat(32),
            },
        )
        .unwrap();

        // Phase 2: FulfillRandomness (by oracle).
        let info = mock_info("oracle_relayer", &[]);
        let res = execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::FulfillRandomness {
                buyer_address: "buyer".to_string(),
                random_seed: "42".to_string(),
            },
        )
        .unwrap();

        assert_eq!(
            res.attributes
                .iter()
                .find(|a| a.key == "action")
                .unwrap()
                .value,
            "fulfill_randomness"
        );
        assert!(res.attributes.iter().any(|a| a.key == "payload_index"));

        // Verify active count decreased.
        let active: ActiveCountResponse =
            from_json(&query(deps.as_ref(), env.clone(), QueryMsg::ActiveCount {}).unwrap())
                .unwrap();
        assert_eq!(active.count, 5);

        // Verify claimed payload recorded.
        let claimed: ClaimedPayloadsResponse = from_json(
            &query(
                deps.as_ref(),
                env.clone(),
                QueryMsg::GetClaimedPayloads {
                    buyer: "buyer".to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(claimed.payload_indices.len(), 1);

        // Verify pending request was consumed.
        let pending: PendingRequestResponse = from_json(
            &query(
                deps.as_ref(),
                env.clone(),
                QueryMsg::GetPendingRequest {
                    buyer: "buyer".to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!pending.found);
    }

    #[test]
    fn fulfill_randomness_rejects_non_oracle() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        setup_contract_with_oracle(&mut deps, env.clone());

        for i in 0..6 {
            deposit_valid(&mut deps, env.clone(), &format!("seller{}", i));
        }

        let info = mock_info("seller0", &[]);
        execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::Transfer {
                recipient: "buyer".to_string(),
                amount: Uint128::new(ONE_TOKEN),
            },
        )
        .unwrap();

        let info = mock_info("buyer", &[]);
        execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::BurnAndRequest {
                buyer_x25519_pubkey: "aa".repeat(32),
            },
        )
        .unwrap();

        // Non-oracle address tries to fulfill — must fail.
        let info = mock_info("attacker", &[]);
        let res = execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::FulfillRandomness {
                buyer_address: "buyer".to_string(),
                random_seed: "42".to_string(),
            },
        );
        assert_eq!(res.unwrap_err(), ContractError::UnauthorizedOracle {});
    }

    #[test]
    fn duplicate_burn_and_request_rejected() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        setup_contract_with_oracle(&mut deps, env.clone());

        for i in 0..6 {
            deposit_valid(&mut deps, env.clone(), &format!("seller{}", i));
        }

        // Transfer 2 tokens to buyer.
        let info = mock_info("seller0", &[]);
        execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            ExecuteMsg::Transfer {
                recipient: "buyer".to_string(),
                amount: Uint128::new(ONE_TOKEN),
            },
        )
        .unwrap();
        let info = mock_info("seller1", &[]);
        execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::Transfer {
                recipient: "buyer".to_string(),
                amount: Uint128::new(ONE_TOKEN),
            },
        )
        .unwrap();

        // First request succeeds.
        let info = mock_info("buyer", &[]);
        execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            ExecuteMsg::BurnAndRequest {
                buyer_x25519_pubkey: "aa".repeat(32),
            },
        )
        .unwrap();

        // Second request while first is pending — must fail.
        let res = execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::BurnAndRequest {
                buyer_x25519_pubkey: "aa".repeat(32),
            },
        );
        assert_eq!(res.unwrap_err(), ContractError::RequestAlreadyPending {});
    }

    #[test]
    fn burn_and_request_fails_without_oracle() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        // Set up without oracle.
        setup_contract(&mut deps, env.clone());

        for i in 0..6 {
            deposit_valid(&mut deps, env.clone(), &format!("seller{}", i));
        }

        let info = mock_info("seller0", &[]);
        execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::Transfer {
                recipient: "buyer".to_string(),
                amount: Uint128::new(ONE_TOKEN),
            },
        )
        .unwrap();

        let info = mock_info("buyer", &[]);
        let res = execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::BurnAndRequest {
                buyer_x25519_pubkey: "aa".repeat(32),
            },
        );
        assert_eq!(res.unwrap_err(), ContractError::OracleNotConfigured {});
    }

    #[test]
    fn fulfill_randomness_no_pending_request() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        setup_contract_with_oracle(&mut deps, env.clone());

        let info = mock_info("oracle_relayer", &[]);
        let res = execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::FulfillRandomness {
                buyer_address: "buyer".to_string(),
                random_seed: "42".to_string(),
            },
        );
        assert_eq!(res.unwrap_err(), ContractError::NoPendingRequest {});
    }

    #[test]
    fn recover_oracle_timeout_succeeds() {
        let mut deps = mock_dependencies();
        let mut env = mock_env();
        setup_contract_with_oracle(&mut deps, env.clone());

        for i in 0..6 {
            deposit_valid(&mut deps, env.clone(), &format!("seller{}", i));
        }

        let info = mock_info("seller0", &[]);
        execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::Transfer {
                recipient: "buyer".to_string(),
                amount: Uint128::new(ONE_TOKEN),
            },
        )
        .unwrap();

        // Phase 1: BurnAndRequest.
        let info = mock_info("buyer", &[]);
        execute(
            deps.as_mut(),
            env.clone(),
            info.clone(),
            ExecuteMsg::BurnAndRequest {
                buyer_x25519_pubkey: "aa".repeat(32),
            },
        )
        .unwrap();

        // Token was burned — balance should be 0.
        let bal: cw20::BalanceResponse = from_json(
            &query(
                deps.as_ref(),
                env.clone(),
                QueryMsg::Balance {
                    address: "buyer".to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(bal.balance, Uint128::zero());

        // Recovery before timeout should fail.
        let info = mock_info("buyer", &[]);
        let res = execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::RecoverOracleTimeout {},
        );
        assert!(matches!(
            res.unwrap_err(),
            ContractError::OracleTimeoutNotElapsed { .. }
        ));

        // Advance past oracle timeout (50 blocks per setup_contract_with_oracle).
        env.block.height += 100;

        // Recovery after timeout should succeed.
        let info = mock_info("buyer", &[]);
        let res = execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::RecoverOracleTimeout {},
        )
        .unwrap();

        assert_eq!(
            res.attributes
                .iter()
                .find(|a| a.key == "action")
                .unwrap()
                .value,
            "recover_oracle_timeout"
        );

        // Token should be re-minted.
        let bal: cw20::BalanceResponse = from_json(
            &query(
                deps.as_ref(),
                env.clone(),
                QueryMsg::Balance {
                    address: "buyer".to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(bal.balance, Uint128::new(ONE_TOKEN));

        // Pending request should be cleared.
        let pending: PendingRequestResponse = from_json(
            &query(
                deps.as_ref(),
                env.clone(),
                QueryMsg::GetPendingRequest {
                    buyer: "buyer".to_string(),
                },
            )
            .unwrap(),
        )
        .unwrap();
        assert!(!pending.found);
    }

    #[test]
    fn recover_oracle_timeout_no_pending() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        setup_contract_with_oracle(&mut deps, env.clone());

        let info = mock_info("buyer", &[]);
        let res = execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::RecoverOracleTimeout {},
        );
        assert_eq!(res.unwrap_err(), ContractError::NoPendingRequest {});
    }

    #[test]
    fn fulfill_randomness_invalid_seed_rejected() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        setup_contract_with_oracle(&mut deps, env.clone());

        for i in 0..6 {
            deposit_valid(&mut deps, env.clone(), &format!("seller{}", i));
        }

        let info = mock_info("seller0", &[]);
        execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::Transfer {
                recipient: "buyer".to_string(),
                amount: Uint128::new(ONE_TOKEN),
            },
        )
        .unwrap();

        let info = mock_info("buyer", &[]);
        execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::BurnAndRequest {
                buyer_x25519_pubkey: "aa".repeat(32),
            },
        )
        .unwrap();

        // Invalid random seed string should fail.
        let info = mock_info("oracle_relayer", &[]);
        let res = execute(
            deps.as_mut(),
            env.clone(),
            info,
            ExecuteMsg::FulfillRandomness {
                buyer_address: "buyer".to_string(),
                random_seed: "not_a_number".to_string(),
            },
        );
        assert_eq!(res.unwrap_err(), ContractError::InvalidRandomSeed {});
    }
}
