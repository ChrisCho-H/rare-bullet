# Rare Bullet

**Privacy-Preserving Data Trading via WASM-Native Bulletproofs and AMM Liquidity**

Rare Bullet resolves the **Privacy-Liquidity Paradox** in decentralized data markets: transparent pricing exposes confidential metadata, while opaque privacy pools trigger adverse-selection collapse. Our architecture segments encrypted data into cryptographically verified *Range Buckets*, minting fungible **Data-Backed Range Tokens** tradable on standard AMMs—without metadata leakage or trusted setups.

---

## Architecture Overview

### Hybrid Trust Model

The protocol compartmentalizes trust into three independent failure domains:

| Domain | Mechanism | Hardware Trust? |
|--------|-----------|-----------------|
| **Computational Integrity** | Aggregated ($m = 2$) Bulletproof verification + CW-20 minting on-chain via CosmWasm | **No** — pure cryptography (DL assumption) + BFT consensus |
| **Data Semantic Integrity** | TEE-based TLS oracle (e.g., Town Crier) attests score-to-payload binding | Yes — SGX enclave for ingestion only |
| **Key Custody** | $(t, n)$-Threshold TEE network (e.g., Tora) for fair-exchange decryption | Yes — SGX enclaves for key shares only |

**Key security property:** If the TEE network suffers catastrophic compromise, the attacker can only breach *confidentiality* (decrypt data)—they *cannot* forge tokens or drain AMM liquidity.

### Protocol Flow (Deposit → Mint → Trade → Claim)

**Phase 1 — Encrypted Deposit.** The seller encrypts payload $P$ with key $K_{sym}$, obtains a TLS oracle attestation binding score $s$ to $P$, computes a Pedersen commitment $C = sG + rH$, generates a Bulletproof $\pi$ proving $s \in B_k = [a_k, b_k)$, and submits $(cid, ct\_key, C, \pi, nul)$ on-chain. A deterministic payload nullifier $nul = \text{SHA256}(\text{canonical}(P))$ prevents Sybil-style vault dilution via commitment re-randomization.

**Phase 2 — On-Chain Verification & Minting.** The CosmWasm contract homomorphically derives two shifted commitments:

$$C_1 = C - a_k G, \quad C_2 = (b_k - 1)G - C$$

and verifies the aggregated Bulletproof $\pi$ against $(C_1, C_2)$ in a single transaction, simultaneously enforcing both boundaries. A domain-separated Merlin transcript provides consensus-safe deterministic randomness for the verifier's multi-scalar multiplication (bypassing WASM's prohibition on `getrandom`/`OsRng`). On success, the contract mints exactly 1.0 CW-20 Range Token $T_k$ to the seller. **No hardware trust required.**

**Phase 3 — AMM Liquidity.** The seller swaps $T_k$ for stablecoins on any CW-20-compatible AMM. A buyer seeking data in tier $B_k$ purchases $T_k$ at market price.

**Phase 4 — Burn-to-Claim.** The buyer burns 1.0 $T_k$ via `BurnAndRequest`. The contract enforces a $k_{min}$-anonymity vault depth threshold (with a temporal liveness fallback for starved vaults), emits an oracle request, and upon receiving a random seed via `FulfillRandomness`, pseudorandomly selects a vault entry using $\mathcal{O}(1)$ swap-and-pop. The Threshold TEE Committee observes the on-chain claim event and releases the decryption key to the buyer. A timeout recovery mechanism re-mints the token if the TEE committee fails to respond.

---

## Evaluation

### Implementation

Single unified CosmWasm smart contract. Bulletproof prover/verifier in Rust (`bulletproofs` v4.0.0, `curve25519-dalek-ng` v4.1.1). Compiles to ~335 KB WASM binary via `cosmwasm-std` v1.5, deployed on `wasmd` v0.53.0.

### On-Chain Gas Costs (wasmd v0.53.0, single-node)

| Operation | Gas Used |
|-----------|----------|
| `Store WASM code` (contract upload) | 2,866,479 |
| `Instantiate` (CW-20 config + vault + oracle init) | 193,000 |
| `Deposit` (aggregated BP verify + CW-20 mint + nullifier, avg ×6) | **~626,164** |
| `Transfer` (standard CW-20 baseline) | 129,907 |
| `BurnAndRequest` (burn + emit oracle_request) | 164,428 |
| `FulfillRandomness` (oracle callback + swap-and-pop) | 169,869 |

> Values from `eval/d1_bulletproof_cosmwasm/gas_estimation_results.md` (reproducible via `wasmd_gas_estimate.sh`). The finalized paper §8 metric (~631K gas for Deposit) reflects the fully-loaded state machine on the distributed 8-node testnet with sustained load (see `singlenode_eval_results.md` for capacity benchmark data).

### Cross-VM Performance Comparison

| Metric | Standard EVM Bulletproof | VeRange (Type-1) | Rare Bullet |
|--------|--------------------------|-------------------|-------------|
| Execution Environment | EVM (BN-128) | EVM (BN-128) | CosmWasm (Native Rust) |
| Gas Cost (64-bit range) | ~3,704K | ~351K | ~631K |
| Token Transfer Baseline | ~65K (ERC-20) | ~65K (ERC-20) | ~130K (CW-20) |
| **Relative Compute Multiplier** | **57.0×** | **5.4×** | **4.8×** |
| Includes Token Minting + Sybil Resistance | No | No | **Yes** |

Rare Bullet's 631K measurement encompasses a full state machine (verification + minting + nullifier + persistent state), making the 4.8× multiplier a conservative upper bound.

### WASM VM Micro-Benchmarks (cosmwasm-vm, Cranelift backend)

Testbed: Google Cloud `e2-standard-2` (2 vCPUs, 8 GiB RAM, Ubuntu 24.04 LTS, x86_64).

| Entry Point | Primary Operation | Execution Time |
|-------------|-------------------|----------------|
| `instantiate` | CW20 & Vault Initialization | 130.32 µs |
| `Deposit` | Bulletproof Verify + Mint + Nullifier | **30.19 ms** |
| `BurnAndRequest` | CW20 Burn + Oracle Request Emit | 82.01 µs |
| `FulfillRandomness` | O(1) Vault Swap-and-Pop Selection | 99.82 µs |
| `Transfer` | CW20 Token Transfer | 31.48 µs |
| `ActiveCount` | Storage Read (Vault Count) | 16.11 µs |

### Native vs WASM Bulletproof Micro-Benchmarks (Criterion)

Each Criterion iteration selects from a rotating pool of 128 unique pre-generated proofs with domain-separated transcripts matching on-chain execution.

| Operation | Native (ms) | WASM/Wasmtime (ms) | Overhead |
|-----------|-------------|---------------------|----------|
| Proving | 13.611 | 96.118 | ~7.1× |
| Verification | 1.809 | 13.043 | ~7.2× |
| Proof Size (64-bit) | 672 bytes | — | — |

> The ~7× WASM overhead is consistent with published Ristretto255 compilation penalties. Browser engines (V8, SpiderMonkey) may add 1.5–2× additional overhead from GC/sandboxing.

### Throughput & Saturation

**Single-Node (e2-standard-2):**

| Burst Config | TXs Submitted | Success Rate | Peak Block Time | Effective TPS |
|--------------|---------------|--------------|-----------------|---------------|
| 40×5 | 200 | 100% | 6940.2 ms | 28.8 tx/s |
| 50×5 | 250 | 100% | 8680.1 ms | 28.8 tx/s |
| 100×5 | 500 | 100% | 17189.9 ms | 29.1 tx/s |

**8-Node Testnet (5 validators + 3 full nodes, 3 geographic regions):**

| Metric | Result |
|--------|--------|
| Gas Saturation | 99.84M / 100M block gas limit (156 TXs/block) |
| Peak Throughput | **26 TPS** at 6s block interval |
| Per-Transaction Latency | ~38.4 ms |

### Latency Decomposition

| Layer | Latency | Notes |
|-------|---------|-------|
| Pure cryptographic verification (WASM VM) | 30.2 ms | Bulletproof inner-product argument |
| Cosmos SDK state-transition (IAVL + AnteHandler) | ~4.2 ms | Deterministic storage overhead |
| Decentralization overhead (P2P gossip + CometBFT) | ~4.0 ms | Network consensus cost |
| **Total per-TX** | **~38.4 ms** | |

### End-to-End Acquisition Path

| Step | Duration |
|------|----------|
| Seller Deposit (1 block) | ~6s |
| Buyer AMM purchase (1 block) | ~6s |
| Oracle request + TEE key release | ~6s + ~400 ms |
| Oracle callback (1 block) | ~6s |
| **Total** | **~24–25s** |

---

## Artifacts & Reproduction

### Repository Structure

```
eval/
├── d1_bulletproof_cosmwasm/           # CosmWasm contract + gas estimation
│   ├── bulletproof-contract/          # Unified CosmWasm smart contract (Rust)
│   │   ├── bulletproof_contract.wasm  # Pre-built optimized binary
│   │   ├── src/                       # Contract source
│   │   └── tests/                     # Integration tests (gas_simulation, e2e_experiment, gen_testdata)
│   ├── wasmd_gas_estimate.sh          # Single-node gas measurement script
│   ├── gas_sim.sh                     # Integration test runner (cw-multi-test)
│   ├── setup_singlenode_bench.sh      # Multi-account sustained load benchmark
│   ├── gas_estimation_results.md      # Gas measurement results
│   └── singlenode_eval_results.md     # Single-node capacity benchmark results
├── d1_wasm_vm_bench/                  # cosmwasm-vm Criterion benchmarks
│   ├── benches/bench_wasmvm.rs        # Criterion benchmark source
│   └── README.md                      # Detailed methodology & variance analysis
└── ...
```

### CI Workflows

| Workflow | File | Description |
|----------|------|-------------|
| Build & Test | `.github/workflows/d1-cosmwasm-ci.yml` | Builds contract, runs all integration tests |
| Gas Estimation | `.github/workflows/d1-wasmd-gas-estimate.yml` | Optimized WASM build → wasmd v0.53.0 single-node → real gas measurement |
| WASM VM Bench | `.github/workflows/d1-wasm-vm-bench.yml` | Criterion CPU overhead benchmarks via `cosmwasm-vm` (Cranelift) |
| Single-Node Eval | `.github/workflows/d1-singlenode-eval.yml` | Multi-account sustained load capacity benchmark |

### Running Locally

#### CosmWasm Integration Tests

```bash
cd eval/d1_bulletproof_cosmwasm/bulletproof-contract
cargo test -- --nocapture
```

Or use the convenience wrapper:

```bash
bash eval/d1_bulletproof_cosmwasm/gas_sim.sh
```

Requirements: Rust ≥ 1.70

#### WASM VM CPU Benchmarks

```bash
cd eval/d1_wasm_vm_bench
cargo bench
```

Requirements: Rust ≥ 1.70. Uses the pre-built WASM binary from `eval/d1_bulletproof_cosmwasm/bulletproof-contract/bulletproof_contract.wasm`.

#### Real Gas Estimation (wasmd)

```bash
# 1. Build optimized WASM (requires Docker)
cd eval/d1_bulletproof_cosmwasm/bulletproof-contract
docker run --rm -v "$(pwd)":/code \
  --mount type=volume,source="bulletproof_contract_cache",target=/target \
  --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
  cosmwasm/optimizer:0.16.1

# 2. Generate test transaction data
cargo test --test gen_testdata -- --ignored --nocapture

# 3. Run gas estimation (requires wasmd on PATH)
cd ..
bash wasmd_gas_estimate.sh
# Results written to gas_estimation_results.md
```

Requirements: Docker, Go ≥ 1.21, wasmd v0.53.0 (`go install github.com/CosmWasm/wasmd/cmd/wasmd@v0.53.0`), Rust ≥ 1.70

#### Single-Node Capacity Benchmark

```bash
# Requires wasmd on PATH + Docker for WASM build
bash eval/d1_bulletproof_cosmwasm/setup_singlenode_bench.sh
# Results written to singlenode_eval_results.md
```

#### Native/WASM Bulletproof Micro-Benchmarks

The Native vs WASM comparison data in the evaluation section above is sourced from the paper (§8). The WASM VM benchmarks (which measure contract entry-point execution latency) are reproducible via `eval/d1_wasm_vm_bench/cargo bench` as described above.

---

## License

See [LICENSE](LICENSE) for details.
