# Bulletproof CosmWasm — Gas Estimation Results

> Measured on a disposable wasmd v0.53.0 single-node chain.
> These are real CosmWasm gas figures from on-chain execution.
> The Rare Bullet protocol performs aggregated ($m{=}2$) Bulletproof verification
> over 64 total bits ($2 \times 32$-bit dynamic boundaries via homomorphic shifting)
> natively within the CosmWasm WebAssembly runtime via native Rust compilation.

| Operation | Gas Used |
|-----------|----------|
| Store WASM code | 2866479 |
| Instantiate (CW20 + vault config + oracle) | 193000 |
| Deposit (avg ×6, aggregated $m{=}2$ BP verify + mint + nullifier) | ~626,164 (single-node) |
| CW20 Transfer | 129907 |
| BurnAndRequest (Phase 1: burn + emit oracle_request) | 164428 |
| FulfillRandomness (Phase 2: oracle callback + O(1) swap-and-pop) | 169869 |

### Per-Deposit Breakdown

| Deposit # | Gas Used |
|-----------|----------|
| Deposit 0 | 627846 |
| Deposit 1 | 624134 |
| Deposit 2 | 625685 |
| Deposit 3 | 625504 |
| Deposit 4 | 626661 |
| Deposit 5 | 627152 |

> **Note:** Per-deposit measurements reflect the raw single-node empirical values.
> The finalized paper metric (~631K gas) represents the fully-loaded Deposit state
> machine inclusive of aggregated Bulletproof verification, CW-20 minting,
> nullifier-based Sybil resistance, and persistent vault state updates across the
> 8-node distributed testnet evaluation (see main.tex §8).

### Finalized Empirical Metrics (from paper §8)

| Metric | Value |
|--------|-------|
| Fully-loaded Deposit state machine | ~631K gas (~631,254) |
| Relative compute efficiency (vs CW-20 baseline) | 4.8× multiplier |
| Isolated WASM execution latency | 30.2 ms |
| Systemic testnet throughput (100M block gas limit) | 26 TPS |

### Environment

- **wasmd**: v0.53.0
- **Chain ID**: gas-test-19812
- **WASM binary**: 336K
- **Generated**: 2026-04-02 09:47:55 UTC
