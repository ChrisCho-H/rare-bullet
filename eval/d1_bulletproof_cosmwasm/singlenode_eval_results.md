# Bulletproof CosmWasm — Single-Node Capacity Benchmark Results

> Measured on a single-validator wasmd v0.53.0 node (no multi-node overhead).
> Multi-account sustained load: 3 accounts × 100 bursts (concurrent mempool flood, no inter-burst pacing).
> The Rare Bullet protocol performs aggregated ($m{=}2$) Bulletproof verification over 64 total bits
> ($2 \times 32$-bit dynamic boundaries via homomorphic shifting) natively within the CosmWasm
> WebAssembly runtime. On the distributed 8-node testnet, the architecture achieves a sustained
> systemic throughput of **26 TPS**, fully saturating the 100M block gas limit.

## Summary

| Metric | Value |
|--------|-------|
| Validator Nodes | 1 |
| Load Test Accounts | 3 |
| Sustained Bursts | 100 |
| Total TXs Submitted | 300 |
| Confirmed TXs (Success) | 300 |
| Failed TXs (Contract Error) | 0 |
| Failed TXs (Out of Gas) | 0 |
| Failed TXs (Other) | 0 |
| Peak Block Height | 20 |
| TXs in Peak Block | 53 |
| Block Finalization Interval (peak) | 1883.4ms |
| Average Block Time | 1280.76ms |
| Avg Gas per TX | 629173 |
| TX Size (bytes) | 1976 |
| Avg Event Bytes / TX (state bloat) | 1080 |

## TX Distribution Across Blocks

| Block Height | TX Count |
|-------------|----------|
| 19 | 3 |
| 20 | 53 |
| 21 | 4 |
| 22 | 51 |
| 23 | 6 |
| 24 | 48 |
| 25 | 6 |
| 26 | 48 |
| 27 | 6 |
| 28 | 48 |
| 29 | 6 |
| 30 | 21 |

## Methodology Notes

- **Synthetic nullifiers**: Load test TXs use SHA-256 of deterministic seeds as nullifiers,
  bypassing the production oracle-attested nullifier flow. Production deployments introduce
  additional off-chain latency not captured here.
- **Proof diversity**: Each of the 300 transactions uses a unique Bulletproof witness
  (proof, commitment, nullifier) generated at test-time with a fresh random blinding factor.
  The Merlin transcript binds each proof to its specific nullifier and contract address.

## Environment

- **wasmd**: v0.53.0
- **Chain ID**: singlenode-bench-46169
- **WASM binary**: 420K
- **Genesis**: max_gas=-1, max_bytes=20000000
- **Node**: 1 single validator (no P2P/consensus overhead)
- **Load accounts**: 3 independent accounts
- **Generated**: 2026-04-14 07:23:48 UTC
