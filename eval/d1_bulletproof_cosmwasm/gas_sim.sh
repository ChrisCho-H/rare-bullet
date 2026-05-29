#!/usr/bin/env bash
# ============================================================================
#  Rare Bullet — State Transition & Lifecycle Simulation Runner
# ============================================================================
#  This script runs the cw-multi-test integration tests that exercise the
#  Rare Bullet CosmWasm contract through its full lifecycle:
#
#    instantiate  →  deposit (aggregated m=2 BP verify + mint + nullifier)
#                →  BurnAndRequest → FulfillRandomness (two-phase oracle flow)
#
#  The contract performs aggregated (m=2) Bulletproof verification over 64 total
#  bits (2×32-bit dynamic boundaries via homomorphic shifting) within the native
#  CosmWasm WebAssembly runtime, minting Data-Backed Range Tokens.
#
#  It reports wall-clock timings for each step, validating correct state-
#  machine transitions and algorithmic logic. On-chain gas costs were
#  measured separately via a live CosmWasm testnet deployment (paper §8).
#
#  Usage:
#    bash eval/d1_bulletproof_cosmwasm/gas_sim.sh
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACT_DIR="${SCRIPT_DIR}/bulletproof-contract"

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║   Bulletproof CosmWasm — State Transition & Lifecycle Simulation    ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""
echo "Contract directory: ${CONTRACT_DIR}"
echo ""

cd "${CONTRACT_DIR}"

echo "── Running integration tests (gas_simulation + e2e_experiment) ─────────"
echo ""

cargo test --test gas_simulation --test e2e_experiment -- --nocapture 2>&1

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║   Simulation complete                                              ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
