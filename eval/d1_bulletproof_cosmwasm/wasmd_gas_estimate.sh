#!/usr/bin/env bash
# ============================================================================
#  Rare Bullet — Real Gas Estimation via wasmd Single-Node Chain
# ============================================================================
#  Spins up a disposable wasmd node, uploads the compiled Bulletproof CosmWasm
#  contract, and executes each contract method capturing actual CosmWasm gas
#  consumption from transaction results. The contract performs aggregated (m=2)
#  Bulletproof verification over 64 total bits (2×32-bit dynamic boundaries
#  via homomorphic shifting) within the native CosmWasm WebAssembly runtime.
#  Finalized empirical metric: ~631K gas for the fully-loaded Deposit state
#  machine (4.8× compute multiplier vs CW-20 baseline).
#
#  Prerequisites:
#    - wasmd binary on PATH (v0.50+ recommended)
#    - Contract WASM built at target/wasm32-unknown-unknown/release/
#    - Test transaction data in test_tx_data/ (cargo test --test gen_testdata)
#
#  Usage:
#    bash eval/d1_bulletproof_cosmwasm/wasmd_gas_estimate.sh
# ============================================================================

set -euo pipefail

# ── OS Detection & Portability ──────────────────────────────────────────────
OS_TYPE="$(uname -s)"
IS_MACOS=false
[ "$OS_TYPE" = "Darwin" ] && IS_MACOS=true

# Portable sed in-place editing.
sed_inplace() {
    if $IS_MACOS; then
        sed -i '' "$@"
    else
        sed -i "$@"
    fi
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACT_DIR="${SCRIPT_DIR}/bulletproof-contract"
# Prefer the optimized artifact (built by cosmwasm/optimizer Docker).
# Falls back to the release build if artifacts/ doesn't exist.
if [ -f "${CONTRACT_DIR}/artifacts/bulletproof_contract.wasm" ]; then
    WASM_FILE="${CONTRACT_DIR}/artifacts/bulletproof_contract.wasm"
elif [ -f "${SCRIPT_DIR}/bulletproof_contract.wasm" ]; then
    WASM_FILE="${SCRIPT_DIR}/bulletproof_contract.wasm"
else
    WASM_FILE="${CONTRACT_DIR}/target/wasm32-unknown-unknown/release/bulletproof_contract.wasm"
fi
TX_DATA_DIR="${CONTRACT_DIR}/test_tx_data"
WASMD_HOME="/tmp/wasmd-gas-test-$$"
CHAIN_ID="gas-test-$$"
DENOM="ustake"
KEYRING="test"
GAS_PRICES="0.025${DENOM}"

# Use random high ports to avoid conflicts
RPC_PORT=$((26657 + (RANDOM % 1000)))
P2P_PORT=$((26656 + (RANDOM % 1000) + 1000))
GRPC_PORT=$((9090 + (RANDOM % 1000)))
API_PORT=$((1317 + (RANDOM % 1000)))
RPC_ADDR="tcp://127.0.0.1:${RPC_PORT}"

# Output file
RESULTS_FILE="${SCRIPT_DIR}/gas_estimation_results.md"

NODE_PID=""

# ── Helpers ──────────────────────────────────────────────────────────────────

cleanup() {
    echo ""
    echo "── Cleaning up..."
    if [ -n "${NODE_PID}" ] && kill -0 "$NODE_PID" 2>/dev/null; then
        kill "$NODE_PID" 2>/dev/null || true
        wait "$NODE_PID" 2>/dev/null || true
    fi
    rm -rf "$WASMD_HOME"
}
trap cleanup EXIT

wcmd() {
    wasmd --home "$WASMD_HOME" "$@"
}

wait_for_block() {
    local max=30
    for _ in $(seq 1 $max); do
        local height
        height=$(wcmd status --node "$RPC_ADDR" 2>/dev/null | \
            python3 -c "import sys,json; print(json.load(sys.stdin)['sync_info']['latest_block_height'])" 2>/dev/null || echo "0")
        if [ "$height" -gt "0" ] 2>/dev/null; then
            return 0
        fi
        sleep 1
    done
    echo "ERROR: Node did not produce blocks within ${max}s" >&2
    return 1
}

wait_for_tx() {
    local txhash="$1"
    local max=15
    for _ in $(seq 1 $max); do
        local result
        result=$(wcmd query tx "$txhash" --output json --node "$RPC_ADDR" 2>/dev/null || echo "")
        if [ -n "$result" ] && [ -n "$(echo "$result" | json_field height)" ]; then
            echo "$result"
            return 0
        fi
        sleep 1
    done
    echo "{}"
}

get_gas() {
    python3 -c "
import sys, json
try:
    d = json.load(sys.stdin)
    # In Cosmos, code 0 means success. Anything else is an error.
    if d.get('code', 0) != 0:
        raw_log = d.get('raw_log', 'unknown error')
        print(f'\n❌ FAILED ON-CHAIN (code {d.get(\"code\")}):\n{raw_log}\n', file=sys.stderr)
        sys.exit(1)
    print(d.get('gas_used', 'N/A'))
except Exception as e:
    print(f'PARSE_ERROR: {e}', file=sys.stderr)
    sys.exit(1)
" <<< "$1"
# ^^^ CRITICAL: Ensure `2>/dev/null` is REMOVED from the end of the line above!
}
# Extract a top-level field from JSON on stdin; returns empty string on failure.
json_field() {
    python3 -c "import sys,json; print(json.load(sys.stdin).get('$1',''))" 2>/dev/null || echo ""
}

# Extract an event attribute value from a Cosmos tx JSON on stdin.
# Usage: echo "$TX_JSON" | event_attr <key> [default]
event_attr() {
    local key="$1" default="${2:-}"
    python3 -c "
import sys, json
data = json.load(sys.stdin)
for ev in data.get('events', []):
    for attr in ev.get('attributes', []):
        if attr.get('key') == '$key':
            print(attr['value']); sys.exit(0)
print('$default')
" 2>/dev/null || echo "$default"
}

# Execute a contract message, wait for on-chain inclusion, and print gas_used.
# Usage: exec_contract_gas <json_msg> <sender_key>
exec_contract_gas() {
    local msg="$1" from="$2"
    local result txhash tx
    result=$(wcmd tx wasm execute "$CONTRACT_ADDR" "$msg" --from "$from" $TX_FLAGS 2>/dev/null || echo "{}")
    txhash=$(echo "$result" | json_field txhash)
    if [ -n "$txhash" ]; then
        tx=$(wait_for_tx "$txhash")
        get_gas "$tx"
    else
        echo "FAILED"
    fi
}

# ── Validation ───────────────────────────────────────────────────────────────

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║   Bulletproof CosmWasm — Real Gas Estimation (wasmd)               ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

if ! command -v wasmd &>/dev/null; then
    echo "ERROR: wasmd not found on PATH." >&2
    echo "Install: go install github.com/CosmWasm/wasmd/cmd/wasmd@latest" >&2
    exit 1
fi
echo "  wasmd version: $(wasmd version 2>/dev/null || echo 'unknown')"

if [ ! -f "$WASM_FILE" ]; then
    echo "  Building WASM binary via cosmwasm/optimizer Docker..."
    (cd "$CONTRACT_DIR" && docker run --rm \
        -v "$(pwd)":/code \
        --mount type=volume,source="$(basename "$(pwd)")_cache",target=/target \
        --mount type=volume,source=registry_cache,target=/usr/local/cargo/registry \
        cosmwasm/optimizer:0.16.1 2>&1 | tail -5)
    if [ -f "${CONTRACT_DIR}/artifacts/bulletproof_contract.wasm" ]; then
        WASM_FILE="${CONTRACT_DIR}/artifacts/bulletproof_contract.wasm"
    fi
fi
WASM_SIZE=$(du -h "$WASM_FILE" | cut -f1)
echo "  WASM binary: ${WASM_SIZE} ($WASM_FILE)"

if [ ! -d "$TX_DATA_DIR" ]; then
    echo "  Generating test transaction data..."
    (cd "$CONTRACT_DIR" && cargo test --test gen_testdata -- --ignored --nocapture 2>&1 | tail -3)
fi
echo "  Test data: $TX_DATA_DIR"
echo "  RPC port: $RPC_PORT"
echo ""

# ── Initialize wasmd chain ───────────────────────────────────────────────────

echo "── Initializing single-node wasmd chain..."
wcmd init test --chain-id "$CHAIN_ID" --default-denom "$DENOM" > /dev/null 2>&1

wcmd keys add seller --keyring-backend "$KEYRING" > /dev/null 2>&1
wcmd keys add buyer --keyring-backend "$KEYRING" > /dev/null 2>&1
wcmd keys add oracle --keyring-backend "$KEYRING" > /dev/null 2>&1

SELLER_ADDR=$(wcmd keys show seller -a --keyring-backend "$KEYRING")
BUYER_ADDR=$(wcmd keys show buyer -a --keyring-backend "$KEYRING")
ORACLE_ADDR=$(wcmd keys show oracle -a --keyring-backend "$KEYRING")
echo "  Seller: $SELLER_ADDR"
echo "  Buyer:  $BUYER_ADDR"
echo "  Oracle: $ORACLE_ADDR"

wcmd genesis add-genesis-account "$SELLER_ADDR" "100000000000${DENOM}" > /dev/null 2>&1
wcmd genesis add-genesis-account "$BUYER_ADDR" "100000000000${DENOM}" > /dev/null 2>&1
wcmd genesis add-genesis-account "$ORACLE_ADDR" "100000000000${DENOM}" > /dev/null 2>&1

wcmd genesis gentx seller "250000000${DENOM}" \
    --chain-id "$CHAIN_ID" \
    --keyring-backend "$KEYRING" \
    --moniker "gas-test" > /dev/null 2>&1
wcmd genesis collect-gentxs > /dev/null 2>&1

# Configure custom ports
sed_inplace "s|laddr = \"tcp://127.0.0.1:26657\"|laddr = \"tcp://127.0.0.1:${RPC_PORT}\"|" "$WASMD_HOME/config/config.toml"
sed_inplace "s|laddr = \"tcp://0.0.0.0:26656\"|laddr = \"tcp://0.0.0.0:${P2P_PORT}\"|" "$WASMD_HOME/config/config.toml"
sed_inplace "s|address = \"0.0.0.0:9090\"|address = \"0.0.0.0:${GRPC_PORT}\"|" "$WASMD_HOME/config/app.toml"
sed_inplace "s|address = \"tcp://localhost:1317\"|address = \"tcp://localhost:${API_PORT}\"|" "$WASMD_HOME/config/app.toml"
sed_inplace 's/timeout_commit = "5s"/timeout_commit = "1s"/' "$WASMD_HOME/config/config.toml"

echo "  Chain ID: $CHAIN_ID"

# ── Start node ───────────────────────────────────────────────────────────────

echo ""
echo "── Starting wasmd node..."
wcmd start --log_level error > /tmp/wasmd-gas-node-$$.log 2>&1 &
NODE_PID=$!
echo "  Node PID: $NODE_PID"
echo "  Waiting for first block..."
wait_for_block
echo "  Node producing blocks."

# Verify account funding
SELLER_BAL=$(wcmd query bank balances "$SELLER_ADDR" --output json --node "$RPC_ADDR" 2>/dev/null | \
    python3 -c "import sys,json; bals=json.load(sys.stdin).get('balances',[]); print(bals[0]['amount'] if bals else '0')" 2>/dev/null || echo "0")
echo "  Seller balance: ${SELLER_BAL} ${DENOM}"

TX_FLAGS="--chain-id $CHAIN_ID --keyring-backend $KEYRING --gas 50000000 --gas-prices $GAS_PRICES --broadcast-mode sync -y --output json --node $RPC_ADDR"

# ── 1. Upload contract ──────────────────────────────────────────────────────

echo ""
echo "── [1] Store WASM code..."
UPLOAD_RESULT=$(wcmd tx wasm store "$WASM_FILE" --from seller $TX_FLAGS 2>/dev/null || echo "{}")
UPLOAD_TXHASH=$(echo "$UPLOAD_RESULT" | json_field txhash)

if [ -n "$UPLOAD_TXHASH" ]; then
    UPLOAD_TX=$(wait_for_tx "$UPLOAD_TXHASH")
    UPLOAD_GAS=$(get_gas "$UPLOAD_TX")
    CODE_ID=$(echo "$UPLOAD_TX" | event_attr code_id "1")
else
    echo "  Upload failed: $UPLOAD_RESULT" >&2
    UPLOAD_GAS="FAILED"; CODE_ID="1"
fi
echo "  Code ID: $CODE_ID, Gas: $UPLOAD_GAS"

# ── 2. Instantiate ──────────────────────────────────────────────────────────

echo ""
echo "── [2] Instantiate contract..."
INIT_MSG=$(python3 -c "
import json
msg = json.load(open('$TX_DATA_DIR/instantiate.json'))
msg['oracle_address'] = '$ORACLE_ADDR'
print(json.dumps(msg))
" 2>/dev/null)
INIT_RESULT=$(wcmd tx wasm instantiate "$CODE_ID" "$INIT_MSG" \
    --label "rare-bullet-gas" --admin "$SELLER_ADDR" --from seller $TX_FLAGS 2>/dev/null || echo "{}")
INIT_TXHASH=$(echo "$INIT_RESULT" | json_field txhash)

if [ -n "$INIT_TXHASH" ]; then
    INIT_TX=$(wait_for_tx "$INIT_TXHASH")
    INIT_GAS=$(get_gas "$INIT_TX")
    CONTRACT_ADDR=$(echo "$INIT_TX" | event_attr _contract_address "")
else
    INIT_GAS="FAILED"; CONTRACT_ADDR=""
fi

if [ -z "$CONTRACT_ADDR" ]; then
    CONTRACT_ADDR=$(wcmd query wasm list-contract-by-code "$CODE_ID" --output json --node "$RPC_ADDR" 2>/dev/null | \
        python3 -c "import sys,json; cs=json.load(sys.stdin).get('contracts',[]); print(cs[0] if cs else '')" 2>/dev/null || echo "")
fi
echo "  Contract: $CONTRACT_ADDR"
echo "  Gas: $INIT_GAS"

if [ -z "$CONTRACT_ADDR" ]; then
    echo "ERROR: No contract address. Aborting." >&2; exit 1
fi

# ── Regenerate deposit proofs bound to the real contract address ────────────
# The gen_testdata test binds the Bulletproof transcript to the contract address
# AND the seller bech32 address (sender binding defeats mempool front-running).
# Proofs generated before instantiation used a placeholder address; they must
# be regenerated now that the real on-chain address is known.
echo ""
echo "── Regenerating deposit proofs bound to contract address..."
(cd "$CONTRACT_DIR" && \
    CONTRACT_ADDR="$CONTRACT_ADDR" \
    SENDER_ADDR="$SELLER_ADDR" \
    cargo test --test gen_testdata -- --ignored --nocapture 2>&1 | tail -5)
echo "  Deposit proofs regenerated."

# ── 3. Deposit ×6 ───────────────────────────────────────────────────────────

echo ""
echo "── [3] Deposit × 6 (verify + mint + nullifier)..."
DEPOSIT_GAS_VALUES=()

for i in $(seq 0 5); do
    DEP_MSG=$(cat "$TX_DATA_DIR/deposit_${i}.json")
    DEP_GAS=$(exec_contract_gas "$DEP_MSG" seller)
    DEPOSIT_GAS_VALUES+=("$DEP_GAS")
    echo "  Deposit $i: gas = $DEP_GAS"
done

DEPOSIT_GAS_AVG=$(python3 -c "
vals = [int(v) for v in '${DEPOSIT_GAS_VALUES[*]}'.split() if v not in ('N/A','FAILED')]
print(sum(vals) // len(vals) if vals else 'N/A')
" 2>/dev/null || echo "N/A")
echo "  Average: $DEPOSIT_GAS_AVG"

# ── 4. CW20 Transfer ───────────────────────────────────────────────────────

echo ""
echo "── [4] CW20 Transfer (seller → buyer)..."
TRANSFER_MSG=$(python3 -c "
import json
msg = json.load(open('$TX_DATA_DIR/transfer.json'))
msg['transfer']['recipient'] = '$BUYER_ADDR'
print(json.dumps(msg))
" 2>/dev/null)

XFER_GAS=$(exec_contract_gas "$TRANSFER_MSG" seller)
echo "  Gas: $XFER_GAS"

# ── 5. DEPRECATED: BurnAndClaim (commented out - replaced by two-phase flow) ──
#
# echo ""
# echo "── [5] BurnAndClaim (buyer burns + claims)..."
# CLAIM_MSG=$(cat "$TX_DATA_DIR/burn_and_claim.json")
# CLAIM_RESULT=$(wcmd tx wasm execute "$CONTRACT_ADDR" "$CLAIM_MSG" --from buyer $TX_FLAGS 2>/dev/null || echo "{}")
# CLAIM_TXHASH=$(echo "$CLAIM_RESULT" | python3 -c "import sys,json; print(json.load(sys.stdin).get('txhash',''))" 2>/dev/null || echo "")
#
# if [ -n "$CLAIM_TXHASH" ]; then
#     CLAIM_TX=$(wait_for_tx "$CLAIM_TXHASH")
#     CLAIM_GAS=$(get_gas "$CLAIM_TX")
# else
#     CLAIM_GAS="FAILED"
# fi
# echo "  Gas: $CLAIM_GAS"

# ── 5b. Two-Phase Oracle Flow: BurnAndRequest + FulfillRandomness ───────────

# Transfer another token to buyer for the two-phase flow test.
echo ""
echo "── [5b] Two-Phase Oracle Flow..."
XFER2_MSG=$(python3 -c "
import json
msg = json.load(open('$TX_DATA_DIR/transfer.json'))
msg['transfer']['recipient'] = '$BUYER_ADDR'
print(json.dumps(msg))
" 2>/dev/null)
XFER2_HASH=$(wcmd tx wasm execute "$CONTRACT_ADDR" "$XFER2_MSG" --from seller $TX_FLAGS 2>/dev/null | json_field txhash)
echo "  Transfer tx: ${XFER2_HASH:0:16} ..."
sleep 2

# Phase 1: BurnAndRequest
echo "  Phase 1: BurnAndRequest..."
REQUEST_MSG=$(cat "$TX_DATA_DIR/burn_and_request.json")
REQUEST_GAS=$(exec_contract_gas "$REQUEST_MSG" buyer)
echo "  BurnAndRequest gas: $REQUEST_GAS"

# Phase 2: FulfillRandomness (from oracle account)
echo "  Phase 2: FulfillRandomness..."
FULFILL_MSG=$(python3 -c "
import json
msg = json.load(open('$TX_DATA_DIR/fulfill_randomness.json'))
msg['fulfill_randomness']['buyer_address'] = '$BUYER_ADDR'
print(json.dumps(msg))
" 2>/dev/null)
FULFILL_GAS=$(exec_contract_gas "$FULFILL_MSG" oracle)
echo "  FulfillRandomness gas: $FULFILL_GAS"

# ── 6. Queries ──────────────────────────────────────────────────────────────

echo ""
echo "── [6] Query contract state..."
for q in active_count get_config token_info; do
    Q_MSG=$(cat "$TX_DATA_DIR/query_${q}.json")
    Q_RESULT=$(wcmd query wasm contract-state smart "$CONTRACT_ADDR" "$Q_MSG" --output json --node "$RPC_ADDR" 2>/dev/null || echo "{}")
    echo "  $q: $(echo "$Q_RESULT" | python3 -c "import sys,json; d=json.load(sys.stdin).get('data',{}); print(json.dumps(d)[:200])" 2>/dev/null || echo "error")"
done

# ── Results ──────────────────────────────────────────────────────────────────

WASMD_VER=$(wasmd version 2>/dev/null || echo "unknown")

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║   Gas Estimation Results (wasmd v${WASMD_VER})                       ║"
echo "╠══════════════════════════════════════════════════════════════════════╣"
printf "║  %-46s %8s    ║\n" "Operation" "Gas Used"
echo "╠══════════════════════════════════════════════════════════════════════╣"
printf "║  %-46s %8s    ║\n" "Store WASM code" "$UPLOAD_GAS"
printf "║  %-46s %8s    ║\n" "Instantiate" "$INIT_GAS"
printf "║  %-46s %8s    ║\n" "Deposit (avg, verify+mint+nullifier)" "$DEPOSIT_GAS_AVG"
printf "║  %-46s %8s    ║\n" "CW20 Transfer" "$XFER_GAS"
# printf "║  %-46s %8s    ║\n" "BurnAndClaim (atomic)" "$CLAIM_GAS"
printf "║  %-46s %8s    ║\n" "BurnAndRequest (Phase 1)" "$REQUEST_GAS"
printf "║  %-46s %8s    ║\n" "FulfillRandomness (Phase 2)" "$FULFILL_GAS"
echo "╚══════════════════════════════════════════════════════════════════════╝"

# ── Write Markdown ───────────────────────────────────────────────────────────

cat > "$RESULTS_FILE" << MDEOF
# Bulletproof CosmWasm — Gas Estimation Results

> Measured on a disposable wasmd v${WASMD_VER} single-node chain.
> These are real CosmWasm gas figures from on-chain execution.

| Operation | Gas Used |
|-----------|----------|
| Store WASM code | ${UPLOAD_GAS} |
| Instantiate (CW20 + vault config + oracle) | ${INIT_GAS} |
| Deposit (avg ×6, verify + mint + nullifier) | ${DEPOSIT_GAS_AVG} |
| CW20 Transfer | ${XFER_GAS} |
| BurnAndRequest (Phase 1: burn + emit oracle_request) | ${REQUEST_GAS} |
| FulfillRandomness (Phase 2: oracle callback + O(1) swap-and-pop) | ${FULFILL_GAS} |

### Per-Deposit Breakdown

| Deposit # | Gas Used |
|-----------|----------|
$(for i in $(seq 0 5); do echo "| Deposit $i | ${DEPOSIT_GAS_VALUES[$i]} |"; done)

### Environment

- **wasmd**: v${WASMD_VER}
- **Chain ID**: ${CHAIN_ID}
- **WASM binary**: ${WASM_SIZE}
- **Generated**: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
MDEOF

echo ""
echo "  Results: $RESULTS_FILE"
echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║   Gas estimation complete                                          ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
