#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Rare Bullet — CosmWasm Contract Instantiation Script
# ============================================================================

# --- Configuration ---
# Replace with your actual CLI binary (wasmd, hippod, etc.)
CLI="$HOME/Desktop/code/hippo-protocol/build/hippod"

# The Code ID you received when you stored/uploaded the new WASM file
CODE_ID=11 

# Your deployer wallet/key name
KEY_NAME="hippo-deployer" 

# Network config
RPC_URL="https://rpc.testnet.hippo-protocol.com"
CHAIN_ID="hippo-protocol-testnet-1"
FEES="500000000000000000ahp" # Adjust fee denom/amount as needed

# --- Instantiate Payload ---
# We are filling out the InstantiateMsg struct here. 
# You can remove the Option fields (like oracle_address) if you want them to be None.
INIT_MSG=$(cat <<EOF
{
  "token_name": "RangeBucket90-100",
  "token_symbol": "RB90",
  "token_decimals": 6,
  "min_vault_depth": 5,
  "fallback_timeout_blocks": 100000,
  "oracle_address": "hippo17plwy3nmxg4s7snlaq7zpvwe48073ur32uqxd0",
  "oracle_timeout_blocks": 100800
}
EOF
)

# Strip newlines and spaces for safe CLI passing
INIT_JSON=$(echo "$INIT_MSG" | jq -c .)

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║ Instantiating Rare Bullet Contract (Code ID: $CODE_ID)               ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo "Payload: $INIT_JSON"
echo ""

# Execute the instantiation
$CLI tx wasm instantiate $CODE_ID "$INIT_JSON" \
    --from "$KEY_NAME" \
    --admin "$KEY_NAME" \
    --label "RareBullet RB90 Vault" \
    --chain-id "$CHAIN_ID" \
    --node "$RPC_URL" \
    --gas auto \
    --gas-adjustment 1.3 \
    --fees "$FEES" \
    --broadcast-mode sync \
    -y

echo ""
echo "⌛ Transaction broadcasted. Waiting for block inclusion to fetch Contract Address..."
sleep 6

# Fetch the instantiated contract address by querying the TX history of the deployer
DEPLOYER_ADDR=$($CLI keys show "$KEY_NAME" -a)
CONTRACT_ADDR=$($CLI query wasm list-contract-by-code $CODE_ID --node "$RPC_URL" --output json | jq -r '.contracts[-1]')

echo "✅ Instantiation complete!"
echo "📄 Contract Address: $CONTRACT_ADDR"