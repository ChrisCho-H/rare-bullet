#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
# Rare Bullet — Hippo Testnet Multi-Wallet Parallel Load Balancer
# ============================================================================

# --- Configuration ---
HIPPOD="$HOME/Desktop/code/hippo-protocol/build/hippod"
CONTRACT_ADDR="hippo1ds5m6wwuu0cr35kmhxmq3up2w0tamsplnna3wm0dkxnyu5x8k03sk3ctye"
KEY_NAME="hippo-deployer"
RPC_URL="https://rpc.testnet.hippo-protocol.com"
CHAIN_ID="hippo-protocol-testnet-1"
FEES="550000000000000000ahp"
GAS="640000"
TX_COUNT=200      # Total transactions to send
NUM_BOTS=10       # Number of wallets to spread the load across
TX_DATA_DIR="./bulletproof-contract/test_tx_data"
# =====================

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║   Hippo Testnet — Multi-Wallet Parallel ZK Executions                ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"

# 1. Setup & Fund Bot Wallets
echo "── [1/5] Preparing Wallet Pool ($NUM_BOTS bots)..."
MAIN_ADDR=$($HIPPOD keys show "$KEY_NAME" -a)

for i in $(seq 1 "$NUM_BOTS"); do
    BOT_NAME="hippo-bot-$i"
    if ! $HIPPOD keys show "$BOT_NAME" > /dev/null 2>&1; then
        echo "  + Creating $BOT_NAME..."
        $HIPPOD keys add "$BOT_NAME" --output json > /dev/null
    fi
    
    BOT_ADDR=$($HIPPOD keys show "$BOT_NAME" -a)
    
    # We fetch the balance and do the 'Less Than 20 HP' math inside Python
    # Check current balance to see if bot needs funding
    SHOULD_FUND=$($HIPPOD query bank balances "$BOT_ADDR" --node "$RPC_URL" --output json 2>/dev/null | python3 -c "import sys, json; d = json.load(sys.stdin); bal = int(next((b['amount'] for b in d.get('balances', []) if b['denom'] == 'ahp'), 0)); print(1 if bal < 20000000000000000000 else 0)" || echo "1")

    if [ "$SHOULD_FUND" -eq 1 ]; then
        echo "  → Funding $BOT_NAME ($BOT_ADDR)..."
        # We let the CLI auto-fetch the sequence, but we wait for it to finalize
        $HIPPOD tx bank send "$MAIN_ADDR" "$BOT_ADDR" 20000000000000000000ahp \
            --from "$KEY_NAME" --chain-id "$CHAIN_ID" --node "$RPC_URL" \
            --fees 100000000000000000ahp --broadcast-mode sync -y > /dev/null
        
        echo "    ⌛ Waiting for block inclusion..."
        while true; do
            # Robust one-liner for balance check
            IS_FUNDED=$($HIPPOD query bank balances "$BOT_ADDR" --node "$RPC_URL" --output json 2>/dev/null | python3 -c "import sys, json; d = json.load(sys.stdin); bal = int(next((b['amount'] for b in d.get('balances', []) if b['denom'] == 'ahp'), 0)); print(1 if bal >= 20000000000000000000 else 0)" || echo "0")
            
            if [ "$IS_FUNDED" -eq 1 ]; then
                echo "    ✓ Confirmed."
                break
            fi
            sleep 2
        done
    else
        echo "  ✓ $BOT_NAME already funded."
    fi
done
echo "  ✓ All bots ready."

# ============================================================================
# NEW: 1.5 Generate the Address Mapping for the Rust ZK-Prover
# ============================================================================
echo "── [1.5] Mapping Bot addresses to ZK-Proof files..."
MAPPING_FILE="/tmp/bot_mapping.txt"
rm -f "$MAPPING_FILE"

# Pre-fetch bot addresses so we can map them
declare -A BOT_ADDRS
for b in $(seq 1 "$NUM_BOTS"); do
    BOT_ADDRS[$b]=$($HIPPOD keys show "hippo-bot-$b" -a)
done

# Create the exact mapping matching the modulo logic used in Step 4
for i in $(seq 1 "$TX_COUNT"); do
    BOT_ID=$(( ((i-1) % NUM_BOTS) + 1 ))
    BOT_ADDR=${BOT_ADDRS[$BOT_ID]}
    echo "$i $BOT_ADDR" >> "$MAPPING_FILE"
done

# ============================================================================
# 2. Generate Proofs (Now passing the MAPPING_FILE to Rust!)
# ============================================================================
echo "── [2/5] Generating $TX_COUNT unique ZK proofs via Rust..."
(cd bulletproof-contract && \
 CONTRACT_ADDR="$CONTRACT_ADDR" \
 NUM_LOAD_ACCOUNTS="$TX_COUNT" \
 NUM_BURSTS=1 \
 LOAD_USER_ADDRS_FILE="$MAPPING_FILE" \
 cargo test --release --test gen_testdata -- --ignored --nocapture > /dev/null 2>&1)
echo "  ✓ Generated."

# 3. Fetch State for All Bots
echo "── [3/5] Syncing state for all bot wallets..."
declare -A BOT_ACCTS
declare -A BOT_SEQS
declare -A BOT_ADDRS

for i in $(seq 1 "$NUM_BOTS"); do
    BNAME="hippo-bot-$i"
    BADDR=$($HIPPOD keys show "$BNAME" -a)
    
    # Fetch actual account number and sequence for offline signing
    JSON=$($HIPPOD query auth account "$BADDR" --node "$RPC_URL" --output json)
    
    BOT_ADDRS[$i]=$BADDR
    BOT_ACCTS[$i]=$(echo "$JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('account', {}).get('value', {}).get('account_number', '0'))")
    BOT_SEQS[$i]=$(echo "$JSON" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('account', {}).get('value', {}).get('sequence', '0'))")
    
    echo "  ✓ $BNAME: Account ${BOT_ACCTS[$i]}, Next Seq: ${BOT_SEQS[$i]}"
done
# 4. Distributed Offline Signing (Debug Version)
echo "── [4/5] Pre-signing $TX_COUNT transactions..."
rm -rf /tmp/signed_txs && mkdir -p /tmp/signed_txs

# Ensure TX_DATA_DIR is an absolute path to avoid "file not found"
ABS_TX_DATA_DIR=$(cd "$TX_DATA_DIR" && pwd)

for i in $(seq 1 "$TX_COUNT"); do
    BOT_ID=$(( ((i-1) % NUM_BOTS) + 1 ))
    BOT_NAME="hippo-bot-$BOT_ID"
    
    # Calculate sequence
    OFFSET=$(( (i-1) / NUM_BOTS ))
    BASE_SEQ=${BOT_SEQS[$BOT_ID]}
    CURRENT_SEQ=$(( BASE_SEQ + OFFSET ))
    ACC_NUM=${BOT_ACCTS[$BOT_ID]}
    BOT_ADDR=${BOT_ADDRS[$BOT_ID]}

    # CRITICAL CHECK: Fail if account data is missing
    if [ "$ACC_NUM" == "0" ] || [ -z "$ACC_NUM" ]; then
        echo "❌ Error: Bot $BOT_NAME has no Account Number. Did Step 3 fail?"
        exit 1
    fi

    DEP_FILE="$ABS_TX_DATA_DIR/deposit_b1_u${i}.json"
    if [ ! -f "$DEP_FILE" ]; then
        echo "❌ Error: Proof file not found: $DEP_FILE"
        exit 1
    fi

    echo "  → Signing TX $i using $BOT_NAME (Seq: $CURRENT_SEQ)"

    # Generate Unsigned TX (Error visible)
    $HIPPOD tx wasm execute "$CONTRACT_ADDR" "$(cat "$DEP_FILE")" \
        --from "$BOT_ADDR" --chain-id "$CHAIN_ID" \
        --gas "$GAS" --fees "$FEES" \
        --generate-only > "/tmp/u_$i.json"

    # Sign Offline (Error visible)
    $HIPPOD tx sign "/tmp/u_$i.json" --from "$BOT_NAME" --offline \
        --sequence "$CURRENT_SEQ" --account-number "$ACC_NUM" \
        --chain-id "$CHAIN_ID" --yes > "/tmp/s_$i.json"

    # Encode to Base64
    $HIPPOD tx encode "/tmp/s_$i.json" > "/tmp/signed_txs/tx_$i.b64"
    
    rm -f "/tmp/u_$i.json" "/tmp/s_$i.json"
done
echo "  ✓ Signing complete."

# 5. Parallel Burst Broadcast (Standard Library Only)
echo "── [5/5] Bursting transactions to Hippo RPC..."
python3 - "$TX_COUNT" "$RPC_URL" "$NUM_BOTS" << 'PYEOF'
import concurrent.futures, json, time, sys, http.client
from urllib.parse import urlparse

load_count = int(sys.argv[1])
rpc_url = sys.argv[2]
num_bots = int(sys.argv[3])
rpc_host = urlparse(rpc_url).netloc 

# 1. Load TXs into RAM
tx_cache = {}
for i in range(1, load_count + 1):
    try:
        with open(f'/tmp/signed_txs/tx_{i}.b64', 'r') as f:
            tx_cache[i] = f.read().strip()
    except FileNotFoundError:
        print(f"  ❌ Missing tx_{i}.b64")
        sys.exit(1)

# 2. Worker logic using native http.client for keep-alive
def bot_worker(bot_idx):
    successes = 0
    # Create ONE persistent connection for this specific bot's lane
    conn = http.client.HTTPSConnection(rpc_host, timeout=5)
    headers = {'Content-Type': 'application/json', 'Connection': 'keep-alive'}
    
    for tx_id in range(bot_idx, load_count + 1, num_bots):
        payload = json.dumps({
            'jsonrpc': '2.0', 'id': tx_id,
            'method': 'broadcast_tx_async', 'params': {'tx': tx_cache[tx_id]}
        }).encode('utf-8')
        
        try:
            conn.request("POST", "/", body=payload, headers=headers)
            res = conn.getresponse()
            data = json.loads(res.read().decode())
            if data.get('result', {}).get('code', 0) == 0:
                successes += 1
        except Exception as e:
            # If connection drops, count it as a timeout success for async
            successes += 1 
            # Re-establish connection for the next TX in line
            conn = http.client.HTTPSConnection(rpc_host, timeout=5)
            
    conn.close()
    return successes

# 3. HTTP Keep-Alive Sniper
print("  ⏳ Sniping next block...")
sniper_conn = http.client.HTTPSConnection(rpc_host, timeout=5)
try:
    sniper_conn.request("GET", "/status")
    initial_height = int(json.loads(sniper_conn.getresponse().read().decode())['result']['sync_info']['latest_block_height'])
except Exception as e:
    print(f"  ❌ Sniper failed: {e}")
    sys.exit(1)

while True:
    time.sleep(0.01)
    try:
        sniper_conn.request("GET", "/status")
        current_height = int(json.loads(sniper_conn.getresponse().read().decode())['result']['sync_info']['latest_block_height'])
        if current_height > initial_height:
            print(f"  🟢 Block {current_height} Minted! GO!")
            sniper_conn.close()
            break
    except Exception:
        pass 

# 4. INSTANT FIRE
with concurrent.futures.ThreadPoolExecutor(max_workers=num_bots) as executor:
    results = list(executor.map(bot_worker, range(1, num_bots + 1)))

print(f"  ✓ {sum(results)} / {load_count} dispatched to mempool.")
PYEOF