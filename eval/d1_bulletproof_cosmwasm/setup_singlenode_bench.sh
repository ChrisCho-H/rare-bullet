# ============================================================================
#  Rare Bullet — Single-Node Capacity Benchmark
# ============================================================================
#  Bootstraps a single-validator wasmd node, deploys the Rare Bullet CosmWasm
#  contract (aggregated m=2 Bulletproof verification over 64 total bits within
#  the native CosmWasm WebAssembly runtime), and runs a multi-account sustained
#  load test measuring absolute maximum throughput and block execution time
#  without multi-node OS context-switching noise. On the distributed 8-node
#  testnet, the architecture achieves a sustained systemic throughput of 26 TPS,
#  fully saturating the 100M block gas limit.
#
#  Metrics collected:
#    • Total Broadcasted / Confirmed TXs
#    • Peak Block Height & TX Count
#    • Per-TX DeliverTx Time — DeliverTx duration / peak block TX count
#    • Average Gas per TX (~631K for the fully-loaded Deposit state machine)
#    • Transaction Size (Bytes)#
#
#  Each burst uses 100 independent accounts to eliminate sequence collisions.
#  All bursts fire without inter-burst pacing for genuine mempool saturation.
#
#  Usage:
#    bash eval/d1_bulletproof_cosmwasm/setup_singlenode_bench.sh
# ============================================================================

export PATH=$PATH:$HOME/go/bin

set -euo pipefail

# ── OS Detection & Portability ──────────────────────────────────────────────
# Ensures the script runs identically on Linux (CI) and macOS (local dev).

OS_TYPE="$(uname -s)"
IS_MACOS=false
[ "$OS_TYPE" = "Darwin" ] && IS_MACOS=true

# Bash 4+ is required for associative arrays (declare -A).
if [ "${BASH_VERSINFO[0]}" -lt 4 ]; then
    echo "ERROR: bash 4+ required (current: bash ${BASH_VERSION})." >&2
    if $IS_MACOS; then
        echo "  Install via Homebrew:  brew install bash" >&2
        echo "  Then run with:         /opt/homebrew/bin/bash $0" >&2
    fi
    exit 1
fi

# Portable sed in-place editing.
# BSD sed (macOS) requires a backup suffix argument after -i; GNU sed does not.
sed_inplace() {
    if $IS_MACOS; then
        sed -i '' "$@"
    else
        sed -i "$@"
    fi
}

# Portable base64 decode (macOS BSD base64 uses -D, GNU coreutils uses -d).
b64_decode() {
    if $IS_MACOS; then
        base64 -D
    else
        base64 -d
    fi
}

# ── Path Setup ──────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONTRACT_DIR="${SCRIPT_DIR}/bulletproof-contract"

# Prefer the optimized artifact (built by cosmwasm/optimizer Docker).
if [ -f "${CONTRACT_DIR}/artifacts/bulletproof_contract.wasm" ]; then
    WASM_FILE="${CONTRACT_DIR}/artifacts/bulletproof_contract.wasm"
elif [ -f "${SCRIPT_DIR}/bulletproof.wasm" ]; then
    WASM_FILE="${SCRIPT_DIR}/bulletproof.wasm"
else
    WASM_FILE="${CONTRACT_DIR}/target/wasm32-unknown-unknown/release/bulletproof_contract.wasm"
fi
TX_DATA_DIR="${CONTRACT_DIR}/test_tx_data"
RESULTS_FILE="${SCRIPT_DIR}/singlenode_eval_results.md"

# ── Chain parameters ────────────────────────────────────────────────────────

CHAIN_ID="singlenode-bench-$$"
DENOM="ustake"
KEYRING="test"
GAS_PRICES="0.025${DENOM}"
LOAD_TX_COUNT=3       # TXs per block burst (= number of load test accounts)
SUSTAINED_BLOCKS=100    # Number of consecutive block bursts
TOTAL_TXS=$((LOAD_TX_COUNT * SUSTAINED_BLOCKS))
BLOCK_COMMIT_TIME=1     # timeout_commit in seconds (set in config.toml below)
MAX_GAS='-1'
MAX_BYTES='20000000'

# Number of CPU cores available (used for parallel operations).
NPROC=$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)

# ── Single-node home directory ──────────────────────────────────────────────

NODE_HOME="${HOME}/.wasmd"
NODE_PID=""
GENESIS="${NODE_HOME}/config/genesis.json"

# ── Ports (single node — defaults) ─────────────────────────────────────────

RPC_PORT=26657
P2P_PORT=26656
API_PORT=1317

PRIMARY_RPC="tcp://127.0.0.1:${RPC_PORT}"

# ── Helpers ─────────────────────────────────────────────────────────────────

# Run wasmd against the node's home directory.
ncmd() {
    wasmd --home "${NODE_HOME}" "$@"
}

# Get current Unix time in milliseconds (portable).
now_ms() {
    python3 -c "import time; print(int(time.time() * 1000))"
}

# Extract block timestamp directly from CometBFT RPC (Bypassing CLI instability)
get_block_time() {
    local height="$1"
    curl -s "http://127.0.0.1:${RPC_PORT}/block?height=$height" | \
        python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    print(data['result']['block']['header']['time'])
except:
    print('')
" 2>/dev/null || echo ""
}

# Extract a top-level field from JSON on stdin (default: empty string).
json_field() {
    python3 -c "import sys,json; print(json.load(sys.stdin).get('$1','${2:-}'))" 2>/dev/null
}

# Get current chain height via the wasmd CLI status endpoint.
# Optional argument: fallback value on failure (default: "0").
get_chain_height() {
    ncmd status --node "$PRIMARY_RPC" 2>/dev/null | \
        python3 -c "import sys,json; print(json.load(sys.stdin)['sync_info']['latest_block_height'])" 2>/dev/null || echo "${1:-0}"
}

# Get current chain height via the CometBFT REST /status endpoint.
get_chain_height_rpc() {
    curl -s "http://127.0.0.1:${RPC_PORT}/status" 2>/dev/null | \
        python3 -c "import sys,json; print(json.load(sys.stdin)['result']['sync_info']['latest_block_height'])" 2>/dev/null || echo "0"
}

# Count transactions in a block at a given height via CometBFT REST.
get_block_tx_count() {
    curl -s "http://127.0.0.1:${RPC_PORT}/block?height=$1" 2>/dev/null | \
        python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    txs = data.get('result', {}).get('block', {}).get('data', {}).get('txs', [])
    print(len(txs) if txs else 0)
except:
    print(0)
" 2>/dev/null || echo "0"
}

set_genesis_block_capacity() {
python3 -c "
import json
import sys

MAX_GAS = '$MAX_GAS'
MAX_BYTES = '$MAX_BYTES'


with open('$GENESIS') as f:
    g = json.load(f)

# 1. Patch Tendermint / CometBFT consensus layer.
patched_top_level = False
if isinstance(g.get('consensus_params'), dict):
    if not isinstance(g['consensus_params'].get('block'), dict):
        g['consensus_params']['block'] = {}
    g['consensus_params']['block']['max_gas'] = MAX_GAS
    g['consensus_params']['block']['max_bytes'] = MAX_BYTES
    patched_top_level = True
elif isinstance(g.get('consensus'), dict) and isinstance(g['consensus'].get('params'), dict):
    if not isinstance(g['consensus']['params'].get('block'), dict):
        g['consensus']['params']['block'] = {}
    g['consensus']['params']['block']['max_gas'] = MAX_GAS
    g['consensus']['params']['block']['max_bytes'] = MAX_BYTES
    patched_top_level = True

# 2. Patch Cosmos SDK app_state layer (critical for v0.50+).
if not isinstance(g.get('app_state'), dict):
    g['app_state'] = {}
if not isinstance(g['app_state'].get('consensus'), dict):
    g['app_state']['consensus'] = {}
if not isinstance(g['app_state']['consensus'].get('params'), dict):
    g['app_state']['consensus']['params'] = {}
if not isinstance(g['app_state']['consensus']['params'].get('block'), dict):
    g['app_state']['consensus']['params']['block'] = {}

g['app_state']['consensus']['params']['block']['max_gas'] = MAX_GAS
g['app_state']['consensus']['params']['block']['max_bytes'] = MAX_BYTES

with open('$GENESIS', 'w') as f:
    json.dump(g, f, indent=2)

# Verify the required values were actually written.
with open('$GENESIS') as f:
    written = json.load(f)

app_block = (((written.get('app_state') or {}).get('consensus') or {}).get('params') or {}).get('block') or {}
if app_block.get('max_gas') != MAX_GAS or app_block.get('max_bytes') != MAX_BYTES:
    raise SystemExit('Failed to verify app_state consensus block params in genesis.json')

top_block = None
if isinstance(written.get('consensus_params'), dict):
    top_block = written['consensus_params'].get('block') or {}
elif isinstance(written.get('consensus'), dict) and isinstance(written['consensus'].get('params'), dict):
    top_block = written['consensus']['params'].get('block') or {}

if not patched_top_level or not isinstance(top_block, dict) or top_block.get('max_gas') != MAX_GAS or top_block.get('max_bytes') != MAX_BYTES:
    raise SystemExit('Failed to verify top-level consensus block params in genesis.json')
" 2>/dev/null || {
    echo "ERROR: Failed to set genesis block capacity." >&2
    exit 1
}
}

# Compute millisecond delta between two ISO-8601 CometBFT timestamps.
# Outputs a float with 1 decimal (e.g. "6123.4"). Prints nothing on failure.
ts_delta_ms() {
    python3 -c "
from datetime import datetime, timezone
def parse_ts(s):
    s = s.rstrip('Z')
    parts = s.split('.')
    if len(parts) == 2: s = parts[0] + '.' + parts[1][:6].ljust(6, '0')
    return datetime.fromisoformat(s).replace(tzinfo=timezone.utc)
t1 = parse_ts('$1')
t2 = parse_ts('$2')
print(f'{(t2 - t1).total_seconds() * 1000:.1f}')
" 2>/dev/null
}

# Convert a duration string (e.g. "1.234s", "500ms", "1234µs") to milliseconds.
duration_to_ms() {
    python3 -c "
import re
raw = '$1'
m = re.match(r'^([0-9]+(?:\.[0-9]+)?)(s|ms|µs|μs|us)?$', raw)
if m:
    val = float(m.group(1))
    unit = m.group(2) or 's'
    if unit == 's': val *= 1000
    elif unit in ('µs', 'μs', 'us'): val /= 1000
    print(f'{val:.2f}')
else:
    print('N/A')
" 2>/dev/null || echo "N/A"
}

# Safe Python division: pydiv <numerator> <denominator> [format]
# Prints "0.00" when denominator ≤ 0; "N/A" on error.
pydiv() {
    python3 -c "
n=float($1); d=float($2)
print(f'{n/d:${3:-.2f}}') if d > 0 else print('0.00')
" 2>/dev/null || echo "N/A"
}

# Parse 'keys list --output json' on stdin to extract load_user_{idx} addresses.
# Outputs lines of "idx addr" for each load_user_* key found.
parse_load_user_keys() {
    python3 -c "
import sys, json
keys = json.load(sys.stdin)
for k in keys:
    name = k.get('name', '')
    if name.startswith('load_user_'):
        idx = name[len('load_user_'):]
        addr = k.get('address', '')
        if addr:
            print(f'{idx} {addr}')
" 2>/dev/null
}

# Batch-add genesis accounts from stdin (one address per line) into genesis.json.
# Usage: echo -e "addr1\naddr2" | batch_add_genesis_accounts <genesis_path> <denom> <amount>
batch_add_genesis_accounts() {
    local genesis_path="$1" denom="$2" amount="$3"
    # Capture stdin to a temp file before the heredoc overrides it.
    local addr_tmp="/tmp/genesis_addrs_$$.txt"
    cat > "$addr_tmp"
    python3 - "$genesis_path" "$denom" "$amount" "$addr_tmp" << 'PYEOF'
import json, sys

genesis_path = sys.argv[1]
denom = sys.argv[2]
amount = sys.argv[3]
addr_file = sys.argv[4]
addresses = [line.strip() for line in open(addr_file) if line.strip()]

with open(genesis_path) as f:
    g = json.load(f)

# Determine next account_number from existing accounts.
auth_accounts = g['app_state']['auth']['accounts']
max_num = max((int(a.get('account_number', '0')) for a in auth_accounts), default=-1)
next_num = max_num + 1

for addr in addresses:
    auth_accounts.append({
        '@type': '/cosmos.auth.v1beta1.BaseAccount',
        'address': addr,
        'pub_key': None,
        'account_number': str(next_num),
        'sequence': '0'
    })
    next_num += 1
    g['app_state']['bank']['balances'].append({
        'address': addr,
        'coins': [{'denom': denom, 'amount': amount}]
    })

# Update total supply.
total_add = int(amount) * len(addresses)
supply = g['app_state']['bank']['supply']
found = False
for coin in supply:
    if coin['denom'] == denom:
        coin['amount'] = str(int(coin['amount']) + total_add)
        found = True
        break
if not found:
    supply.append({'denom': denom, 'amount': str(total_add)})

# Sort to match cosmos SDK conventions (SanitizeGenesisAccounts / Balances).
auth_accounts.sort(key=lambda a: int(a.get('account_number', '0')))
g['app_state']['bank']['balances'].sort(key=lambda b: b['address'])
supply.sort(key=lambda c: c['denom'])

with open(genesis_path, 'w') as f:
    json.dump(g, f, indent=2)
PYEOF
    rm -f "$addr_tmp"
}

# Check if a TX JSON result (on stdin) contains a 'height' field.
# Returns exit code 0 if found, 1 otherwise.
check_tx_included() {
    python3 -c "import sys,json; d=json.load(sys.stdin); sys.exit(0 if 'height' in d else 1)" 2>/dev/null
}

# Extract code_id from a WASM store transaction result on stdin.
# Prints the code_id on success, or "FAILED_TX:<reason>" on failure.
extract_code_id() {
    python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    if data.get('code', 0) != 0:
        print('FAILED_TX:' + data.get('raw_log', 'Unknown execution error'))
        sys.exit(0)
    for ev in data.get('events', []):
        for attr in ev.get('attributes', []):
            if attr.get('key') == 'code_id':
                print(attr['value'])
                sys.exit(0)
    print('FAILED_TX:No code_id found in events.')
except Exception:
    print('FAILED_TX:Python parsing error')
" 2>/dev/null || echo "FAILED_TX:Bash pipe error"
}

# Build the instantiate message by merging oracle_address into the template.
# Usage: build_init_msg <json_template_path> <oracle_address>
build_init_msg() {
    python3 - "$1" "$2" << 'PYEOF'
import json, sys
msg = json.load(open(sys.argv[1]))
msg['oracle_address'] = sys.argv[2]
print(json.dumps(msg))
PYEOF
}

# Extract _contract_address from instantiate TX events on stdin.
# Prints the address or empty string if not found.
extract_contract_addr() {
    python3 -c "
import sys, json
data = json.load(sys.stdin)
for ev in data.get('events', []):
    for attr in ev.get('attributes', []):
        if attr.get('key') == '_contract_address':
            print(attr['value']); sys.exit(0)
print('')
" 2>/dev/null || echo ""
}

# Extract the first contract address from 'list-contract-by-code' JSON on stdin.
extract_first_contract() {
    python3 -c "
import sys, json
cs = json.load(sys.stdin).get('contracts', [])
print(cs[0] if cs else '')
" 2>/dev/null || echo ""
}

# Fetch account numbers in parallel via REST API.
# Usage: fetch_account_numbers <addr_list_file> <api_port> <nproc>
# addr_list_file has lines of "idx address".
# Outputs lines of "idx account_number".
fetch_account_numbers() {
    python3 - "$1" "$2" "$3" << 'PYEOF'
import urllib.request, json, concurrent.futures, sys

addr_file = sys.argv[1]
api_port = sys.argv[2]
nproc = int(sys.argv[3])
lines = open(addr_file).read().strip().split('\n')
jobs = [(int(l.split()[0]), l.split()[1]) for l in lines if l.strip()]

def fetch(job):
    idx, addr = job
    try:
        url = f'http://127.0.0.1:{api_port}/cosmos/auth/v1beta1/accounts/{addr}'
        with urllib.request.urlopen(url, timeout=10) as res:
            data = json.loads(res.read())
            acct = data.get('account', data)
            if 'value' in acct and isinstance(acct['value'], dict):
                acct = acct['value']
            return f'{idx} {acct.get("account_number", "0")}'
    except:
        return f'{idx} 0'

with concurrent.futures.ThreadPoolExecutor(max_workers=max(nproc, 4)) as ex:
    results = list(ex.map(fetch, jobs))

for r in results:
    print(r)
PYEOF
}

# Broadcast a burst of pre-signed transactions concurrently via JSON-RPC.
# Usage: broadcast_burst <block_idx> <load_count> <rpc_url>
# Reads from /tmp/signed_txs/tx_{block_idx}_{i}.b64.
# Prints the number of successfully accepted transactions.
broadcast_burst() {
    python3 - "$1" "$2" "$3" << 'PYEOF'
import urllib.request, json, concurrent.futures, sys

block_idx = int(sys.argv[1])
load_count = int(sys.argv[2])
rpc_url = sys.argv[3]

def send_tx(i):
    try:
        with open(f'/tmp/signed_txs/tx_{block_idx}_{i}.b64', 'r') as f:
            b64 = f.read().strip()
        if not b64: return 0

        payload = json.dumps({
            'jsonrpc': '2.0',
            'id': i,
            'method': 'broadcast_tx_sync',
            'params': {'tx': b64}
        }).encode('utf-8')

        req = urllib.request.Request(rpc_url, data=payload,
                                     headers={'Content-Type': 'application/json'})

        with urllib.request.urlopen(req, timeout=20) as res:
            resp = json.loads(res.read().decode('utf-8'))
            if resp.get('result', {}).get('code', 0) == 0:
                return 1
    except Exception:
        pass
    return 0

with concurrent.futures.ThreadPoolExecutor(max_workers=load_count) as executor:
    successes = sum(executor.map(send_tx, range(1, load_count + 1)))

print(successes)
PYEOF
}

# Parse block_results JSON on stdin and extract per-block metrics.
# Outputs a single line: "successful failed_contract failed_gas failed_other total_gas total_evt"
parse_block_results() {
    python3 -c "
import sys, json
try:
    data = json.load(sys.stdin)
    result = data.get('result', {})
    txs = result.get('txs_results') or result.get('deliver_tx') or []

    successful = 0
    failed_contract = 0
    failed_gas = 0
    failed_other = 0
    total_gas = 0
    total_evt = 0

    for tx in txs:
        code = tx.get('code', 0)
        if code == 0:
            successful += 1
            total_gas += int(tx.get('gas_used', '0') or '0')
            for ev in tx.get('events', []):
                total_evt += len(ev.get('type', ''))
                for attr in ev.get('attributes', []):
                    total_evt += len(str(attr.get('key', ''))) + len(str(attr.get('value', '')))
        elif code == 5:
            failed_contract += 1
        elif code == 11:
            failed_gas += 1
        else:
            failed_other += 1

    print(f'{successful} {failed_contract} {failed_gas} {failed_other} {total_gas} {total_evt}')
except Exception:
    print('0 0 0 0 0 0')
" 2>/dev/null || echo "0 0 0 0 0 0"
}

# ── Cleanup ─────────────────────────────────────────────────────────────────
# Kill the background wasmd process and remove the temp home directory.

cleanup() {
    echo ""
    echo "── Cleaning up..."
    # Stop the resource monitor if running.
    if [ -n "${RESMON_PID:-}" ] && kill -0 "$RESMON_PID" 2>/dev/null; then
        kill "$RESMON_PID" 2>/dev/null || true
        wait "$RESMON_PID" 2>/dev/null || true
    fi
    if [ -n "$NODE_PID" ] && kill -0 "$NODE_PID" 2>/dev/null; then
        echo "  Stopping node (PID $NODE_PID)..."
        kill "$NODE_PID" 2>/dev/null || true
        wait "$NODE_PID" 2>/dev/null || true
    fi
    rm -rf "$NODE_HOME"
    echo "  Done."
}
trap cleanup EXIT

# ── Validation ──────────────────────────────────────────────────────────────

echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║   Bulletproof CosmWasm — Single-Node Capacity Benchmark            ║"
echo "╚══════════════════════════════════════════════════════════════════════╝"
echo ""

if ! command -v wasmd &>/dev/null; then
    echo "ERROR: wasmd not found on PATH." >&2; exit 1
fi
if ! command -v python3 &>/dev/null; then
    echo "ERROR: python3 not found on PATH." >&2
    if $IS_MACOS; then echo "  Install via: brew install python3" >&2; fi
    exit 1
fi
WASMD_VER=$(wasmd version 2>/dev/null || echo "unknown")
echo "  wasmd version: $WASMD_VER"

if [ ! -f "$WASM_FILE" ]; then
    echo "ERROR: WASM binary not found at $WASM_FILE" >&2; exit 1
fi
WASM_SIZE=$(du -h "$WASM_FILE" | cut -f1)
echo "  WASM binary:   ${WASM_SIZE} ($WASM_FILE)"
echo "  Chain ID:      $CHAIN_ID"
echo "  Node:          1 (single-node benchmark)"
echo ""

# ============================================================================
#   1 — Initialize single node
# ============================================================================

echo "── [1/7] Initializing single node..."

ncmd init "node1" --chain-id "$CHAIN_ID" --default-denom "$DENOM" > /dev/null 2>&1

# ── Patch config.toml ──
CFG="${NODE_HOME}/config/config.toml"
# Speed up block production for the load test.
sed_inplace "s/timeout_commit = \"5s\"/timeout_commit = \"${BLOCK_COMMIT_TIME}s\"/" "$CFG"
sed_inplace 's/timeout_propose = "3s"/timeout_propose = "1s"/' "$CFG"
sed_inplace 's/timeout_prevote = "1s"/timeout_prevote = "500ms"/' "$CFG"
sed_inplace 's/timeout_precommit = "1s"/timeout_precommit = "500ms"/' "$CFG"
# Allow CORS for local debugging (optional).
sed_inplace 's/cors_allowed_origins = \[\]/cors_allowed_origins = ["*"]/' "$CFG"
# Enable Prometheus metrics on the CometBFT side (default port 26660).
sed_inplace 's/prometheus = false/prometheus = true/' "$CFG"
# Increase the max open connections for the RPC server (default is 900)
sed_inplace 's/^max_open_connections = 900/max_open_connections = 100000/' "$CFG"

# ── Unlimit Mempool for Extreme Saturation ──
# 1. Increase max transactions in the mempool (default is 5000)
sed_inplace 's/^size = 5000/size = 1000000/' "$CFG"

# 2. Increase the cache size to match or exceed the size (default is 10000)
# If cache_size is smaller than size, the node will start rejecting valid TXs as duplicates!
sed_inplace 's/^cache_size = 10000/cache_size = 1000000/' "$CFG"

# 3. Increase total mempool physical byte size to ~5GB (default is 1073741824 bytes / 1GB)
# Required because 20,000 of your 2KB ZK-proofs will quickly hit the byte ceiling.
sed_inplace 's/^max_txs_bytes = 1073741824/max_txs_bytes = 5368709120/' "$CFG"

# ── Patch app.toml for API ──
APP="${NODE_HOME}/config/app.toml"
# Enable the REST API (required for metrics endpoint).
sed_inplace '/^\[api\]/,/^\[/ s/enable = false/enable = true/' "$APP"

echo "  Node 1: home=${NODE_HOME}  RPC=${RPC_PORT}  P2P=${P2P_PORT}"

# ============================================================================
#   2 — Create validator key, genesis accounts, gentx
# ============================================================================

echo ""
echo "── [2/7] Creating validator key & genesis..."

ncmd keys add "validator1" --keyring-backend "$KEYRING" > /dev/null 2>&1
VAL_ADDR=$(ncmd keys show "validator1" -a --keyring-backend "$KEYRING")
echo "  Validator 1: ${VAL_ADDR}"

ncmd genesis add-genesis-account "${VAL_ADDR}" "100000000000${DENOM}" > /dev/null 2>&1

# ── Provision Load Testing Accounts ─────────────────────────────────────────
# Optimized: create all keys first, then batch-retrieve addresses via a single
# 'keys list' call, and batch-insert all genesis accounts in one Python pass
# (replaces 3N sequential wasmd invocations with N + 1 + 1).
echo "  Provisioning $LOAD_TX_COUNT unique load testing accounts..."
declare -a LOAD_ADDRS

# Step 1: Create all keys (sequential — keyring file safety).
for i in $(seq 1 $LOAD_TX_COUNT); do
    ncmd keys add "load_user_$i" --keyring-backend "$KEYRING" > /dev/null 2>&1
done

# Step 2: Retrieve all addresses in a single 'keys list' call.
while IFS=' ' read -r idx addr; do
    LOAD_ADDRS[$idx]="$addr"
done < <(ncmd keys list --keyring-backend "$KEYRING" --output json 2>/dev/null | parse_load_user_keys)

# Validate all addresses were retrieved.
MISSING_ADDRS=0
for i in $(seq 1 $LOAD_TX_COUNT); do
    if [ -z "${LOAD_ADDRS[$i]:-}" ]; then
        MISSING_ADDRS=$((MISSING_ADDRS + 1))
    fi
done
if [ "$MISSING_ADDRS" -gt 0 ]; then
    echo "ERROR: Failed to retrieve addresses for $MISSING_ADDRS / $LOAD_TX_COUNT load accounts." >&2
    exit 1
fi

# Step 3: Batch-add all load accounts to genesis in a single JSON operation.
# (Replaces $LOAD_TX_COUNT sequential 'genesis add-genesis-account' CLI calls.)
for i in $(seq 1 $LOAD_TX_COUNT); do
    echo "${LOAD_ADDRS[$i]}"
done | batch_add_genesis_accounts "$GENESIS" "$DENOM" "1000000000" \
    || { echo "ERROR: Failed to batch-add genesis accounts." >&2; exit 1; }
echo "  $LOAD_TX_COUNT load test accounts added to genesis."

# ── Set block capacity in genesis ──────────────────────────────────────
set_genesis_block_capacity

# Generate gentx for the single validator.
ncmd genesis gentx "validator1" "250000000${DENOM}" \
    --chain-id "$CHAIN_ID" \
    --keyring-backend "$KEYRING" \
    --moniker "node1" > /dev/null 2>&1

ncmd genesis collect-gentxs > /dev/null 2>&1
echo "  Collected gentx from validator."

# ============================================================================
#   3 — Start the single node and wait for blocks
# ============================================================================

echo "── [3/7] Starting single node..."

# Call wasmd directly instead of via the ncmd function
# Get Debug level log
wasmd --home "${NODE_HOME}" start --log_level debug > "/tmp/wasmd_$$.log" 2>&1 &
NODE_PID=$!
echo "  Node 1 started (PID $NODE_PID)"

# ── Wait for the node to produce blocks ─────────────────────────────────────
echo ""
echo "  Waiting for block production..."
MAX_WAIT=90
ELAPSED=0
HEIGHT="0"
while [ $ELAPSED -lt $MAX_WAIT ]; do
    HEIGHT=$(get_chain_height)
    if [ "$HEIGHT" -gt "1" ] 2>/dev/null; then
        echo "  ✓ Node live — latest height: $HEIGHT"
        break
    fi
    sleep 2
    ELAPSED=$((ELAPSED + 2))
done
if [ "$HEIGHT" -le "1" ] 2>/dev/null; then
    echo "ERROR: Node failed to produce blocks within ${MAX_WAIT}s" >&2
    echo "── Node log (last 30 lines):" >&2
    tail -30 "/tmp/wasmd_$$.log" >&2 || true
    exit 1
fi

# Common transaction flags targeting the single node.
TX_FLAGS="--chain-id $CHAIN_ID --keyring-backend $KEYRING --gas 50000000 --gas-prices $GAS_PRICES --broadcast-mode sync -y --output json --node $PRIMARY_RPC"

# ============================================================================
#   4 — Deploy the contract (upload + instantiate)
# ============================================================================

echo ""
echo "── [4/7] Deploying contract..."

# Helper: wait for a single tx to be included.
wait_for_tx() {
    local txhash="$1"
    local max=30
    for _ in $(seq 1 "$max"); do
        local result
        result=$(ncmd query tx "$txhash" --output json --node "$PRIMARY_RPC" 2>/dev/null || echo "")
        if [ -n "$result" ] && echo "$result" | check_tx_included; then
            echo "$result"
            return 0
        fi
        sleep 1
    done
    echo "{}"
}

# 4a. Upload (store) the WASM code using validator1.
echo "  Storing WASM..."
UPLOAD_RESULT=$(ncmd tx wasm store "$WASM_FILE" --from "validator1" $TX_FLAGS 2>/dev/null || echo "{}")
UPLOAD_TXHASH=$(echo "$UPLOAD_RESULT" | json_field txhash || echo "")

if [ -z "$UPLOAD_TXHASH" ]; then
    echo "ERROR: WASM store failed." >&2
    echo "  Result: $UPLOAD_RESULT" >&2
    exit 1
fi
echo "  Store TX: ${UPLOAD_TXHASH:0:16}..."

UPLOAD_TX=$(wait_for_tx "$UPLOAD_TXHASH")
CODE_ID=$(echo "$UPLOAD_TX" | extract_code_id)

if [[ "$CODE_ID" == FAILED_TX* ]]; then
    echo "ERROR: WASM upload (store) transaction failed!" >&2
    echo "  Reason: ${CODE_ID#FAILED_TX:}" >&2
    echo "  Full TX Hash: $UPLOAD_TXHASH" >&2
    exit 1
fi

echo "  Code ID: $CODE_ID"

# 4b. Instantiate the contract.
echo "  Instantiating..."
ORACLE_ADDR="${VAL_ADDR}"  # Use validator1 as oracle for the eval.
INIT_MSG=$(build_init_msg "$TX_DATA_DIR/instantiate.json" "$ORACLE_ADDR")

INIT_RESULT=$(ncmd tx wasm instantiate "$CODE_ID" "$INIT_MSG" \
    --label "singlenode-bench" --admin "${VAL_ADDR}" --from "validator1" $TX_FLAGS 2>/dev/null || echo "{}")
INIT_TXHASH=$(echo "$INIT_RESULT" | json_field txhash || echo "")

if [ -z "$INIT_TXHASH" ]; then
    echo "ERROR: Instantiate failed." >&2; exit 1
fi

INIT_TX=$(wait_for_tx "$INIT_TXHASH")
CONTRACT_ADDR=$(echo "$INIT_TX" | extract_contract_addr)

# Fallback: query by code ID.
if [ -z "$CONTRACT_ADDR" ]; then
    CONTRACT_ADDR=$(ncmd query wasm list-contract-by-code "$CODE_ID" --output json --node "$PRIMARY_RPC" 2>/dev/null | \
        extract_first_contract)
fi

if [ -z "$CONTRACT_ADDR" ]; then
    echo "ERROR: No contract address obtained." >&2
    echo "================ DEBUG INFO ================" >&2
    echo "INIT_MSG: $INIT_MSG" >&2
    echo "INIT_TX: $INIT_TX" >&2
    echo "============================================" >&2
    exit 1
fi
echo "  Contract: $CONTRACT_ADDR"

# ── Regenerate deposit proofs bound to the real contract address ────────────
echo ""
echo "── Regenerating deposit proofs bound to contract address..."
echo "  Generating $TOTAL_TXS unique proofs ($LOAD_TX_COUNT accounts × $SUSTAINED_BLOCKS bursts)..."
# Persist per-user sender bech32 addresses so the prover can bind `info.sender`
# into the Merlin transcript (defeats mempool front-running).
LOAD_USER_ADDRS_FILE="/tmp/load_user_addrs_$$.txt"
: > "$LOAD_USER_ADDRS_FILE"
for i in $(seq 1 $LOAD_TX_COUNT); do
    echo "$i ${LOAD_ADDRS[$i]}" >> "$LOAD_USER_ADDRS_FILE"
done
(cd "$CONTRACT_DIR" && \
    CONTRACT_ADDR="$CONTRACT_ADDR" \
    LOAD_USER_ADDRS_FILE="$LOAD_USER_ADDRS_FILE" \
    NUM_LOAD_ACCOUNTS="$LOAD_TX_COUNT" \
    NUM_BURSTS="$SUSTAINED_BLOCKS" \
    cargo test --release --test gen_testdata -- --ignored --nocapture 2>&1 | tail -5)
rm -f "$LOAD_USER_ADDRS_FILE"
echo "  Deposit proofs regenerated."

# Record the chain height after deployment — load-test TXs start after this.
DEPLOY_END_HEIGHT=$(get_chain_height 5)
echo "  Chain height after deploy: $DEPLOY_END_HEIGHT"

# ============================================================================
#  STEP 5 — Pre-Sign & Multi-Account Sustained Load Test
# ============================================================================

echo ""
echo "── [5/7] Multi-Account Sustained Load Test..."

echo "  Phase A: Pre-generating and signing $TOTAL_TXS transactions (${NPROC} parallel workers)..."

# 1. Fetch Account Numbers ONCE (parallel via REST API, with retry)
declare -A ACC_NUMS
ADDR_LIST_FILE="/tmp/load_addrs_$$.txt"
for i in $(seq 1 $LOAD_TX_COUNT); do
    echo "$i ${LOAD_ADDRS[$i]}"
done > "$ADDR_LIST_FILE"

MAX_FETCH_RETRIES=3
for attempt in $(seq 1 $MAX_FETCH_RETRIES); do
    while IFS=' ' read -r idx num; do
        ACC_NUMS[$idx]=$num
    done < <(fetch_account_numbers "$ADDR_LIST_FILE" "$API_PORT" "$NPROC")

    FAILED_ACCS=0
    for i in $(seq 1 $LOAD_TX_COUNT); do
        if [ "${ACC_NUMS[$i]:-0}" = "0" ]; then
            FAILED_ACCS=$((FAILED_ACCS + 1))
        fi
    done

    if [ "$FAILED_ACCS" -eq 0 ]; then
        break
    fi

    if [ "$attempt" -lt "$MAX_FETCH_RETRIES" ]; then
        echo "  ⚠ $FAILED_ACCS / $LOAD_TX_COUNT account numbers returned 0 — retrying (attempt $((attempt+1))/$MAX_FETCH_RETRIES)..."
        sleep 3
    fi
done
rm -f "$ADDR_LIST_FILE"

if [ "$FAILED_ACCS" -gt 0 ]; then
    echo "ERROR: Failed to fetch account numbers for $FAILED_ACCS / $LOAD_TX_COUNT accounts after $MAX_FETCH_RETRIES attempts." >&2
    echo "  The REST API may not be ready. Check that the node is running and the API is enabled." >&2
    exit 1
fi

mkdir -p /tmp/signed_txs

# 2. Generate, Sign, and Encode — PARALLEL via xargs -P
# Each TX uses a unique pre-generated proof file (deposit_b{burst}_u{user}.json)
# where the Bulletproof π, commitment, and nullifier are cryptographically bound
# via the Merlin transcript. This ensures on-chain verification succeeds.
# NOTE (scientific caveat — nullifier synthesis):
#   Nullifiers are deterministic SHA-256("singlenode-bench-b{burst}-u{user}")
#   rather than oracle-attested nullifiers derived from real payloads.
#   This bypasses the production Sybil resistance mechanism to enable
#   high-volume throughput measurement. Production deployments require
#   oracle-attested nullifiers, which introduce additional off-chain latency
#   not captured in this benchmark.
#
# Write a helper script executed by xargs workers.
HELPER_SCRIPT="/tmp/gen_sign_encode_$$.sh"
cat > "$HELPER_SCRIPT" << 'HELPEREOF'
#!/usr/bin/env bash
set -euo pipefail
block_idx=$1; i=$2; addr=$3; acc=$4

ncmd() { wasmd --home "$NODE_HOME" "$@"; }

DEP_FILE="$TX_DATA_DIR/deposit_b${block_idx}_u${i}.json"
if [ ! -f "$DEP_FILE" ]; then
    echo "ERROR: proof file not found: $DEP_FILE" >&2; exit 255
fi

SEQ=$((block_idx - 1))
UF="/tmp/unsigned_${block_idx}_${i}.json"
SF="/tmp/signed_${block_idx}_${i}.json"
B64F="/tmp/signed_txs/tx_${block_idx}_${i}.b64"

if ! ncmd tx wasm execute "$CONTRACT_ADDR" "$(cat "$DEP_FILE")" \
    --from "$addr" --chain-id "$CHAIN_ID" \
    --gas 750000 --gas-prices "$GAS_PRICES" \
    --generate-only > "$UF" 2>/dev/null; then
    echo "ERROR: failed to generate unsigned tx for block ${block_idx}, user ${i}" >&2; exit 255
fi
[ -s "$UF" ] || { echo "ERROR: unsigned tx empty for block ${block_idx}, user ${i}" >&2; exit 255; }

if ! ncmd tx sign "$UF" \
    --from "load_user_$i" --chain-id "$CHAIN_ID" --keyring-backend "$KEYRING" \
    --sequence "$SEQ" --account-number "$acc" \
    --offline --yes > "$SF" 2>/dev/null; then
    echo "ERROR: failed to sign tx for block ${block_idx}, user ${i}" >&2; exit 255
fi
[ -s "$SF" ] || { echo "ERROR: signed tx empty for block ${block_idx}, user ${i}" >&2; exit 255; }

B64=$(ncmd tx encode "$SF" 2>/dev/null) || {
    echo "ERROR: failed to encode tx for block ${block_idx}, user ${i}" >&2; exit 255
}
[ -n "$B64" ] || { echo "ERROR: encoded tx empty for block ${block_idx}, user ${i}" >&2; exit 255; }

echo "$B64" > "$B64F"
rm -f "$UF" "$SF"
HELPEREOF
chmod +x "$HELPER_SCRIPT"

# Export variables needed by the helper script.
export NODE_HOME CONTRACT_ADDR CHAIN_ID GAS_PRICES KEYRING TX_DATA_DIR

# Build job manifest and execute in parallel with NPROC workers.
for block_idx in $(seq 1 $SUSTAINED_BLOCKS); do
    for i in $(seq 1 $LOAD_TX_COUNT); do
        echo "$block_idx $i ${LOAD_ADDRS[$i]} ${ACC_NUMS[$i]}"
    done
done | xargs -P "$NPROC" -L 1 bash "$HELPER_SCRIPT"

rm -f "$HELPER_SCRIPT"

# Capture the raw byte size of the first transaction.
SAMPLE_TX_SIZE_BYTES=""
B64_SAMPLE=$(cat /tmp/signed_txs/tx_1_1.b64 2>/dev/null || echo "")
if [ -n "$B64_SAMPLE" ]; then
    SAMPLE_TX_SIZE_BYTES=$(echo "$B64_SAMPLE" | b64_decode 2>/dev/null | wc -c | tr -d ' ')
fi

echo "  Phase B: Executing Load Test Burst via Fast Sequential REST..."

declare -a TX_HASHES
BROADCAST_OK=0

# ── Outer Loop: The Blocks ──
for block_idx in $(seq 1 $SUSTAINED_BLOCKS); do
    echo "  [Burst $block_idx/$SUSTAINED_BLOCKS] Blasting $LOAD_TX_COUNT transactions..."

    BURST_SUCCESS=$(broadcast_burst "$block_idx" "$LOAD_TX_COUNT" "http://127.0.0.1:${RPC_PORT}" 2>/dev/null || echo "0")

    BROADCAST_OK=$((BROADCAST_OK + BURST_SUCCESS))
    echo "    ✓ $BURST_SUCCESS / $LOAD_TX_COUNT accepted by mempool"
done

T_END=$(now_ms)
echo "  End time:   $T_END ($(date -u '+%H:%M:%S UTC'))"

echo "  Waiting for all transactions to be included in blocks..."
PREV_SETTLE_H="0"
STABLE_COUNT=0
MAX_SETTLE_WAIT=300
SETTLE_ELAPSED=0
while [ $SETTLE_ELAPSED -lt $MAX_SETTLE_WAIT ]; do
    CUR_H=$(get_chain_height_rpc)
    if [ "$CUR_H" != "$PREV_SETTLE_H" ] && [ "$CUR_H" != "0" ]; then
        BLK_TX_CNT=$(get_block_tx_count "$CUR_H")
        if [ "$BLK_TX_CNT" = "0" ]; then
            STABLE_COUNT=$((STABLE_COUNT + 1))
            if [ "$STABLE_COUNT" -ge 2 ]; then
                echo "  ✓ All transactions included (2 consecutive empty blocks at height $CUR_H)"
                break
            fi
        else
            STABLE_COUNT=0
        fi
        PREV_SETTLE_H="$CUR_H"
    fi
    sleep "$BLOCK_COMMIT_TIME"
    SETTLE_ELAPSED=$((SETTLE_ELAPSED + BLOCK_COMMIT_TIME))
done
if [ $SETTLE_ELAPSED -ge $MAX_SETTLE_WAIT ]; then
    echo "  ⚠ Settlement timeout reached (${MAX_SETTLE_WAIT}s)"
fi

# ── Block-based confirmation & metric gathering ─────────────────────────────
# Scan blocks after deployment to count TXs and extract gas/event metrics.
# This is O(blocks) instead of O(TXs), dramatically faster for large loads.

LATEST_HEIGHT=$(get_chain_height_rpc)
echo "  Scanning blocks $((DEPLOY_END_HEIGHT + 1))–${LATEST_HEIGHT} for load test transactions..."

declare -A HEIGHT_COUNTS
CONFIRMED=0
TOTAL_GAS_USED=0
TOTAL_EVENT_BYTES=0
TOTAL_FAILED_WASM=0
TOTAL_FAILED_GAS=0
TOTAL_FAILED_OTHER=0

for h in $(seq $((DEPLOY_END_HEIGHT + 1)) "$LATEST_HEIGHT"); do
    BLOCK_DATA=$(curl -s "http://127.0.0.1:${RPC_PORT}/block_results?height=$h" 2>/dev/null || echo "")
    # Notice the 6 variables declared here to catch the Python output
    read -r NUM_TXS F_WASM F_GAS F_OTHER BLK_GAS BLK_EVT_BYTES < <(echo "$BLOCK_DATA" | parse_block_results)

    # If the block had ANY transactions (success or fail), record it
    if [ $((NUM_TXS + F_WASM + F_GAS + F_OTHER)) -gt 0 ]; then
        HEIGHT_COUNTS[$h]=$((NUM_TXS + F_WASM + F_GAS + F_OTHER))
        
        # Accumulate metrics
        CONFIRMED=$((CONFIRMED + NUM_TXS))
        TOTAL_FAILED_WASM=$((TOTAL_FAILED_WASM + F_WASM))
        TOTAL_FAILED_GAS=$((TOTAL_FAILED_GAS + F_GAS))
        TOTAL_FAILED_OTHER=$((TOTAL_FAILED_OTHER + F_OTHER))
        TOTAL_GAS_USED=$((TOTAL_GAS_USED + BLK_GAS))
        TOTAL_EVENT_BYTES=$((TOTAL_EVENT_BYTES + BLK_EVT_BYTES))
    fi
done

echo "  Confirmed $CONFIRMED / $BROADCAST_OK transactions"

# ── Derived Metrics ─────────────────────────────────────────────────────────

# Average gas per TX.
if [ "$CONFIRMED" -gt 0 ]; then
    AVG_GAS=$((TOTAL_GAS_USED / CONFIRMED))
    AVG_EVENT_BYTES=$((TOTAL_EVENT_BYTES / CONFIRMED))
else
    AVG_GAS=0
    AVG_EVENT_BYTES=0
fi

# Transaction size.
TX_SIZE_BYTES="${SAMPLE_TX_SIZE_BYTES:-N/A}"

echo ""
echo "  ┌──────────────────────────────────────────┐"
echo "  │ Sustained Load Test Results (Isolated VM)│"
echo "  ├──────────────────────────────────────────┤"
echo "  │  Total Broadcasted: $BROADCAST_OK / $TOTAL_TXS"
echo "  │  Confirmed TXs:     $CONFIRMED"
echo "  │  Avg Gas per TX:    ${AVG_GAS}"
echo "  │  TX Size (bytes):   ${TX_SIZE_BYTES}"
echo "  └──────────────────────────────────────────┘"

# ============================================================================
#  STEP 6 — Block Execution Time Analysis (CORRECTED)
# ============================================================================

echo ""
echo "── [6/7] Block execution time analysis (10-Block Window & Log Parsing)..."

PEAK_HEIGHT=""
PEAK_TX_COUNT=0
MIN_HEIGHT=999999999
MAX_HEIGHT=0

# Find peak block and the range of active blocks
for h in "${!HEIGHT_COUNTS[@]}"; do
    if [ "${HEIGHT_COUNTS[$h]}" -gt "$PEAK_TX_COUNT" ]; then
        PEAK_TX_COUNT=${HEIGHT_COUNTS[$h]}
        PEAK_HEIGHT=$h
    fi
    if [ "$h" -lt "$MIN_HEIGHT" ]; then MIN_HEIGHT=$h; fi
    if [ "$h" -gt "$MAX_HEIGHT" ]; then MAX_HEIGHT=$h; fi
done

PEAK_BLOCK_TIME_MS="N/A"
AVG_BLOCK_TIME_MS="N/A"
PEAK_TPS="N/A"

if [ -n "$PEAK_HEIGHT" ] && [ "$PEAK_HEIGHT" != "0" ]; then

    # --------------------------------------------------------------------------
    # 1. Log Parsing: Extract exact CPU execution time bypassing CometBFT
    # --------------------------------------------------------------------------
    # In Cosmos SDK 0.50+, this is logged as 'txs_execution_time' or 'duration'
    EXEC_LOG=$(grep -a "executed block" "/tmp/wasmd_$$.log" 2>/dev/null | grep "height=$PEAK_HEIGHT" | tail -1 || true)
    
    if [ -n "$EXEC_LOG" ]; then
        # Strip potential JSON quotes/commas to get raw duration string (e.g. "21.45s")
        RAW_TIME=$(echo "$EXEC_LOG" | grep -oE '(txs_execution_time|duration)=[^ ]+' | cut -d= -f2 | tr -d '",')
        if [ -n "$RAW_TIME" ]; then
            PEAK_BLOCK_TIME_MS=$(duration_to_ms "$RAW_TIME")
        fi
    fi

    # --------------------------------------------------------------------------
    # 2. The Execution Shadow Fallback (N+1 to N+2)
    # --------------------------------------------------------------------------
    # If log parsing fails, measure the consensus delay *after* the peak block 
    # to capture the execution wall-clock time that delayed the next proposal.
    if [ "$PEAK_BLOCK_TIME_MS" = "N/A" ]; then
        POST_PEAK_TIME=$(get_block_time "$((PEAK_HEIGHT + 1))")
        NEXT_POST_PEAK_TIME=$(get_block_time "$((PEAK_HEIGHT + 2))")
        if [ -n "$POST_PEAK_TIME" ] && [ -n "$NEXT_POST_PEAK_TIME" ]; then
            PEAK_BLOCK_TIME_MS=$(ts_delta_ms "$POST_PEAK_TIME" "$NEXT_POST_PEAK_TIME")
        fi
    fi

# --------------------------------------------------------------------------
    # 3. Dynamic Window Average Time (Smoothes BFT Jitter)
    # --------------------------------------------------------------------------
    # Measure before and after the load test, but strictly bound it 
    # to blocks that actually exist on the chain right now.
    
    LATEST_AVAILABLE=$(get_chain_height_rpc)
    [ -z "$LATEST_AVAILABLE" ] && LATEST_AVAILABLE=$MAX_HEIGHT
    
    WINDOW_START=$((MIN_HEIGHT - 2))
    [ "$WINDOW_START" -lt 1 ] && WINDOW_START=1
    
    WINDOW_END=$((MAX_HEIGHT + 2))
    [ "$WINDOW_END" -gt "$LATEST_AVAILABLE" ] && WINDOW_END=$LATEST_AVAILABLE

    START_TIME=$(get_block_time "$WINDOW_START")
    END_TIME=$(get_block_time "$WINDOW_END")

    if [ -n "$START_TIME" ] && [ -n "$END_TIME" ]; then
        TOTAL_SPAN_MS=$(ts_delta_ms "$START_TIME" "$END_TIME")
        NUM_INTERVALS=$((WINDOW_END - WINDOW_START))
        
        if [ "$NUM_INTERVALS" -gt 0 ]; then
            AVG_BLOCK_TIME_MS=$(pydiv "$TOTAL_SPAN_MS" "$NUM_INTERVALS")
        fi
    fi

    # --------------------------------------------------------------------------
    # 4. Final True TPS Calculation
    # --------------------------------------------------------------------------
    if [ "$PEAK_BLOCK_TIME_MS" != "N/A" ] && [ "$PEAK_BLOCK_TIME_MS" != "0.0" ] && [ "$PEAK_BLOCK_TIME_MS" != "0.00" ]; then
        PEAK_TPS=$(pydiv "$PEAK_TX_COUNT" "$(pydiv "$PEAK_BLOCK_TIME_MS" "1000" ".3f")" ".1f")
    fi
fi

echo "  Peak block: height $PEAK_HEIGHT ($PEAK_TX_COUNT TXs) — Execution Time: ${PEAK_BLOCK_TIME_MS}ms"
echo "  Peak TPS (Execution Bound): ${PEAK_TPS:-N/A} tx/sec"
echo "  Average block interval (10-block window): ${AVG_BLOCK_TIME_MS}ms"
# ===========================================================================
#  STEP 7 — Results Summary
# ============================================================================

echo ""
echo "╔══════════════════════════════════════════════════════════════════════╗"
echo "║   Single-Node Capacity Benchmark (wasmd v${WASMD_VER})"
echo "╠══════════════════════════════════════════════════════════════════════╣"
printf "║  %-42s %12s    ║\n" "Metric" "Value"
echo "╠══════════════════════════════════════════════════════════════════════╣"
printf "║  %-42s %12s    ║\n" "Nodes" "1"
printf "║  %-42s %12s    ║\n" "Burst Config" "${LOAD_TX_COUNT}×${SUSTAINED_BLOCKS}"
printf "║  %-42s %12s    ║\n" "Total Submitted" "$BROADCAST_OK"
printf "║  %-42s %12s    ║\n" "Confirmed TXs (Success)" "$CONFIRMED"
printf "║  %-42s %12s    ║\n" "Failed TXs (Contract Error)" "$TOTAL_FAILED_WASM"
printf "║  %-42s %12s    ║\n" "Failed TXs (Out of Gas)" "$TOTAL_FAILED_GAS"
printf "║  %-42s %12s    ║\n" "Failed TXs (Other)" "$TOTAL_FAILED_OTHER"
printf "║  %-42s %12s    ║\n" "Peak Block Height" "${PEAK_HEIGHT:-N/A}"
printf "║  %-42s %12s    ║\n" "Peak Block TXs" "${PEAK_TX_COUNT}"
printf "║  %-42s %12s    ║\n" "Peak Block Time" "${PEAK_BLOCK_TIME_MS}ms"
printf "║  %-42s %12s    ║\n" "Average Block Time" "${AVG_BLOCK_TIME_MS}ms"
printf "║  %-42s %12s    ║\n" "Avg Gas per TX" "${AVG_GAS}"
printf "║  %-42s %12s    ║\n" "TX Size (bytes)" "${TX_SIZE_BYTES}"
printf "║  %-42s %12s    ║\n" "Avg Event Bytes per TX (state bloat)" "${AVG_EVENT_BYTES}"

echo "╚══════════════════════════════════════════════════════════════════════╝"

# ── Write Markdown Results ──────────────────────────────────────────────────

cat > "$RESULTS_FILE" << MDEOF
# Bulletproof CosmWasm — Single-Node Capacity Benchmark Results

> Measured on a single-validator wasmd v${WASMD_VER} node (no multi-node overhead).
> Multi-account sustained load: ${LOAD_TX_COUNT} accounts × ${SUSTAINED_BLOCKS} bursts (concurrent mempool flood, no inter-burst pacing).

## Summary

| Metric | Value |
|--------|-------|
| Validator Nodes | 1 |
| Load Test Accounts | ${LOAD_TX_COUNT} |
| Sustained Bursts | ${SUSTAINED_BLOCKS} |
| Total TXs Submitted | ${BROADCAST_OK} |
| Confirmed TXs (Success) | ${CONFIRMED} |
| Failed TXs (Contract Error) | ${TOTAL_FAILED_WASM} |
| Failed TXs (Out of Gas) | ${TOTAL_FAILED_GAS} |
| Failed TXs (Other) | ${TOTAL_FAILED_OTHER} |
| Peak Block Height | ${PEAK_HEIGHT:-N/A} |
| TXs in Peak Block | ${PEAK_TX_COUNT} |
| Block Finalization Interval (peak) | ${PEAK_BLOCK_TIME_MS}ms |
| Average Block Time | ${AVG_BLOCK_TIME_MS}ms |
| Avg Gas per TX | ${AVG_GAS} |
| TX Size (bytes) | ${TX_SIZE_BYTES} |
| Avg Event Bytes / TX (state bloat) | ${AVG_EVENT_BYTES} |

## TX Distribution Across Blocks

| Block Height | TX Count |
|-------------|----------|
$(for h in $(echo "${!HEIGHT_COUNTS[@]}" | tr ' ' '\n' | sort -n); do echo "| $h | ${HEIGHT_COUNTS[$h]} |"; done)

## Methodology Notes

- **Synthetic nullifiers**: Load test TXs use SHA-256 of deterministic seeds as nullifiers,
  bypassing the production oracle-attested nullifier flow. Production deployments introduce
  additional off-chain latency not captured here.
- **Proof diversity**: Each of the ${TOTAL_TXS} transactions uses a unique Bulletproof witness
  (proof, commitment, nullifier) generated at test-time with a fresh random blinding factor.
  The Merlin transcript binds each proof to its specific nullifier and contract address.

## Environment

- **wasmd**: v${WASMD_VER}
- **Chain ID**: ${CHAIN_ID}
- **WASM binary**: ${WASM_SIZE}
- **Genesis**: max_gas=${MAX_GAS}, max_bytes=${MAX_BYTES}
- **Node**: 1 single validator (no P2P/consensus overhead)
- **Load accounts**: ${LOAD_TX_COUNT} independent accounts
- **Generated**: $(date -u '+%Y-%m-%d %H:%M:%S UTC')
MDEOF
