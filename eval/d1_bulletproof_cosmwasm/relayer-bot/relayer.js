/**
 * Rare Bullet — Simulated Oracle Relayer Bot
 *
 * An off-chain Node.js relayer that acts as the "simulated oracle" for the
 * two-phase asynchronous BurnAndRequest / FulfillRandomness claim flow.
 *
 * Architecture:
 *   1. Connects to a CosmWasm RPC endpoint using a mnemonic.
 *   2. Polls the blockchain every POLL_INTERVAL_MS for `wasm-oracle_request`
 *      events emitted by the Rare Bullet smart contract.
 *   3. For each detected request, generates a secure 64-bit random number
 *      using Node.js crypto.randomBytes().
 *   4. Signs and broadcasts a FulfillRandomness transaction to complete the
 *      vault selection.
 *
 * Usage:
 *   RPC_ENDPOINT=http://localhost:26657 \
 *   MNEMONIC="your twelve word mnemonic ..." \
 *   CONTRACT_ADDRESS=wasm1... \
 *   node relayer.js
 *
 * Environment Variables:
 *   RPC_ENDPOINT       — CosmWasm RPC URL (default: http://localhost:26657)
 *   MNEMONIC           — BIP39 mnemonic for the oracle relayer wallet
 *   CONTRACT_ADDRESS   — Address of the deployed Rare Bullet contract
 *   POLL_INTERVAL_MS   — Polling interval in milliseconds (default: 3000)
 *   GAS_PRICE          — Gas price string (default: "0.025ustake")
 *   CHAIN_ID           — Chain ID (default: "testing")
 *   PREFIX             — Bech32 prefix (default: "wasm")
 *
 * This script is designed as an "asynchronous systems-evaluation harness"
 * for academic benchmarking. It is NOT a production security mechanism.
 * In production, replace with Nois Network, drand, or TEE threshold
 * signatures.
 */

import { SigningCosmWasmClient } from "@cosmjs/cosmwasm-stargate";
import { DirectSecp256k1HdWallet } from "@cosmjs/proto-signing";
import { GasPrice } from "@cosmjs/stargate";
import crypto from "node:crypto";

// ── Configuration ──────────────────────────────────────────────────────

const RPC_ENDPOINT = process.env.RPC_ENDPOINT || "http://localhost:26657";
const MNEMONIC = process.env.MNEMONIC;
const CONTRACT_ADDRESS = process.env.CONTRACT_ADDRESS;
const POLL_INTERVAL_MS = parseInt(process.env.POLL_INTERVAL_MS || "3000", 10);
const GAS_PRICE_STR = process.env.GAS_PRICE || "0.025ustake";
const CHAIN_ID = process.env.CHAIN_ID || "testing";
const PREFIX = process.env.PREFIX || "wasm";

if (!MNEMONIC) {
  console.error("ERROR: MNEMONIC environment variable is required.");
  process.exit(1);
}
if (!CONTRACT_ADDRESS) {
  console.error("ERROR: CONTRACT_ADDRESS environment variable is required.");
  process.exit(1);
}

// ── Helpers ────────────────────────────────────────────────────────────

/**
 * Generate a cryptographically secure random 64-bit unsigned integer.
 * Reads 64 bits of randomness from Node.js native crypto and returns it
 * as a decimal string to match the contract's `random_seed: String` field.
 * By using BigInt.toString(), we preserve the full 64-bit entropy without
 * modulo bias and avoid JavaScript's Number.MAX_SAFE_INTEGER (2^53-1) limitation.
 */
function generateSecureRandomU64() {
  const buf = crypto.randomBytes(8);
  // Read as an unsigned 64-bit big-endian integer (Native BigInt).
  const value = buf.readBigUInt64BE();
  // BigInt.toString() accurately serializes the full 64-bit value without precision loss.
  // The CosmWasm JSON deserializer will parse this string flawlessly back into a Rust u64.
  return value.toString();
}

/**
 * Sleep for the specified number of milliseconds.
 */
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

// ── Main Relayer Loop ──────────────────────────────────────────────────

async function main() {
  console.log("╔══════════════════════════════════════════════════════════╗");
  console.log("║  Rare Bullet — Simulated Oracle Relayer Bot             ║");
  console.log("╚══════════════════════════════════════════════════════════╝");
  console.log(`  RPC:      ${RPC_ENDPOINT}`);
  console.log(`  Contract: ${CONTRACT_ADDRESS}`);
  console.log(`  Chain ID: ${CHAIN_ID}`);
  console.log(`  Poll:     ${POLL_INTERVAL_MS}ms`);
  console.log("");

  // 1. Connect wallet.
  const wallet = await DirectSecp256k1HdWallet.fromMnemonic(MNEMONIC, {
    prefix: PREFIX,
  });
  const [account] = await wallet.getAccounts();
  console.log(`  Oracle address: ${account.address}`);

  // 2. Connect to chain.
  const client = await SigningCosmWasmClient.connectWithSigner(
    RPC_ENDPOINT,
    wallet,
    { gasPrice: GasPrice.fromString(GAS_PRICE_STR) }
  );
  console.log("  Connected to chain.");
  console.log("");

  // Track the last processed block height to avoid duplicate processing.
  let lastProcessedHeight = 0;

  try {
    const status = await client.getBlock();
    lastProcessedHeight = status.header.height;
    console.log(`  Starting from block height: ${lastProcessedHeight}`);
  } catch {
    console.log("  Could not fetch current block; starting from 0.");
  }

  // 3. Polling loop.
  console.log("  Entering polling loop...\n");

  // eslint-disable-next-line no-constant-condition
  while (true) {
    try {
      // Query for oracle_request events from the contract.
      // We search for events with the wasm-oracle_request type.
      const currentBlock = await client.getBlock();
      const currentHeight = currentBlock.header.height;

      if (currentHeight <= lastProcessedHeight) {
        await sleep(POLL_INTERVAL_MS);
        continue;
      }

      // Search for transactions with oracle_request events in recent blocks.
      // Note: We rely on the height-based skip (tx.height <= lastProcessedHeight)
      // below to avoid re-processing already-handled events. On longer-running
      // chains, consider adding a WebSocket subscription for real-time events.
      const searchResult = await client.searchTx([
        { key: "wasm-oracle_request._contract_address", value: CONTRACT_ADDRESS },
      ]);

      for (const tx of searchResult) {
        // Skip already-processed transactions.
        if (tx.height <= lastProcessedHeight) continue;

        // Parse oracle_request events.
        for (const event of tx.events) {
          if (event.type !== "wasm-oracle_request") continue;

          const buyerAttr = event.attributes.find(
            (a) => a.key === "buyer"
          );
          const bucketAttr = event.attributes.find(
            (a) => a.key === "bucket_id"
          );

          if (!buyerAttr) continue;

          const buyerAddress = buyerAttr.value;
          const bucketId = bucketAttr ? bucketAttr.value : "unknown";

          console.log(
            `  [${new Date().toISOString()}] Detected oracle_request: buyer=${buyerAddress} bucket_id=${bucketId} height=${tx.height}`
          );

          // Check if the pending request still exists (not already fulfilled).
          try {
            const pending = await client.queryContractSmart(
              CONTRACT_ADDRESS,
              { get_pending_request: { buyer: buyerAddress } }
            );

            if (!pending.found) {
              console.log(`    Request already fulfilled, skipping.`);
              continue;
            }
          } catch (queryErr) {
            console.log(`    Could not query pending request: ${queryErr.message}`);
            continue;
          }

          // Generate secure random seed.
          const randomSeed = generateSecureRandomU64();
          console.log(`    Generated random_seed: ${randomSeed}`);

          // Broadcast FulfillRandomness transaction.
          try {
            const fulfillMsg = {
              fulfill_randomness: {
                buyer_address: buyerAddress,
                random_seed: randomSeed,
              },
            };

            const result = await client.execute(
              account.address,
              CONTRACT_ADDRESS,
              fulfillMsg,
              "auto",
              `Oracle fulfillment for ${buyerAddress}`
            );

            console.log(
              `    ✓ FulfillRandomness tx: ${result.transactionHash} gas=${result.gasUsed} height=${result.height}`
            );
          } catch (execErr) {
            console.error(
              `    ✗ FulfillRandomness failed: ${execErr.message}`
            );
          }
        }
      }

      lastProcessedHeight = currentHeight;
    } catch (err) {
      console.error(`  [${new Date().toISOString()}] Poll error: ${err.message}`);
    }

    await sleep(POLL_INTERVAL_MS);
  }
}

main().catch((err) => {
  console.error("Fatal error:", err);
  process.exit(1);
});
