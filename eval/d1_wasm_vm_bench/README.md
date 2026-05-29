# D1-VM — WASM VM CPU Overhead Benchmarks

Measures the **pure WASM VM execution overhead** of each CosmWasm smart contract
entry point within the Rare Bullet protocol, fully isolated from P2P gossip,
PBFT/Tendermint consensus, or networking overhead. Uses `cosmwasm-vm`
(Wasmer-backed) with the **Cranelift** compiler backend to match production
`wasmd`. The native CosmWasm WebAssembly runtime enables native Rust compilation
of the standard `bulletproofs` crate, completely bypassing EVM pre-compile
limitations. Empirically, the isolated WASM execution latency for aggregated
($m{=}2$) Bulletproof verification over 64 total bits is **30.2 ms**.

## Quick Start

```bash
cd eval/d1_wasm_vm_bench
cargo bench
```

The pre-built optimised WASM binary is loaded from
`../d1_bulletproof_cosmwasm/bulletproof_contract.wasm` (checked into the repo).

## Entry Points Benchmarked

| Benchmark | Entry Point | What It Measures |
|-----------|-------------|------------------|
| `wasmvm_instantiate` | `instantiate` | CW20 + vault config initialisation |
| `wasmvm_execute_deposit` | `execute(Deposit)` | Aggregated ($m{=}2$) Bulletproof verification (64 total bits) + CW20 mint + nullifier |
| `wasmvm_execute_transfer` | `execute(Transfer)` | CW20 token transfer (warm instance) |
| `wasmvm_execute_burn_request` | `execute(BurnAndRequest)` | CW20 burn + oracle request emit |
| `wasmvm_execute_fulfill` | `execute(FulfillRandomness)` | O(1) swap-and-pop vault selection |
| `wasmvm_query_active_count` | `query(ActiveCount)` | Storage read for active vault count |

## Methodology — Why These Numbers Are Trustworthy

### Eliminating Benchmark Artefacts

All benchmarks use `iter_custom` with **manual `Instant` timing** plus
`std::hint::black_box` on every measured result, explicitly avoiding four
classic micro-benchmark pitfalls:

1. **Drop Penalty:** Wasmer `Instance` destructor (memory unmap, page dealloc)
   runs ~30 ms on x86-64. We stop the timer *before* the instance is dropped.

2. **Cold-Start Memory Penalty:** `mock_instance_with_options` compiles WASM
   from scratch every call (no module caching). Production `wasmd` caches the
   compiled module. Our warm-instance strategy with untimed warm-up calls
   mirrors the steady-state production behaviour.

3. **Compiler Backend Mismatch:** `cosmwasm-vm` defaults to Singlepass
   (fast-compile / slow-execute). We enable Cranelift (`features = ["cranelift"]`)
   to match production `wasmd`, avoiding a ~10–20× timing inflation.

4. **Dead-Code Elimination:** All measured call results are passed through
   `std::hint::black_box()` to prevent the optimizer from eliding result
   construction or reordering timing fences.

### Warm-Instance Strategy

For the `Deposit` benchmark, multiple deposits execute on the **same warm
instance** (after an untimed warm-up deposit), mirroring production
`FinalizeBlock` where hundreds of TXs share warm L1i/L1d caches. A rotating
pool of 64 unique Bulletproof proofs prevents branch-prediction bias.

### Statistical Configuration (Criterion)

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `significance_level` | 0.05 | 95% bootstrap confidence intervals |
| `noise_threshold` | 0.02 | Suppress change reports for <2% shifts (OS scheduling jitter) |
| `warm_up_time` | 5 s | Ensure Cranelift JIT and CPU caches are fully primed |
| `measurement_time` (Deposit) | 30 s | Long enough for stable estimates on ~50 ms operations |
| `sample_size` (Deposit) | 10 | Trades sample count for reasonable total runtime |

## CPU Specification Variance Analysis

**Absolute wall-clock numbers will vary significantly across hardware.**
When reproducing these benchmarks or citing results in a paper, understanding
the sources of variance is critical.

### 1. Micro-architecture & IPC

The `Deposit` benchmark is dominated by **Ristretto255 multi-scalar
multiplication** — a chain of dependent 64-bit integer multiplies and
conditional moves implementing aggregated ($m{=}2$) Bulletproof verification
over 64 total bits ($2 \times 32$-bit dynamic boundaries via homomorphic
shifting). CPUs with wider issue width and deeper out-of-order
reorder buffers execute this faster:

| CPU Family | Approx. Relative Speed | Notes |
|------------|----------------------|-------|
| Apple M3 Pro / M4 | 1.0× (baseline) | Wide issue (8+), large ROB, high IPC |
| AMD Zen 4 (EPYC 9004 / Ryzen 7000) | ~1.1–1.3× | Excellent integer throughput, 6-wide decode |
| Intel Raptor Lake (13th/14th Gen) | ~1.2–1.5× | Competitive on P-cores, E-cores ~2× slower |
| AMD EPYC 7R13 (GitHub Actions) | ~2.0–3.0× | Older Zen 3 at lower clocks, shared vCPU |
| AWS Graviton 2 (Neoverse-N1) | ~2.5–4.0× | Narrower 4-wide decode, smaller ROB |

*Ratios are approximate; actual results depend on clock speed, turbo state,
and thermal throttling.*

### 2. Cache Hierarchy Impact

| Factor | Effect |
|--------|--------|
| **L1i size** | The Bulletproof verifier's hot loop compiles to ~32 KB of x86-64 machine code. CPUs with 32 KB L1i (common on ARM Cortex-A55, Graviton 2) may see elevated L1i miss rates. CPUs with 64+ KB L1i (Apple M-series, AMD Zen 4 at 32 KB per core but with µ-op cache) perform better. |
| **L1d / L2 latency** | Multi-scalar multiply performs random-access lookups into precomputed point tables (~16 KB). L1d hits are critical; L2 fallback adds ~3–5 ns per access. |
| **TLB reach** | Wasmer's linear memory uses 4 KB mmap'd pages. CPUs with larger TLBs (or transparent huge page support) avoid TLB misses during table lookups. |

### 3. CPU Frequency Scaling

Dynamic frequency governors (Intel Turbo Boost, AMD Precision Boost) **inflate
single-threaded results** on lightly loaded machines:

- **Bare-metal / laptop:** Peak turbo may sustain 4.5–5.5 GHz. Results are
  fast but may not be reproducible across runs if thermal throttling occurs.
- **CI runners (shared vCPU):** GitHub Actions runners typically run AMD EPYC
  at 2.4–3.5 GHz without sustained turbo. Results are slower but more stable.

**For reproducible paper figures:**
```bash
# Pin CPU governor to fixed frequency (requires root)
sudo cpupower frequency-set -g performance
# Or on systemd systems:
sudo systemctl stop thermald
```

### 4. CI vs. Bare-Metal Guidance

| Environment | Best Use | Expected Variance |
|-------------|----------|-------------------|
| **GitHub Actions** (shared vCPU) | Regression detection between commits | ~10–20% CoV, 2–4× slower absolute times |
| **Dedicated bare-metal** (fixed governor) | Paper figures, absolute performance claims | <5% CoV with proper pinning |
| **Laptop** (variable turbo) | Development iteration | ~5–15% CoV depending on thermal state |

> **Recommendation:** Report paper figures from a dedicated machine with
> a fixed CPU frequency governor. Record exact CPU model, core count, clock
> speed, and OS kernel version. Use CI results for automated regression
> detection only.

### 5. Non-CPU Factors

- **OS kernel version:** Linux kernel versions differ in `mmap`/`munmap`
  performance, affecting Wasmer instance creation (excluded from timing) but
  not the measured contract calls.
- **ASLR:** Address Space Layout Randomization may cause minor (~1%) jitter
  in instruction cache placement. Disable with
  `echo 0 | sudo tee /proc/sys/kernel/randomize_va_space` for maximum
  reproducibility.
- **Compiler version:** Cranelift code generation may change between
  `cosmwasm-vm` versions. Pin the exact `cosmwasm-vm` version (currently 1.5)
  in `Cargo.toml` for reproducibility across builds.

## Continuous Integration

The CI workflow (`.github/workflows/d1-wasm-vm-bench.yml`) runs on every
push/PR that modifies `eval/d1_wasm_vm_bench/`. It:

1. Prints the CI runner's hardware specification.
2. Builds and runs all Criterion benchmarks.
3. Uploads Criterion HTML reports as artifacts (downloadable for 30 days).
4. Writes a human-readable summary to the GitHub Actions job summary page.
5. Uploads raw benchmark logs as artifacts.

### Viewing CI Results

- **Job summary:** Open the workflow run → scroll to the bottom of the run
  page to see the rendered Markdown report with benchmark timings.
- **HTML reports:** Download the `criterion-reports` artifact. Open
  `report/index.html` in a browser for interactive violin plots and
  regression analysis.
- **Raw logs:** Download the `bench-logs` artifact for `bench.log`,
  `bench_report.md`, and `bench_env.txt`.

## Interpreting Results

Criterion reports each benchmark with:

- **Mean time:** The average execution time per iteration.
- **95% CI:** Bootstrap confidence interval — the true mean lies within this
  range with 95% probability.
- **Outliers:** Criterion classifies outliers (mild/severe) that may indicate
  OS scheduling interference or thermal throttling.

For `Deposit`, which is the most important benchmark (aggregated ($m{=}2$)
Bulletproof verification over 64 total bits is the dominant on-chain cost,
empirically measured at ~30.2 ms isolated WASM execution latency), look for:

- **Tight CI:** A narrow 95% CI (< 2% of mean) indicates stable measurements.
- **Low outlier count:** >5% severe outliers suggests environmental noise
  (shared CI runner, frequency throttling). Re-run on dedicated hardware.

## License

Same as the parent repository.
