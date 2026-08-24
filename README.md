# threei-dispatch-bench

A **standalone** Rust microbenchmark (independent of the lind-wasm repo) comparing the performance of the proposed 3i syscall-dispatch / policy-enforcement designs:

| Option | What the design doc proposes |
|---|---|---|
| Option 1 | Parent grate registers all syscalls for its children; policy lives entirely in the grate |
| Option 2a | Hierarchy policy fixed inside 3i (a cage may only reference its own subtree) |
| Option 2b | 2a, but grates can change the policy via a syscall |
| Option 2c | 3i supports eBPF-style allow/block filters |
| Option 3 | `register_handler` stores arg_cageids; `make_syscall` shrinks to 7 args |


## Why these numbers can be trusted

The hot path of lind-wasm is reproduced structurally:

* `src/handler.rs::MutexNested` mirrors `src/threei/src/handler_table/hashmap_impl.rs`: `Mutex<HashMap<cageid, HashMap<callnum, HashMap<grateid, fnptr>>>>`, down to reading the innermost map with `keys().next()` / `values().next()`. `DashNested` mirrors the `dashmap` feature.
* `src/dispatch.rs::make_syscall` mirrors `threei.rs::make_syscall`: the same 16-argument ABI, the same "look up the handler, then either `transmute` a raw fn pointer and call it directly (RawPOSIX) or bounce into a grate through the runtime trampoline".
* The grates in `src/grate.rs` are **real wasm** running on real wasmtime, and the trampoline follows `wasmtime/src/commands/run.rs::grate_callback_trampoline`:
  - `TrampolineMode::PerCall` (default, = what upstream does today): every dispatch does
    1. `get_vmctx` out of the vmctx pool and `set_vmctx` back after the call,
    2. `get_export("pass_fptr_to_wt")` **by name**,
    3. a `typed::<(u64 x14), i32>()` signature check, and only then `call`.
  - `TrampolineMode::Cached`: the `TypedFunc` is cached and the pool churn is dropped. This variant exists to answer "how much of Option 1's cost is *inherent* versus *an artifact of the current implementation*".
  - A forwarding grate calls the host import `threei.make_syscall`, so a stack of N grates costs N host→wasm entries plus N wasm→host exits, as it would in production.
* Each grate gets its own `Store` and `Instance`, as in lind-wasm.

**Known divergences** (all deliberate, and all of them make Option 1 look *better* than it really is — so the real numbers can only be worse):

* No asyncify / stack switching, no signal checks, no `grate_inflight` atomics, no `is_cage_dead` / `EXITING_TABLE` checks, no glibc-side `MAKE_LEGACY_SYSCALL` wrapper.
* The in-grate handler is an `if` chain rather than a real grate's dispatch logic.
* `Caller::with(vmctx)` is wasmtime-internal, so this holds a `Store` and calls directly; the vmctx pool cost is modelled as a `Mutex<HashMap>` remove + insert.

Hot-path policy configuration lives in relaxed atomics (`POLICY_KIND` / `NCHECK`) rather than locks, so that no scenario is charged uniform noise unrelated to the design choice under test. The leaf (rawposix) does a handful of XORs by default; `--leaf syscall` swaps in a genuine host syscall so dispatch overhead can be read against a real syscall cost.

## Usage

```bash
cargo run --release -- --trials 9 --csv results.csv
```

Flags:

```
--trials N        trials per scenario; min and median are reported (default 9)
--depth N         how many levels below the caller the target/arg cages sit (default 3;
                  this is what the 2a walk implementation is sensitive to)
--ncheck N        how many of the six arg cage ids the policy inspects (default 2)
--leaf cheap|syscall     what rawposix does at the bottom (default cheap)
--table mutex|dash|flat  handler-table backend for the full-path scenarios (default mutex,
                         which is what upstream ships)
--grates 1,2,3    grate stack depths to measure
--threads 1,2,4,8 thread counts for the contention scenario
--only SUBSTR     only run scenarios whose name contains SUBSTR
--csv PATH        also write results as CSV
```

## Reference results

Apple M-series (aarch64, macOS), `--trials 7`, `--table mutex`, `--depth 3`, `--ncheck 2`, user-space-only leaf (`cheap`). **Absolute values move with the machine; the ratios between options are stable.**

### Lookup only (group A)

| Scenario | ns/op |
|---|---:|
| `Mutex<HashMap<..>>`, three levels of nesting (upstream default) | 20.6 |
| `DashMap`, three levels of nesting | 21.5 |
| Flat `[cage][callnum]` array | 6.7 |

### The policy check in isolation (group B1 — no lookup, no leaf)

| Scenario | ns/op |
|---|---:|
| 2a ancestor bitset (O(1)) | 4.8 |
| 2b grant bitset | 4.8 |
| 2a parent-pointer walk, depth 1 | 4.8 |
| 2a parent-pointer walk, depth 4 | 7.4 |
| 2a parent-pointer walk, depth 16 | 26.4 |
| 2a parent-pointer walk, depth 32 | 61.7 |
| 2b grant HashSet | 27.4 |

### Full `make_syscall` (groups B / C / D)

| Scenario | ns/op | vs baseline |
|---|---:|---:|
| **B0 baseline: today's 3i, no policy** | **27.0** | 1.00x |
| 2c ebpf: always-deny (1 insn; returns before lookup and dispatch) | 13.0 | 0.48x |
| 3 narrowed ABI (7 args, host side) | 26.0 | 0.96x |
| 2b grants-bitset | 33.5 | 1.24x |
| 2a subtree-bitset | 34.1 | 1.26x |
| 2a subtree-walk (depth 3) | 34.1 | 1.26x |
| 2c ebpf: allow-all (1 insn) | 35.5 | 1.31x |
| 2c ebpf: syscall allowlist, 32 entries | 36.1 | 1.33x |
| 2c ebpf: subtree check via helper | 42.9 | 1.59x |
| 2b grants-hashset | 53.9 | 1.99x |
| **1 grate layer (cached typedfunc — the achievable floor)** | **167.1** | 6.2x |
| 2 grate layers (cached) | 276.6 | 10.2x |
| 3 grate layers (cached) | 422.0 | 15.6x |
| **1 grate layer (trampoline as shipped)** | **384.9** | 14.2x |
| 2 grate layers (as shipped) | 724.0 | 26.8x |
| 3 grate layers (as shipped) | 1051.1 | 38.9x |
| 1 grate layer: deny immediately, no forward | 323.5 | 12.0x |

Cost of the wasm→host import signature width alone (group D, isolated): 16 params **7.0 ns**, 7 params **3.8 ns**.

### Swapping the handler-table backend (`--table flat`)

| Scenario | nested Mutex+HashMap | flat array |
|---|---:|---:|
| B0 baseline, no policy | 27.0 ns | **11.2 ns** |
| 2a subtree-bitset | 34.1 ns | **15.8 ns** |

That is: **a flat table with the 2a policy switched on (15.8 ns) is 1.7x faster than today's table doing no policy work at all (27.0 ns).**

### One-time / bookkeeping costs (group E)

| Scenario | ns/op |
|---|---:|
| `register_handler` (current, 8 args) | 82.6 |
| `register_handler` (Option 3, 13 args with arg_cageids) | 79.4 |
| fork: `copy_handler_table_to_cage` (cage with 64 registered syscalls) | 3408 |
| fork: 2a ancestor-bitset copy | 23.1 |
| fork: 2b grant-set inherit (16 grants) | 54.1 |
| 2b grant + revoke pair | 35.2 |
| 2c eBPF verifier, 34-instruction program | 28.0 |

### Contention (group F, aggregate ns per syscall)

| Threads | Aggregate ns/syscall |
|---:|---:|
| 1 | 27.1 |
| 2 | 49.6 |
| 4 | 79.1 |
| 8 | 75.2 |
