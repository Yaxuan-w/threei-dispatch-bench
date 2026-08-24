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

