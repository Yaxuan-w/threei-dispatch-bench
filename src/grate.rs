//! Option 1: real wasm grates, reached through a trampoline shaped like
//! `wasmtime/src/commands/run.rs::grate_callback_trampoline`.
//!
//! Faithfulness notes:
//! * each grate is its own `Store` + `Instance`, as in lind-wasm;
//! * `TrampolineMode::PerCall` reproduces upstream exactly — every dispatch does
//!   a vmctx-pool lookup, `get_export("pass_fptr_to_wt")` by name, and a
//!   `typed::<..>()` type check before the call;
//! * `TrampolineMode::Cached` keeps the `TypedFunc` and skips the pool churn, to
//!   show how much of Option 1's cost is inherent versus fixable;
//! * a grate that forwards calls the host import `threei.make_syscall`, so a
//!   stack of N grates costs N host->wasm entries plus N wasm->host exits.

use anyhow::Result;
use parking_lot::Mutex;
use std::cell::RefCell;
use std::collections::HashMap;
use wasmtime::{Engine, Instance, Linker, Module, Store, TypedFunc};

use crate::dispatch;

pub const GRATE_BASE: u64 = 100;

/// handler ids passed as `in_grate_fn_ptr`
pub const FPTR_FORWARD: u64 = 1;
pub const FPTR_DENY: u64 = 2;
pub const FPTR_POLICY_FORWARD: u64 = 3;

type Args14 = (u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64, u64);
type GrateEntry = TypedFunc<Args14, i32>;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum TrampolineMode {
    /// exactly what upstream does today
    PerCall,
    /// cached TypedFunc, no vmctx pool churn
    Cached,
}

struct Slot {
    store: RefCell<Store<()>>,
    instance: Instance,
    cached: RefCell<Option<GrateEntry>>,
}

pub struct Chain {
    slots: Vec<Slot>,
    mode: TrampolineMode,
    /// stands in for lind-3i's VMContext pool (`get_vmctx` / `set_vmctx`)
    vmctx_pool: Mutex<HashMap<u64, usize>>,
}

thread_local! {
    static CHAIN: RefCell<Option<Chain>> = RefCell::new(None);
}

/// Generates one grate module.
///
/// `callnum` is baked in because `register_handler` binds one grate function per
/// syscall, so the grate always knows which call it is forwarding.
/// `policy_len` is the size of the in-grate allowlist scan for `FPTR_POLICY_FORWARD`.
fn grate_wat(callnum: u64, policy_len: u32) -> String {
    format!(
        r#"(module
  (import "threei" "make_syscall" (func $ms
    (param i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64) (result i32)))
  (memory (export "memory") 1)
  (func (export "pass_fptr_to_wt")
    (param $fptr i64) (param $cage i64)
    (param $a1 i64) (param $c1 i64) (param $a2 i64) (param $c2 i64)
    (param $a3 i64) (param $c3 i64) (param $a4 i64) (param $c4 i64)
    (param $a5 i64) (param $c5 i64) (param $a6 i64) (param $c6 i64)
    (result i32)
    (local $i i32) (local $ok i32)

    ;; handler 2: deny outright
    (if (i64.eq (local.get $fptr) (i64.const 2))
      (then (return (i32.const -13))))

    ;; handler 3: policy check, then forward
    (if (i64.eq (local.get $fptr) (i64.const 3))
      (then
        (local.set $ok (i32.const 0))
        (local.set $i (i32.const 0))
        (block $done
          (loop $l
            (br_if $done (i32.ge_u (local.get $i) (i32.const {policy_len})))
            (if (i64.eq (i64.load (i32.mul (local.get $i) (i32.const 8))) (local.get $c1))
              (then (local.set $ok (i32.const 1)) (br $done)))
            (local.set $i (i32.add (local.get $i) (i32.const 1)))
            (br $l)))
        (if (i32.eqz (local.get $ok))
          (then (return (i32.const -13))))))

    ;; forward the call down the stack
    (call $ms
      (local.get $cage) (i64.const {callnum}) (i64.const 0) (local.get $cage)
      (local.get $a1) (local.get $c1) (local.get $a2) (local.get $c2)
      (local.get $a3) (local.get $c3) (local.get $a4) (local.get $c4)
      (local.get $a5) (local.get $c5) (local.get $a6) (local.get $c6))
  )
)
"#
    )
}

/// Builds `n` stacked grates for `callnum` and wires the handler table so that
/// cage -> grate0 -> grate1 -> ... -> rawposix.
pub fn build_chain(
    n: usize,
    callnum: u64,
    mode: TrampolineMode,
    policy_len: u32,
    _cage: u64,
    allowlist: &[u64],
) -> Result<()> {
    let engine = Engine::default();
    let module = Module::new(&engine, grate_wat(callnum, policy_len))?;

    let mut slots = Vec::new();
    for i in 0..n {
        let grateid = GRATE_BASE + i as u64;
        let mut store = Store::new(&engine, ());
        let mut linker: Linker<()> = Linker::new(&engine);
        linker.func_wrap(
            "threei",
            "make_syscall",
            move |self_cageid: u64,
                  syscall_num: u64,
                  _name: u64,
                  target_cageid: u64,
                  a1: u64, c1: u64, a2: u64, c2: u64, a3: u64, c3: u64,
                  a4: u64, c4: u64, a5: u64, c5: u64, a6: u64, c6: u64|
                  -> i32 {
                dispatch::from_grate(
                    self_cageid,
                    syscall_num,
                    target_cageid,
                    [a1, c1, a2, c2, a3, c3, a4, c4, a5, c5, a6, c6],
                )
            },
        )?;
        let instance = linker.instantiate(&mut store, &module)?;

        // seed the in-grate allowlist used by FPTR_POLICY_FORWARD
        let mem = instance.get_memory(&mut store, "memory").unwrap();
        let data = mem.data_mut(&mut store);
        for (k, v) in allowlist.iter().enumerate() {
            data[k * 8..k * 8 + 8].copy_from_slice(&v.to_le_bytes());
        }

        slots.push(Slot { store: RefCell::new(store), instance, cached: RefCell::new(None) });
        let _ = grateid;
    }

    let mut pool = HashMap::new();
    for i in 0..n {
        pool.insert(GRATE_BASE + i as u64, i);
    }

    CHAIN.with(|c| {
        *c.borrow_mut() = Some(Chain { slots, mode, vmctx_pool: Mutex::new(pool) });
    });
    Ok(())
}

pub fn teardown() {
    CHAIN.with(|c| *c.borrow_mut() = None);
}

/// The 3i-side `_call_grate_func` + the runtime-side trampoline, together.
pub fn call_grate(
    grateid: u64,
    fnptr: u64,
    a1: u64, c1: u64, a2: u64, c2: u64, a3: u64, c3: u64,
    a4: u64, c4: u64, a5: u64, c5: u64, a6: u64, c6: u64,
) -> i32 {
    CHAIN.with(|cell| {
        let borrowed = cell.borrow();
        let chain = borrowed.as_ref().expect("no grate chain built");

        let idx = match chain.mode {
            // upstream takes the vmctx out of the pool and pushes it back after
            TrampolineMode::PerCall => {
                let idx = chain.vmctx_pool.lock().remove(&grateid).expect("no vmctx");
                idx
            }
            TrampolineMode::Cached => (grateid - GRATE_BASE) as usize,
        };
        let slot = &chain.slots[idx];
        let mut store = slot.store.borrow_mut();

        let func: GrateEntry = match chain.mode {
            TrampolineMode::PerCall => {
                let ext = slot
                    .instance
                    .get_export(&mut *store, "pass_fptr_to_wt")
                    .expect("missing export `pass_fptr_to_wt`");
                let f = ext.into_func().expect("not a func");
                f.typed::<Args14, i32>(&*store).expect("bad signature")
            }
            TrampolineMode::Cached => {
                let mut cached = slot.cached.borrow_mut();
                if cached.is_none() {
                    let f = slot
                        .instance
                        .get_typed_func::<Args14, i32>(&mut *store, "pass_fptr_to_wt")
                        .expect("missing export");
                    *cached = Some(f);
                }
                cached.as_ref().unwrap().clone()
            }
        };

        let r = func
            .call(
                &mut *store,
                (fnptr, grateid, a1, c1, a2, c2, a3, c3, a4, c4, a5, c5, a6, c6),
            )
            .expect("grate trap");

        if chain.mode == TrampolineMode::PerCall {
            chain.vmctx_pool.lock().insert(grateid, idx);
        }
        r
    })
}

/// Measures the raw wasm->host import cost for a 16-argument versus a 7-argument
/// signature: the Option 3 ABI-narrowing claim, isolated from everything else.
pub struct AbiProbe {
    store: Store<()>,
    wide: TypedFunc<(u32,), u64>,
    narrow: TypedFunc<(u32,), u64>,
}

impl AbiProbe {
    pub fn new() -> Result<Self> {
        let engine = Engine::default();
        let wat = r#"(module
  (import "h" "wide" (func $wide
    (param i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64 i64) (result i32)))
  (import "h" "narrow" (func $narrow (param i64 i64 i64 i64 i64 i64 i64) (result i32)))
  (func (export "loop_wide") (param $n i32) (result i64)
    (local $i i32) (local $acc i64)
    (block $done (loop $l
      (br_if $done (i32.ge_u (local.get $i) (local.get $n)))
      (local.set $acc (i64.add (local.get $acc) (i64.extend_i32_u (call $wide
        (i64.const 1) (i64.const 2) (i64.const 0) (i64.const 1)
        (i64.const 3) (i64.const 1) (i64.const 4) (i64.const 1)
        (i64.const 5) (i64.const 1) (i64.const 6) (i64.const 1)
        (i64.const 7) (i64.const 1) (i64.const 8) (i64.const 1)))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $l)))
    (local.get $acc))
  (func (export "loop_narrow") (param $n i32) (result i64)
    (local $i i32) (local $acc i64)
    (block $done (loop $l
      (br_if $done (i32.ge_u (local.get $i) (local.get $n)))
      (local.set $acc (i64.add (local.get $acc) (i64.extend_i32_u (call $narrow
        (i64.const 2) (i64.const 3) (i64.const 4)
        (i64.const 5) (i64.const 6) (i64.const 7) (i64.const 8)))))
      (local.set $i (i32.add (local.get $i) (i32.const 1)))
      (br $l)))
    (local.get $acc))
)
"#;
        let module = Module::new(&engine, wat)?;
        let mut store = Store::new(&engine, ());
        let mut linker: Linker<()> = Linker::new(&engine);
        linker.func_wrap(
            "h",
            "wide",
            |a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64, a8: u64,
             a9: u64, a10: u64, a11: u64, a12: u64, a13: u64, a14: u64, a15: u64, a16: u64| -> i32 {
                ((a1 ^ a2 ^ a3 ^ a4 ^ a5 ^ a6 ^ a7 ^ a8 ^ a9 ^ a10 ^ a11 ^ a12 ^ a13 ^ a14 ^ a15
                    ^ a16)
                    & 1) as i32
            },
        )?;
        linker.func_wrap(
            "h",
            "narrow",
            |a1: u64, a2: u64, a3: u64, a4: u64, a5: u64, a6: u64, a7: u64| -> i32 {
                ((a1 ^ a2 ^ a3 ^ a4 ^ a5 ^ a6 ^ a7) & 1) as i32
            },
        )?;
        let instance = linker.instantiate(&mut store, &module)?;
        let wide = instance.get_typed_func::<(u32,), u64>(&mut store, "loop_wide")?;
        let narrow = instance.get_typed_func::<(u32,), u64>(&mut store, "loop_narrow")?;
        Ok(AbiProbe { store, wide, narrow })
    }

    pub fn run_wide(&mut self, n: u32) -> u64 {
        self.wide.call(&mut self.store, (n,)).unwrap()
    }
    pub fn run_narrow(&mut self, n: u32) -> u64 {
        self.narrow.call(&mut self.store, (n,)).unwrap()
    }
}
