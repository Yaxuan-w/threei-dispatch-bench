//! Handler-table backends.
//!
//! `MutexNested` is a faithful re-implementation of lind-wasm's current default
//! backend (`src/threei/src/handler_table/hashmap_impl.rs`): a
//! `Mutex<HashMap<cageid, HashMap<callnum, HashMap<grateid, fnptr>>>>`, where the
//! innermost map is read with `keys().next()` / `values().next()`.
//!
//! `DashNested` mirrors the `dashmap` feature of the same crate.
//!
//! `Flat` is not in lind-wasm today; it is included as the "how cheap could the
//! hot-path lookup be" reference point, because every option in the design doc
//! that keeps the decision inside 3i is bounded from below by this number.

use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;

pub const MAX_CAGES: usize = 1024;
pub const MAX_SYSCALLS: usize = 512;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HandlerKind {
    /// dispatch straight to a host fn pointer (RAWPOSIX_CAGEID / WASMTIME_CAGEID)
    Raw,
    /// dispatch into a wasm grate through the runtime trampoline
    Grate,
}

#[derive(Clone, Copy, Debug)]
pub struct Handler {
    pub kind: HandlerKind,
    pub grateid: u64,
    pub fnptr: u64,
    /// Option 3: the arg cage ids are pinned at `register_handler` time instead
    /// of being passed on every `make_syscall`.
    pub arg_cageids: [u64; 6],
}

impl Handler {
    pub fn raw(fnptr: u64) -> Self {
        Handler { kind: HandlerKind::Raw, grateid: 0, fnptr, arg_cageids: [0; 6] }
    }
    pub fn grate(grateid: u64, fnptr: u64) -> Self {
        Handler { kind: HandlerKind::Grate, grateid, fnptr, arg_cageids: [0; 6] }
    }
}

pub trait HandlerTable: Send + Sync {
    fn name(&self) -> &'static str;
    fn register(&self, cage: u64, callnum: u64, h: Handler);
    fn get(&self, cage: u64, callnum: u64) -> Option<Handler>;
    /// models `copy_handler_table_to_cage` on fork
    fn copy_to_cage(&self, src: u64, dst: u64);
}

/* ------------------------------------------------------------------ */
/* Backend 1: Mutex<HashMap<..>> — what 3i ships with today            */
/* ------------------------------------------------------------------ */

type TargetCageMap = HashMap<u64, u64>;
type CallnumMap = HashMap<u64, TargetCageMap>;
type CageHandlerTable = HashMap<u64, CallnumMap>;

/// The nested map only stores `(grateid -> fnptr)`, exactly like upstream, so the
/// extra `Handler` metadata (kind / arg_cageids) is kept in a side table that is
/// *not* touched on the hot path unless the option under test needs it.
pub struct MutexNested {
    table: Mutex<CageHandlerTable>,
    meta: RwLock<HashMap<(u64, u64), Handler>>,
}

impl MutexNested {
    pub fn new() -> Self {
        MutexNested { table: Mutex::new(HashMap::new()), meta: RwLock::new(HashMap::new()) }
    }
}

impl HandlerTable for MutexNested {
    fn name(&self) -> &'static str {
        "mutex-nested-hashmap (upstream default)"
    }

    fn register(&self, cage: u64, callnum: u64, h: Handler) {
        let mut t = self.table.lock();
        let call_map = t.entry(cage).or_insert_with(HashMap::new);
        let target_map = call_map.entry(callnum).or_insert_with(HashMap::new);
        target_map.clear();
        target_map.insert(h.grateid, h.fnptr);
        drop(t);
        self.meta.write().insert((cage, callnum), h);
    }

    fn get(&self, cage: u64, callnum: u64) -> Option<Handler> {
        let t = self.table.lock();
        let call_map = t.get(&cage)?;
        let target_map = call_map.get(&callnum)?;
        let grateid = *target_map.keys().next()?;
        let fnptr = *target_map.values().next()?;
        drop(t);
        // upstream returns (grateid, fnptr) and decides Raw-vs-Grate by comparing
        // grateid against RAWPOSIX_CAGEID / WASMTIME_CAGEID / THREEI_CAGEID.
        let kind = if grateid == RAWPOSIX_CAGEID { HandlerKind::Raw } else { HandlerKind::Grate };
        let arg_cageids = if kind == HandlerKind::Raw {
            [0; 6]
        } else {
            self.meta.read().get(&(cage, callnum)).map(|h| h.arg_cageids).unwrap_or([0; 6])
        };
        Some(Handler { kind, grateid, fnptr, arg_cageids })
    }

    fn copy_to_cage(&self, src: u64, dst: u64) {
        let mut t = self.table.lock();
        if let Some(src_entry) = t.get(&src).cloned() {
            t.insert(dst, src_entry);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Backend 2: DashMap — the `dashmap` feature of the same crate        */
/* ------------------------------------------------------------------ */

pub struct DashNested {
    table: DashMap<u64, HashMap<u64, HashMap<u64, u64>>>,
}

impl DashNested {
    pub fn new() -> Self {
        DashNested { table: DashMap::new() }
    }
}

impl HandlerTable for DashNested {
    fn name(&self) -> &'static str {
        "dashmap-nested"
    }

    fn register(&self, cage: u64, callnum: u64, h: Handler) {
        let mut e = self.table.entry(cage).or_insert_with(HashMap::new);
        let target_map = e.entry(callnum).or_insert_with(HashMap::new);
        target_map.clear();
        target_map.insert(h.grateid, h.fnptr);
    }

    fn get(&self, cage: u64, callnum: u64) -> Option<Handler> {
        let e = self.table.get(&cage)?;
        let target_map = e.get(&callnum)?;
        let grateid = *target_map.keys().next()?;
        let fnptr = *target_map.values().next()?;
        let kind = if grateid == RAWPOSIX_CAGEID { HandlerKind::Raw } else { HandlerKind::Grate };
        Some(Handler { kind, grateid, fnptr, arg_cageids: [0; 6] })
    }

    fn copy_to_cage(&self, src: u64, dst: u64) {
        let cloned = self.table.get(&src).map(|e| e.clone());
        if let Some(c) = cloned {
            self.table.insert(dst, c);
        }
    }
}

/* ------------------------------------------------------------------ */
/* Backend 3: flat [cage][callnum] array — the lower bound             */
/* ------------------------------------------------------------------ */

pub struct Flat {
    rows: RwLock<Vec<Option<Box<[Option<Handler>]>>>>,
}

impl Flat {
    pub fn new() -> Self {
        Flat { rows: RwLock::new((0..MAX_CAGES).map(|_| None).collect()) }
    }
}

impl HandlerTable for Flat {
    fn name(&self) -> &'static str {
        "flat-array"
    }

    fn register(&self, cage: u64, callnum: u64, h: Handler) {
        let mut rows = self.rows.write();
        let row = rows[cage as usize]
            .get_or_insert_with(|| vec![None; MAX_SYSCALLS].into_boxed_slice());
        row[callnum as usize] = Some(h);
    }

    fn get(&self, cage: u64, callnum: u64) -> Option<Handler> {
        let rows = self.rows.read();
        rows[cage as usize].as_ref()?[callnum as usize]
    }

    fn copy_to_cage(&self, src: u64, dst: u64) {
        let mut rows = self.rows.write();
        let cloned = rows[src as usize].clone();
        rows[dst as usize] = cloned;
    }
}

/// mirrors `sysdefs::constants::lind_platform_const::RAWPOSIX_CAGEID`
pub const RAWPOSIX_CAGEID: u64 = 1;

/// mirrors `threei::RawCallFunc`
pub type RawCallFunc = extern "C" fn(
    target_cageid: u64,
    arg1: u64,
    arg1_cageid: u64,
    arg2: u64,
    arg2_cageid: u64,
    arg3: u64,
    arg3_cageid: u64,
    arg4: u64,
    arg4_cageid: u64,
    arg5: u64,
    arg5_cageid: u64,
    arg6: u64,
    arg6_cageid: u64,
) -> i32;
