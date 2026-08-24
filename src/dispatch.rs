//! The mini-3i under test.
//!
//! `make_syscall` mirrors `src/threei/src/threei.rs::make_syscall`: same 16-arg
//! ABI, same "look up handler, then either call a host fn pointer directly or
//! bounce into a grate through the runtime trampoline" shape. The policy hook is
//! the part the design options disagree about.

use parking_lot::RwLock;
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, AtomicU8, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};

use crate::bpf::{self, Program};
use crate::cage::{Grants, Lineage};
use crate::handler::{Handler, HandlerKind, HandlerTable, RAWPOSIX_CAGEID};

pub const EACCES: i32 = -13;

/// Which in-3i policy check runs on the hot path.
#[derive(Clone)]
pub enum Policy {
    /// Option 1 (policy is in a grate) and today's 3i: 3i itself checks nothing.
    None,
    /// Option 2a, parent-pointer lineage
    SubtreeWalk,
    /// Option 2a, ancestor-bitset lineage
    SubtreeBits,
    /// Option 2b, HashSet-backed grant table
    GrantsHash,
    /// Option 2b, bitset-backed grant table
    GrantsBits,
    /// Option 2c, in-3i eBPF-ish filter
    Bpf(Arc<Program>, bool),
}

/// What the bottom of the stack actually does, so that dispatch overhead can be
/// read against a plausible syscall body.
#[derive(Clone, Copy, PartialEq)]
pub enum Leaf {
    /// rawposix call served entirely from user space (getpid, fd table lookup)
    Cheap,
    /// rawposix call that ends in a real host syscall
    HostSyscall,
}

pub struct Threei {
    pub table: Box<dyn HandlerTable>,
    pub lineage: Lineage,
    pub grants: Grants,
    pub denied: AtomicU64,
}

/// Hot-path configuration is kept in relaxed atomics rather than locks: a real
/// 3i would compile these in or read them from a per-cage word, so charging a
/// lock acquisition to every scenario would just add uniform noise.
pub static POLICY_KIND: AtomicU8 = AtomicU8::new(P_NONE);
pub static NCHECK: AtomicUsize = AtomicUsize::new(2);
pub static LEAF_MODE: AtomicU8 = AtomicU8::new(0);
pub static BPF_PROG: RwLock<Option<(Arc<Program>, bool)>> = RwLock::new(None);

pub const P_NONE: u8 = 0;
pub const P_SUBTREE_WALK: u8 = 1;
pub const P_SUBTREE_BITS: u8 = 2;
pub const P_GRANTS_HASH: u8 = 3;
pub const P_GRANTS_BITS: u8 = 4;
pub const P_BPF: u8 = 5;

pub fn set_policy(p: Policy) {
    match p {
        Policy::None => POLICY_KIND.store(P_NONE, Ordering::Relaxed),
        Policy::SubtreeWalk => POLICY_KIND.store(P_SUBTREE_WALK, Ordering::Relaxed),
        Policy::SubtreeBits => POLICY_KIND.store(P_SUBTREE_BITS, Ordering::Relaxed),
        Policy::GrantsHash => POLICY_KIND.store(P_GRANTS_HASH, Ordering::Relaxed),
        Policy::GrantsBits => POLICY_KIND.store(P_GRANTS_BITS, Ordering::Relaxed),
        Policy::Bpf(prog, bits) => {
            *BPF_PROG.write() = Some((prog, bits));
            POLICY_KIND.store(P_BPF, Ordering::Relaxed);
        }
    }
}

pub fn set_leaf(l: Leaf) {
    LEAF_MODE.store(if l == Leaf::HostSyscall { 1 } else { 0 }, Ordering::Relaxed);
}

pub fn set_ncheck(n: usize) {
    NCHECK.store(n, Ordering::Relaxed);
}

static THREEI: OnceLock<Threei> = OnceLock::new();

pub fn init(table: Box<dyn HandlerTable>) -> &'static Threei {
    THREEI.get_or_init(|| Threei {
        table,
        lineage: Lineage::new(),
        grants: Grants::new(),
        denied: AtomicU64::new(0),
    })
}

pub fn threei() -> &'static Threei {
    THREEI.get().expect("threei not initialised")
}

/* ------------------------------------------------------------------ */
/* the leaf: stands in for rawposix                                    */
/* ------------------------------------------------------------------ */

#[inline(never)]
pub extern "C" fn raw_leaf(
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
) -> i32 {
    let acc = target_cageid
        ^ arg1.wrapping_add(arg1_cageid)
        ^ arg2.wrapping_add(arg2_cageid)
        ^ arg3.wrapping_add(arg3_cageid)
        ^ arg4.wrapping_add(arg4_cageid)
        ^ arg5.wrapping_add(arg5_cageid)
        ^ arg6.wrapping_add(arg6_cageid);
    if LEAF_MODE.load(Ordering::Relaxed) == 1 {
        // a genuinely un-cached host syscall, for scale
        unsafe {
            black_box(libc::getppid());
        }
    }
    // returned (rather than accumulated into a global) so that keeping the work
    // alive costs the benchmark an add in the caller instead of an atomic here
    acc as i32
}

/* ------------------------------------------------------------------ */
/* the policy hook                                                     */
/* ------------------------------------------------------------------ */

#[inline]
pub fn policy_ok(t: &Threei, self_cageid: u64, target_cageid: u64, arg_cageids: &[u64; 6]) -> bool {
    let kind = POLICY_KIND.load(Ordering::Relaxed);
    if kind == P_NONE {
        return true;
    }
    let n = NCHECK.load(Ordering::Relaxed);
    // target cage plus the first `n` arg cage ids
    let mut ids = [target_cageid; 7];
    ids[1..1 + n].copy_from_slice(&arg_cageids[..n]);
    let ids = &ids[..1 + n];

    match kind {
        P_SUBTREE_WALK => t.lineage.all_in_subtree_walk(self_cageid, ids),
        P_SUBTREE_BITS => t.lineage.all_in_subtree_bits(self_cageid, ids),
        P_GRANTS_HASH => t.grants.all_allowed_hash(self_cageid, ids),
        P_GRANTS_BITS => t.grants.all_allowed_bits(self_cageid, ids),
        P_BPF => {
            let guard = BPF_PROG.read();
            let (prog, use_bits) = guard.as_ref().expect("no filter installed");
            let ctx = bpf::Ctx {
                self_cage: self_cageid,
                target_cage: target_cageid,
                syscall_num: 0,
                args: [0; 6],
                arg_cageids: *arg_cageids,
                lineage: &t.lineage,
            };
            prog.run(&ctx, *use_bits) == bpf::ALLOW
        }
        _ => true,
    }
}

/* ------------------------------------------------------------------ */
/* the 16-argument hot path (today's ABI)                              */
/* ------------------------------------------------------------------ */

#[inline(never)]
pub extern "C" fn make_syscall(
    self_cageid: u64,
    syscall_num: u64,
    _syscall_name: u64,
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
) -> i32 {
    let t = threei();

    let argc = [
        arg1_cageid,
        arg2_cageid,
        arg3_cageid,
        arg4_cageid,
        arg5_cageid,
        arg6_cageid,
    ];
    if !policy_ok(t, self_cageid, target_cageid, &argc) {
        t.denied.fetch_add(1, Ordering::Relaxed);
        return EACCES;
    }

    let h = match t.table.get(self_cageid, syscall_num) {
        Some(h) => h,
        None => return -38, // ENOSYS
    };

    match h.kind {
        HandlerKind::Raw => {
            let func: crate::handler::RawCallFunc =
                unsafe { std::mem::transmute::<u64, crate::handler::RawCallFunc>(h.fnptr) };
            func(
                target_cageid,
                arg1,
                arg1_cageid,
                arg2,
                arg2_cageid,
                arg3,
                arg3_cageid,
                arg4,
                arg4_cageid,
                arg5,
                arg5_cageid,
                arg6,
                arg6_cageid,
            )
        }
        HandlerKind::Grate => crate::grate::call_grate(
            h.grateid,
            h.fnptr,
            arg1,
            arg1_cageid,
            arg2,
            arg2_cageid,
            arg3,
            arg3_cageid,
            arg4,
            arg4_cageid,
            arg5,
            arg5_cageid,
            arg6,
            arg6_cageid,
        ),
    }
}

/* ------------------------------------------------------------------ */
/* Option 3: the narrowed hot-path ABI                                 */
/* ------------------------------------------------------------------ */

thread_local! {
    /// stands in for "the runtime already knows who is calling", which is what
    /// lets Option 3 drop self_cageid/target_cageid from the call.
    pub static CURRENT_CAGE: std::cell::Cell<u64> = std::cell::Cell::new(0);
}

/// 7 arguments: syscall number + six payload words. The target cage and all six
/// arg cage ids come from the registration record, so a caller cannot spoof them.
#[inline(never)]
pub extern "C" fn make_syscall_narrow(
    syscall_num: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
    arg5: u64,
    arg6: u64,
) -> i32 {
    let t = threei();
    let self_cageid = CURRENT_CAGE.with(|c| c.get());

    let h = match t.table.get(self_cageid, syscall_num) {
        Some(h) => h,
        None => return -38,
    };
    let a = h.arg_cageids;
    let target_cageid = if h.kind == HandlerKind::Raw { self_cageid } else { h.grateid };

    match h.kind {
        HandlerKind::Raw => {
            let func: crate::handler::RawCallFunc =
                unsafe { std::mem::transmute::<u64, crate::handler::RawCallFunc>(h.fnptr) };
            func(
                target_cageid,
                arg1, a[0], arg2, a[1], arg3, a[2], arg4, a[3], arg5, a[4], arg6, a[5],
            )
        }
        HandlerKind::Grate => crate::grate::call_grate(
            h.grateid, h.fnptr,
            arg1, a[0], arg2, a[1], arg3, a[2], arg4, a[3], arg5, a[4], arg6, a[5],
        ),
    }
}

/* ------------------------------------------------------------------ */
/* re-entry from a grate                                               */
/* ------------------------------------------------------------------ */

/// A grate calling `MAKE_LEGACY_SYSCALL` lands here; it is the same 16-arg
/// `make_syscall`, just reached from inside wasm.
pub fn from_grate(
    self_cageid: u64,
    syscall_num: u64,
    target_cageid: u64,
    args: [u64; 12],
) -> i32 {
    make_syscall(
        self_cageid, syscall_num, 0, target_cageid,
        args[0], args[1], args[2], args[3], args[4], args[5],
        args[6], args[7], args[8], args[9], args[10], args[11],
    )
}

pub fn register_raw(cage: u64, callnum: u64) {
    let ptr = raw_leaf as *const () as u64;
    let mut h = Handler::raw(ptr);
    h.grateid = RAWPOSIX_CAGEID;
    threei().table.register(cage, callnum, h);
}

pub fn register_raw_with_argcages(cage: u64, callnum: u64, arg_cageids: [u64; 6]) {
    let ptr = raw_leaf as *const () as u64;
    let mut h = Handler::raw(ptr);
    h.grateid = RAWPOSIX_CAGEID;
    h.arg_cageids = arg_cageids;
    threei().table.register(cage, callnum, h);
}

pub fn register_grate(cage: u64, callnum: u64, grateid: u64, fnptr: u64) {
    threei().table.register(cage, callnum, Handler::grate(grateid, fnptr));
}
