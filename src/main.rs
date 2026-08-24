//! Runner for the 3i dispatch/policy design-option benchmark.
//!
//! See README.md for what each scenario corresponds to in the design document.

use std::sync::atomic::Ordering;
use std::sync::Arc;

use threei_dispatch_bench::bpf::{self, Program};
use threei_dispatch_bench::cage::{Grants, Lineage};
use threei_dispatch_bench::dispatch::{self, Leaf, Policy, CURRENT_CAGE};
use threei_dispatch_bench::grate::{self, TrampolineMode, FPTR_DENY, FPTR_FORWARD, FPTR_POLICY_FORWARD, GRATE_BASE};
use threei_dispatch_bench::handler::{
    DashNested, Flat, Handler, HandlerTable, MutexNested, RAWPOSIX_CAGEID,
};
use threei_dispatch_bench::timing::{bench, render_csv, render_table, Stat};

const CALLNUM: u64 = 63; // read
const SELF_CAGE: u64 = 1;

struct Args {
    trials: usize,
    depth: u64,
    ncheck: usize,
    leaf: Leaf,
    table: String,
    grates: Vec<usize>,
    threads: Vec<usize>,
    only: Option<String>,
    csv: Option<String>,
}

fn parse_args() -> Args {
    let mut a = Args {
        trials: 9,
        depth: 3,
        ncheck: 2,
        leaf: Leaf::Cheap,
        table: "mutex".into(),
        grates: vec![1, 2, 3],
        threads: vec![1, 2, 4, 8],
        only: None,
        csv: None,
    };
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < argv.len() {
        let next = |i: usize| argv.get(i + 1).cloned().unwrap_or_default();
        match argv[i].as_str() {
            "--trials" => { a.trials = next(i).parse().unwrap(); i += 2; }
            "--depth" => { a.depth = next(i).parse().unwrap(); i += 2; }
            "--ncheck" => { a.ncheck = next(i).parse().unwrap(); i += 2; }
            "--leaf" => {
                a.leaf = if next(i) == "syscall" { Leaf::HostSyscall } else { Leaf::Cheap };
                i += 2;
            }
            "--table" => { a.table = next(i); i += 2; }
            "--grates" => {
                a.grates = next(i).split(',').map(|s| s.parse().unwrap()).collect();
                i += 2;
            }
            "--threads" => {
                a.threads = next(i).split(',').map(|s| s.parse().unwrap()).collect();
                i += 2;
            }
            "--only" => { a.only = Some(next(i)); i += 2; }
            "--csv" => { a.csv = Some(next(i)); i += 2; }
            "-h" | "--help" => { print_help(); std::process::exit(0); }
            other => { eprintln!("unknown flag {other}"); print_help(); std::process::exit(2); }
        }
    }
    a
}

fn print_help() {
    println!(
        "threei-dispatch-bench\n\
         \n\
         --trials N        trials per scenario (default 9)\n\
         --depth N         how many levels below the caller the target/arg cages sit (default 3)\n\
         --ncheck N        how many of the six arg cage ids the policy inspects (default 2)\n\
         --leaf cheap|syscall   what rawposix does at the bottom (default cheap)\n\
         --table mutex|dash|flat  handler-table backend for the full-path scenarios (default mutex)\n\
         --grates 1,2,3    grate stack depths to measure\n\
         --threads 1,2,4,8 thread counts for the contention scenario\n\
         --only SUBSTR     only run scenarios whose name contains SUBSTR\n\
         --csv PATH        also write results as CSV\n"
    );
}

fn make_table(kind: &str) -> Box<dyn HandlerTable> {
    match kind {
        "dash" => Box::new(DashNested::new()),
        "flat" => Box::new(Flat::new()),
        _ => Box::new(MutexNested::new()),
    }
}

/// one full 16-arg make_syscall, with the arg cage ids the scenario asks for
#[inline(always)]
fn call16(self_cage: u64, target: u64, argc: u64) -> i32 {
    dispatch::make_syscall(
        self_cage, CALLNUM, 0, target,
        0x1000, argc, 0x2000, argc, 8, argc, 0, argc, 0, argc, 0, argc,
    )
}

fn main() {
    let args = parse_args();
    let keep = |name: &str| args.only.as_ref().map(|s| name.contains(s.as_str())).unwrap_or(true);

    let t = dispatch::init(make_table(&args.table));
    dispatch::set_leaf(args.leaf);
    dispatch::set_ncheck(args.ncheck);

    // cage tree: SELF_CAGE -> ... -> DESC, `depth` levels deep
    for d in 0..=args.depth {
        let parent = if d == 0 { 0 } else { SELF_CAGE + d - 1 };
        t.lineage.fork(parent, SELF_CAGE + d);
    }
    let desc = SELF_CAGE + args.depth;
    t.grants.grant(SELF_CAGE, desc);
    for d in 0..=args.depth {
        t.grants.grant(SELF_CAGE, SELF_CAGE + d);
    }

    dispatch::register_raw(SELF_CAGE, CALLNUM);

    let mut stats: Vec<Stat> = Vec::new();
    let push = |s: Stat, stats: &mut Vec<Stat>| {
        println!("  {:<44} {:>10.1} ns", s.name, s.ns_min);
        stats.push(s);
    };

    println!("\n== A. handler-table lookup only (no dispatch, no policy) ==");
    {
        let m = MutexNested::new();
        let d = DashNested::new();
        let f = Flat::new();
        for tb in [&m as &dyn HandlerTable, &d, &f] {
            let mut h = Handler::raw(dispatch::raw_leaf as *const () as u64);
            h.grateid = RAWPOSIX_CAGEID;
            tb.register(SELF_CAGE, CALLNUM, h);
        }
        for (label, tb) in [
            ("lookup/mutex-nested-hashmap", &m as &dyn HandlerTable),
            ("lookup/dashmap-nested", &d),
            ("lookup/flat-array", &f),
        ] {
            if !keep(label) { continue; }
            let s = bench("A lookup", label, args.trials, |n| {
                let mut acc = 0u64;
                for _ in 0..n {
                    acc += tb.get(SELF_CAGE, CALLNUM).map(|h| h.fnptr).unwrap_or(0);
                }
                acc
            });
            push(s, &mut stats);
        }
        if keep("lookup/flat-array, no vtable") {
            let s = bench("A lookup", "lookup/flat-array, no vtable", args.trials, |n| {
                let mut acc = 0u64;
                for _ in 0..n {
                    acc += f.get(SELF_CAGE, CALLNUM).map(|h| h.fnptr).unwrap_or(0);
                }
                acc
            });
            push(s, &mut stats);
        }
    }

    println!("\n== B1. the policy check in isolation (no table lookup, no leaf) ==");
    {
        let lin = Lineage::new();
        for d in 1..=32u64 {
            lin.fork(d - 1, d);
        }
        let g = Grants::new();
        for d in 0..=32u64 {
            g.grant(0, d);
        }
        for d in [1u64, 4, 16, 32] {
            let ids: Vec<u64> = std::iter::repeat(d).take(1 + args.ncheck).collect();
            let label = format!("2a check only: subtree-walk, depth {d}");
            if keep(&label) {
                let s = bench("B1 policy only", &label, args.trials, |n| {
                    let mut acc = 0u64;
                    for _ in 0..n {
                        acc += lin.all_in_subtree_walk(0, &ids) as u64;
                    }
                    acc
                });
                push(s, &mut stats);
            }
        }
        let ids: Vec<u64> = std::iter::repeat(32u64).take(1 + args.ncheck).collect();
        for (label, f) in [
            ("2a check only: subtree-bitset", 0),
            ("2b check only: grants-bitset", 1),
            ("2b check only: grants-hashset", 2),
        ] {
            if !keep(label) { continue; }
            let s = bench("B1 policy only", label, args.trials, |n| {
                let mut acc = 0u64;
                for _ in 0..n {
                    acc += match f {
                        0 => lin.all_in_subtree_bits(0, &ids) as u64,
                        1 => g.all_allowed_bits(0, &ids) as u64,
                        _ => g.all_allowed_hash(0, &ids) as u64,
                    };
                }
                acc
            });
            push(s, &mut stats);
        }
    }

    println!("\n== B. full make_syscall, policy inside 3i ==");
    let mut baseline_ns = 0.0f64;
    {
        let cases: Vec<(&str, Policy, u64)> = vec![
            ("B0 baseline: no policy (today's 3i)", Policy::None, SELF_CAGE),
            ("2a subtree-walk, target = self", Policy::SubtreeWalk, SELF_CAGE),
            ("2a subtree-walk, target = descendant", Policy::SubtreeWalk, desc),
            ("2a subtree-bits, target = self", Policy::SubtreeBits, SELF_CAGE),
            ("2a subtree-bits, target = descendant", Policy::SubtreeBits, desc),
            ("2b grants-hashset, target = descendant", Policy::GrantsHash, desc),
            ("2b grants-bitset, target = descendant", Policy::GrantsBits, desc),
        ];
        for (label, pol, target) in cases {
            if !keep(label) { continue; }
            dispatch::set_policy(pol);
            let s = bench("B in-3i policy", label, args.trials, |n| {
                let mut acc = 0i64;
                for _ in 0..n {
                    acc += call16(SELF_CAGE, target, target) as i64;
                }
                acc as u64
            });
            if label.starts_with("B0") { baseline_ns = s.ns_min; }
            push(s, &mut stats);
        }

        // 2c: eBPF-style filters
        let progs: Vec<(String, Program, bool)> = vec![
            ("2c ebpf: allow-all (1 insn)".into(), bpf::prog_allow_all(), true),
            ("2c ebpf: deny-all (1 insn)".into(), bpf::prog_deny_all(), true),
            (
                "2c ebpf: syscall allowlist, 8 entries".into(),
                bpf::prog_syscall_allowlist(&(0..8).collect::<Vec<_>>()),
                true,
            ),
            (
                "2c ebpf: syscall allowlist, 32 entries".into(),
                bpf::prog_syscall_allowlist(&(0..32).collect::<Vec<_>>()),
                true,
            ),
            (
                format!("2c ebpf: subtree check via helper, {} args", args.ncheck),
                bpf::prog_subtree_check(args.ncheck),
                true,
            ),
        ];
        for (label, prog, use_bits) in progs {
            if !keep(&label) { continue; }
            prog.verify().expect("program failed verification");
            dispatch::set_policy(Policy::Bpf(Arc::new(prog), use_bits));
            let s = bench("B in-3i policy", &label, args.trials, |n| {
                let mut acc = 0i64;
                for _ in 0..n {
                    acc += call16(SELF_CAGE, desc, desc) as i64;
                }
                acc as u64
            });
            push(s, &mut stats);
        }
        dispatch::set_policy(Policy::None);
    }

    println!("\n== C. Option 1: policy in a wasm grate ==");
    {
        let allow: Vec<u64> = (0..8).map(|i| SELF_CAGE + i).collect();
        for &n in &args.grates {
            for mode in [TrampolineMode::PerCall, TrampolineMode::Cached] {
                let modelabel = if mode == TrampolineMode::PerCall { "as-shipped" } else { "cached-typedfunc" };
                let label = format!("1 grate stack x{n} (forward, {modelabel})");
                if !keep(&label) { continue; }
                grate::build_chain(n, CALLNUM, mode, allow.len() as u32, SELF_CAGE, &allow).unwrap();
                // cage -> grate0 -> ... -> grate(n-1) -> rawposix
                dispatch::register_grate(SELF_CAGE, CALLNUM, GRATE_BASE, FPTR_FORWARD);
                for i in 0..n {
                    let gid = GRATE_BASE + i as u64;
                    if i + 1 < n {
                        dispatch::register_grate(gid, CALLNUM, GRATE_BASE + i as u64 + 1, FPTR_FORWARD);
                    } else {
                        dispatch::register_raw(gid, CALLNUM);
                    }
                }
                let s = bench("C grates", &label, args.trials, |k| {
                    let mut acc = 0i64;
                    for _ in 0..k {
                        acc += call16(SELF_CAGE, SELF_CAGE, SELF_CAGE) as i64;
                    }
                    acc as u64
                });
                push(s, &mut stats);
                grate::teardown();
            }
        }

        // one grate that only enforces policy
        for (fptr, label) in [
            (FPTR_DENY, "1 grate x1: deny immediately (no forward)"),
            (FPTR_POLICY_FORWARD, "1 grate x1: allowlist scan then forward"),
        ] {
            if !keep(label) { continue; }
            grate::build_chain(1, CALLNUM, TrampolineMode::PerCall, allow.len() as u32, SELF_CAGE, &allow).unwrap();
            dispatch::register_grate(SELF_CAGE, CALLNUM, GRATE_BASE, fptr);
            dispatch::register_raw(GRATE_BASE, CALLNUM);
            let s = bench("C grates", label, args.trials, |k| {
                let mut acc = 0i64;
                for _ in 0..k {
                    acc += call16(SELF_CAGE, SELF_CAGE, SELF_CAGE) as i64;
                }
                acc as u64
            });
            push(s, &mut stats);
            grate::teardown();
        }
        dispatch::register_raw(SELF_CAGE, CALLNUM);
    }

    println!("\n== D. Option 3: ABI width ==");
    {
        CURRENT_CAGE.with(|c| c.set(SELF_CAGE));
        dispatch::register_raw_with_argcages(SELF_CAGE, CALLNUM, [SELF_CAGE; 6]);
        if keep("3 narrow make_syscall") {
            let s = bench("D abi", "3 narrow make_syscall (7 args, host side)", args.trials, |n| {
                let mut acc = 0i64;
                for _ in 0..n {
                    acc += dispatch::make_syscall_narrow(CALLNUM, 0x1000, 0x2000, 8, 0, 0, 0) as i64;
                }
                acc as u64
            });
            push(s, &mut stats);
        }
        if keep("3 wide make_syscall") {
            let s = bench("D abi", "3 wide make_syscall (16 args, host side)", args.trials, |n| {
                let mut acc = 0i64;
                for _ in 0..n {
                    acc += call16(SELF_CAGE, SELF_CAGE, SELF_CAGE) as i64;
                }
                acc as u64
            });
            push(s, &mut stats);
        }
        if keep("wasm->host import") {
            let mut probe = grate::AbiProbe::new().unwrap();
            let s = bench("D abi", "wasm->host import, 16 params", args.trials, |n| {
                probe.run_wide(n as u32)
            });
            push(s, &mut stats);
            let s = bench("D abi", "wasm->host import, 7 params", args.trials, |n| {
                probe.run_narrow(n as u32)
            });
            push(s, &mut stats);
        }
        dispatch::register_raw(SELF_CAGE, CALLNUM);
    }

    println!("\n== E. setup / bookkeeping costs (not on the hot path) ==");
    {
        if keep("register_handler") {
            let tb = MutexNested::new();
            let mut h = Handler::raw(dispatch::raw_leaf as *const () as u64);
            h.grateid = RAWPOSIX_CAGEID;
            let s = bench("E setup", "register_handler (current, no arg cage ids)", args.trials, |n| {
                for i in 0..n {
                    tb.register(500 + (i % 64), CALLNUM, h);
                }
                n
            });
            push(s, &mut stats);
            let mut h2 = h;
            h2.arg_cageids = [SELF_CAGE; 6];
            let s = bench("E setup", "register_handler (option 3, 13 args)", args.trials, |n| {
                for i in 0..n {
                    tb.register(500 + (i % 64), CALLNUM, h2);
                }
                n
            });
            push(s, &mut stats);
        }
        if keep("fork") {
            let tb = MutexNested::new();
            let mut h = Handler::raw(dispatch::raw_leaf as *const () as u64);
            h.grateid = RAWPOSIX_CAGEID;
            for c in 0..64u64 {
                tb.register(SELF_CAGE, c, h);
            }
            let s = bench("E setup", "fork: copy_handler_table_to_cage (64 calls)", args.trials, |n| {
                for i in 0..n {
                    tb.copy_to_cage(SELF_CAGE, 600 + (i % 64));
                }
                n
            });
            push(s, &mut stats);

            let lin = Lineage::new();
            lin.fork(0, 1);
            let s = bench("E setup", "fork: 2a ancestor-bitset copy", args.trials, |n| {
                for i in 0..n {
                    lin.fork(1, 2 + (i % 500));
                }
                n
            });
            push(s, &mut stats);

            let g = Grants::new();
            for x in 0..16 {
                g.grant(1, 700 + x);
            }
            let s = bench("E setup", "fork: 2b grant-set inherit (16 grants)", args.trials, |n| {
                for i in 0..n {
                    g.inherit(1, 2 + (i % 500));
                }
                n
            });
            push(s, &mut stats);

            let s = bench("E setup", "2b grant + revoke pair", args.trials, |n| {
                for i in 0..n {
                    g.grant(1, 800 + (i % 100));
                    g.revoke(1, 800 + (i % 100));
                }
                n
            });
            push(s, &mut stats);
        }
        if keep("ebpf verify") {
            let p = bpf::prog_syscall_allowlist(&(0..32).collect::<Vec<_>>());
            let s = bench("E setup", "2c ebpf verifier, 34-insn program", args.trials, |n| {
                let mut ok = 0u64;
                for _ in 0..n {
                    ok += p.verify().is_ok() as u64;
                }
                ok
            });
            push(s, &mut stats);
        }
    }

    println!("\n== F. handler-table contention (aggregate ns per syscall, N threads) ==");
    {
        for &nt in &args.threads {
            let label = format!("F aggregate ns/syscall, {nt} thread(s)");
            if !keep(&label) { continue; }
            for c in 0..nt as u64 {
                dispatch::register_raw(900 + c, CALLNUM);
            }
            let s = bench("F contention", &label, args.trials.min(5), |n| {
                let per = (n / nt as u64).max(1);
                std::thread::scope(|scope| {
                    for c in 0..nt as u64 {
                        scope.spawn(move || {
                            let mut acc = 0i64;
                            for _ in 0..per {
                                acc += call16(900 + c, 900 + c, 900 + c) as i64;
                            }
                            acc
                        });
                    }
                });
                n
            });
            // report per-syscall latency as seen by each thread
            push(s, &mut stats);
        }
    }

    println!("\n{}", render_table(&stats, Some(baseline_ns)));
    println!(
        "denied={} (counter kept so the optimiser cannot delete the work)",
        t.denied.load(Ordering::Relaxed)
    );
    println!(
        "config: table={} depth={} ncheck={} leaf={} trials={}",
        args.table,
        args.depth,
        args.ncheck,
        if args.leaf == Leaf::HostSyscall { "host-syscall" } else { "cheap" },
        args.trials
    );

    if let Some(path) = args.csv {
        std::fs::write(&path, render_csv(&stats)).unwrap();
        println!("wrote {path}");
    }
}
