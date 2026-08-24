//! Option 2c: a seccomp-BPF-shaped filter VM living inside 3i.
//!
//! Deliberately modest: a single accumulator, forward-only jumps, no loops, no
//! maps — i.e. the cheapest thing that could still express "deny this syscall",
//! "deny unless the arg cage id is X", "deny unless target is in my subtree".
//! A real implementation would need at least this much plus a verifier; the
//! verifier cost is charged at install time (`verify`), not on the hot path.

use crate::cage::Lineage;

#[derive(Clone, Copy, Debug)]
pub enum Insn {
    /// A = syscall number
    LdSyscall,
    /// A = caller cage id
    LdSelf,
    /// A = target cage id
    LdTarget,
    /// A = arg_cageids[i]
    LdArgCage(u8),
    /// A = args[i]
    LdArg(u8),
    /// A &= k
    AndK(u64),
    /// if A == k jump +jt else jump +jf
    JeqK { k: u64, jt: u8, jf: u8 },
    /// if A > k jump +jt else jump +jf
    JgtK { k: u64, jt: u8, jf: u8 },
    /// helper: A = in_subtree(self, A)  -- the "2a expressed in eBPF" case
    CallInSubtree,
    Ret(i32),
}

pub const ALLOW: i32 = 0;
pub const DENY: i32 = -1;

pub struct Ctx<'a> {
    pub self_cage: u64,
    pub target_cage: u64,
    pub syscall_num: u64,
    pub args: [u64; 6],
    pub arg_cageids: [u64; 6],
    pub lineage: &'a Lineage,
}

#[derive(Clone, Debug)]
pub struct Program {
    pub insns: Vec<Insn>,
}

impl Program {
    /// Bounded-execution verifier: forward-only jumps, in-range targets, every
    /// path terminates in a `Ret`. Runs at install time only.
    pub fn verify(&self) -> Result<(), String> {
        if self.insns.is_empty() {
            return Err("empty program".into());
        }
        if self.insns.len() > 4096 {
            return Err("program too long".into());
        }
        for (i, insn) in self.insns.iter().enumerate() {
            match insn {
                Insn::JeqK { jt, jf, .. } | Insn::JgtK { jt, jf, .. } => {
                    for off in [*jt, *jf] {
                        let dst = i + 1 + off as usize;
                        if dst >= self.insns.len() {
                            return Err(format!("insn {i}: jump out of range"));
                        }
                    }
                }
                Insn::LdArg(n) | Insn::LdArgCage(n) => {
                    if *n >= 6 {
                        return Err(format!("insn {i}: bad arg index"));
                    }
                }
                _ => {}
            }
        }
        match self.insns.last().unwrap() {
            Insn::Ret(_) => Ok(()),
            _ => Err("program must end in Ret".into()),
        }
    }

    #[inline]
    pub fn run(&self, ctx: &Ctx, use_bits: bool) -> i32 {
        let mut a: u64 = 0;
        let mut pc: usize = 0;
        loop {
            match self.insns[pc] {
                Insn::LdSyscall => a = ctx.syscall_num,
                Insn::LdSelf => a = ctx.self_cage,
                Insn::LdTarget => a = ctx.target_cage,
                Insn::LdArgCage(i) => a = ctx.arg_cageids[i as usize],
                Insn::LdArg(i) => a = ctx.args[i as usize],
                Insn::AndK(k) => a &= k,
                Insn::JeqK { k, jt, jf } => {
                    pc += 1 + if a == k { jt as usize } else { jf as usize };
                    continue;
                }
                Insn::JgtK { k, jt, jf } => {
                    pc += 1 + if a > k { jt as usize } else { jf as usize };
                    continue;
                }
                Insn::CallInSubtree => {
                    let ok = if use_bits {
                        ctx.lineage.in_subtree_bits(ctx.self_cage, a)
                    } else {
                        ctx.lineage.in_subtree_walk(ctx.self_cage, a)
                    };
                    a = ok as u64;
                }
                Insn::Ret(v) => return v,
            }
            pc += 1;
        }
    }
}

/// "always allow" — the one-instruction floor.
pub fn prog_allow_all() -> Program {
    Program { insns: vec![Insn::Ret(ALLOW)] }
}

/// "always deny" — the policy the design doc calls out as absurdly expensive to
/// express with a grate today.
pub fn prog_deny_all() -> Program {
    Program { insns: vec![Insn::Ret(DENY)] }
}

/// a seccomp-style allowlist: linear scan over `n` syscall numbers, deny otherwise.
pub fn prog_syscall_allowlist(allowed: &[u64]) -> Program {
    let mut insns = vec![Insn::LdSyscall];
    let n = allowed.len();
    for (i, k) in allowed.iter().enumerate() {
        // on match jump to the final Ret(ALLOW); otherwise fall through
        let remaining = (n - i - 1) as u8;
        insns.push(Insn::JeqK { k: *k, jt: remaining, jf: 0 });
    }
    insns.push(Insn::Ret(ALLOW));
    insns.push(Insn::Ret(DENY));
    // fix up: matches must land on the Ret(ALLOW) at index insns.len()-2
    let allow_idx = insns.len() - 2;
    for i in 1..=n {
        if let Insn::JeqK { jt, .. } = &mut insns[i] {
            *jt = (allow_idx - i - 1) as u8;
        }
    }
    Program { insns }
}

/// Option 2a expressed as an eBPF filter: every arg cage id must be inside the
/// caller's subtree. This is the case the design doc flags as "non trivial",
/// because the filter needs a helper with access to cage relationships.
pub fn prog_subtree_check(nargs: usize) -> Program {
    let mut insns = Vec::new();
    // target cage first
    insns.push(Insn::LdTarget);
    insns.push(Insn::CallInSubtree);
    insns.push(Insn::JeqK { k: 0, jt: 0, jf: 1 });
    insns.push(Insn::Ret(DENY));
    for i in 0..nargs {
        insns.push(Insn::LdArgCage(i as u8));
        insns.push(Insn::CallInSubtree);
        insns.push(Insn::JeqK { k: 0, jt: 0, jf: 1 });
        insns.push(Insn::Ret(DENY));
    }
    insns.push(Insn::Ret(ALLOW));
    Program { insns }
}
