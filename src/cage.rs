//! Cage lineage (Option 2a) and dynamic grant sets (Option 2b).
//!
//! Option 2a needs 3i to answer "is `target` inside `caller`'s subtree?" on every
//! syscall. Two representations are benchmarked because they trade hot-path cost
//! against fork cost:
//!
//! * `walk`  — parent pointers only. O(depth) per check, O(1) per fork.
//! * `bits`  — every cage stores the bitset of its ancestors (including itself).
//!             O(1) per check, O(MAX_CAGES/64) copy per fork.
//!
//! Option 2b replaces the fixed subtree relation with an explicitly managed set,
//! again in a hash-set flavour and a bitset flavour.

use parking_lot::RwLock;
use std::collections::HashSet;

use crate::handler::MAX_CAGES;

const WORDS: usize = MAX_CAGES / 64;

pub struct Lineage {
    parent: RwLock<Vec<u64>>,
    depth: RwLock<Vec<u32>>,
    /// ancestors[c] has bit a set iff a is c or an ancestor of c
    ancestors: RwLock<Vec<Box<[u64; WORDS]>>>,
}

impl Lineage {
    pub fn new() -> Self {
        let mut ancestors: Vec<Box<[u64; WORDS]>> = Vec::with_capacity(MAX_CAGES);
        for _ in 0..MAX_CAGES {
            ancestors.push(Box::new([0u64; WORDS]));
        }
        let l = Lineage {
            parent: RwLock::new(vec![u64::MAX; MAX_CAGES]),
            depth: RwLock::new(vec![0; MAX_CAGES]),
            ancestors: RwLock::new(ancestors),
        };
        // cage 0 is the root and is its own ancestor
        l.ancestors.write()[0][0] |= 1;
        l
    }

    /// models the bookkeeping 3i would have to do on every fork under 2a
    pub fn fork(&self, parent: u64, child: u64) {
        self.parent.write()[child as usize] = parent;
        let d = self.depth.read()[parent as usize] + 1;
        self.depth.write()[child as usize] = d;
        let mut anc = self.ancestors.write();
        let p = *anc[parent as usize];
        let c = &mut anc[child as usize];
        **c = p;
        c[(child as usize) / 64] |= 1u64 << ((child as usize) % 64);
    }

    pub fn exit(&self, cage: u64) {
        self.parent.write()[cage as usize] = u64::MAX;
        *self.ancestors.write()[cage as usize] = [0u64; WORDS];
    }

    /// O(depth) ancestor walk
    #[inline]
    pub fn in_subtree_walk(&self, root: u64, cage: u64) -> bool {
        if root == cage {
            return true;
        }
        let parent = self.parent.read();
        let mut cur = cage as usize;
        loop {
            let p = parent[cur];
            if p == u64::MAX {
                return false;
            }
            if p == root {
                return true;
            }
            cur = p as usize;
        }
    }

    /// O(1) bitset check
    #[inline]
    pub fn in_subtree_bits(&self, root: u64, cage: u64) -> bool {
        let anc = self.ancestors.read();
        let r = root as usize;
        (anc[cage as usize][r / 64] >> (r % 64)) & 1 == 1
    }

    pub fn depth_of(&self, cage: u64) -> u32 {
        self.depth.read()[cage as usize]
    }
}

/// Option 2b: an explicit, grate-mutable "who may act on whom" relation.
pub struct Grants {
    sets: RwLock<Vec<HashSet<u64>>>,
    bits: RwLock<Vec<Box<[u64; WORDS]>>>,
}

impl Grants {
    pub fn new() -> Self {
        let mut bits: Vec<Box<[u64; WORDS]>> = Vec::with_capacity(MAX_CAGES);
        for _ in 0..MAX_CAGES {
            bits.push(Box::new([0u64; WORDS]));
        }
        Grants {
            sets: RwLock::new(vec![HashSet::new(); MAX_CAGES]),
            bits: RwLock::new(bits),
        }
    }

    pub fn grant(&self, holder: u64, target: u64) {
        self.sets.write()[holder as usize].insert(target);
        let t = target as usize;
        self.bits.write()[holder as usize][t / 64] |= 1u64 << (t % 64);
    }

    pub fn revoke(&self, holder: u64, target: u64) {
        self.sets.write()[holder as usize].remove(&target);
        let t = target as usize;
        self.bits.write()[holder as usize][t / 64] &= !(1u64 << (t % 64));
    }

    /// grants inherited by a forked child
    pub fn inherit(&self, parent: u64, child: u64) {
        let p = self.sets.read()[parent as usize].clone();
        self.sets.write()[child as usize] = p;
        let pb = *self.bits.read()[parent as usize];
        *self.bits.write()[child as usize] = pb;
    }

    #[inline]
    pub fn allowed_hash(&self, holder: u64, target: u64) -> bool {
        holder == target || self.sets.read()[holder as usize].contains(&target)
    }

    #[inline]
    pub fn allowed_bits(&self, holder: u64, target: u64) -> bool {
        let t = target as usize;
        holder == target || (self.bits.read()[holder as usize][t / 64] >> (t % 64)) & 1 == 1
    }
}

/* --- batched variants: one lock acquisition per make_syscall, which is what a
   real in-3i check would do (the per-id versions above are kept so the cost of
   getting this wrong is itself measurable). --- */

impl Lineage {
    #[inline]
    pub fn all_in_subtree_walk(&self, root: u64, ids: &[u64]) -> bool {
        let parent = self.parent.read();
        for &id in ids {
            if id == root {
                continue;
            }
            let mut cur = id as usize;
            let ok = loop {
                let p = parent[cur];
                if p == u64::MAX {
                    break false;
                }
                if p == root {
                    break true;
                }
                cur = p as usize;
            };
            if !ok {
                return false;
            }
        }
        true
    }

    #[inline]
    pub fn all_in_subtree_bits(&self, root: u64, ids: &[u64]) -> bool {
        let anc = self.ancestors.read();
        let r = root as usize;
        let (w, b) = (r / 64, r % 64);
        for &id in ids {
            if (anc[id as usize][w] >> b) & 1 != 1 {
                return false;
            }
        }
        true
    }
}

impl Grants {
    #[inline]
    pub fn all_allowed_hash(&self, holder: u64, ids: &[u64]) -> bool {
        let sets = self.sets.read();
        let s = &sets[holder as usize];
        ids.iter().all(|&t| t == holder || s.contains(&t))
    }

    #[inline]
    pub fn all_allowed_bits(&self, holder: u64, ids: &[u64]) -> bool {
        let bits = self.bits.read();
        let row = &bits[holder as usize];
        ids.iter().all(|&t| t == holder || (row[t as usize / 64] >> (t as usize % 64)) & 1 == 1)
    }
}
