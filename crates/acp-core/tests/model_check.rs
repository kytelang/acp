//! A1 (in-repo form): an exhaustive interleaving check of the single-use-approval invariant
//! "at most one forward per approval". Full TLA+/stateright specs are the remaining formal leg;
//! this enumerates every interleaving of a bounded model in plain Rust, which is deterministic and,
//! crucially, catches a deliberately broken (non-atomic) consume, so it is a real check and not a
//! restatement of the code.
//!
//! Model: two workers each try to consume the same approval. A worker's consume is two micro-steps,
//! Read the consumed flag, then (if it read false) Write it true and count a "forward". We explore
//! all interleavings of the four micro-steps and assert the invariant on the number of forwards.

#[derive(Clone)]
struct Model {
    consumed: bool,
    // per-worker: what it read (None = not read yet), and whether it has written/won.
    read: [Option<bool>; 2],
    won: [bool; 2],
    forwards: u32,
}

impl Model {
    fn new() -> Self {
        Model {
            consumed: false,
            read: [None, None],
            won: [false, false],
            forwards: 0,
        }
    }
}

/// Return the states reachable from `m` by advancing worker `w` one micro-step, for the ATOMIC
/// model (read+test+set fused) or the BROKEN model (read and set are separate steps).
fn steps(m: &Model, w: usize, atomic: bool) -> Vec<Model> {
    let mut out = Vec::new();
    if m.won[w] || (m.read[w] == Some(true)) {
        return out; // this worker is done
    }
    if atomic {
        // One fused step: if not consumed, consume and win.
        let mut n = m.clone();
        if !n.consumed {
            n.consumed = true;
            n.won[w] = true;
            n.forwards += 1;
        }
        n.read[w] = Some(true); // mark done
        out.push(n);
    } else {
        match m.read[w] {
            None => {
                // Read step.
                let mut n = m.clone();
                n.read[w] = Some(m.consumed);
                out.push(n);
            }
            Some(false) => {
                // Write step: it earlier read "not consumed", so it sets and wins (the bug: it does
                // not re-check).
                let mut n = m.clone();
                n.consumed = true;
                n.won[w] = true;
                n.forwards += 1;
                n.read[w] = Some(true);
                out.push(n);
            }
            Some(true) => {}
        }
    }
    out
}

/// Explore the full interleaving state space; return the maximum forwards seen on any path.
fn max_forwards(atomic: bool) -> u32 {
    let mut stack = vec![Model::new()];
    let mut worst = 0;
    while let Some(m) = stack.pop() {
        worst = worst.max(m.forwards);
        for w in 0..2 {
            for n in steps(&m, w, atomic) {
                stack.push(n);
            }
        }
    }
    worst
}

#[test]
fn atomic_consume_forwards_at_most_once_on_every_interleaving() {
    assert_eq!(
        max_forwards(true),
        1,
        "atomic consume: at most one forward per approval"
    );
}

#[test]
fn the_checker_catches_a_broken_non_atomic_consume() {
    // The read-then-write consume admits an interleaving where both workers read "not consumed"
    // and both forward. If this assertion ever fails, the model checker itself is broken.
    assert_eq!(
        max_forwards(false),
        2,
        "non-atomic consume double-forwards; the check must see it"
    );
}

// D6 (in-repo form): "at most one leaf-extender per head". Two writers try to extend the Merkle
// head concurrently. Under a compare-and-set on the head version, at most one succeeds per head;
// a blind (non-CAS) write lets both extend the same head, which the checker must catch.

#[derive(Clone)]
struct HeadModel {
    version: u32,           // the current head version
    read: [Option<u32>; 2], // what each writer read
    done: [bool; 2],
    extends_at_v0: u32, // how many writers extended while head was at version 0
}

fn head_steps(m: &HeadModel, w: usize, cas: bool) -> Vec<HeadModel> {
    let mut out = Vec::new();
    if m.done[w] {
        return out;
    }
    if cas {
        // Fused read-compare-set: extend only if the head is still at the version we expect (0).
        let mut n = m.clone();
        if n.version == 0 {
            n.version = 1;
            n.extends_at_v0 += 1;
        }
        n.done[w] = true;
        out.push(n);
    } else {
        match m.read[w] {
            None => {
                let mut n = m.clone();
                n.read[w] = Some(m.version);
                out.push(n);
            }
            Some(seen) => {
                // Blind write: extend based on the stale read, no re-check.
                let mut n = m.clone();
                if seen == 0 {
                    n.extends_at_v0 += 1;
                }
                n.version = seen + 1;
                n.done[w] = true;
                out.push(n);
            }
        }
    }
    out
}

fn max_extends_at_v0(cas: bool) -> u32 {
    let start = HeadModel {
        version: 0,
        read: [None, None],
        done: [false, false],
        extends_at_v0: 0,
    };
    let mut stack = vec![start];
    let mut worst = 0;
    while let Some(m) = stack.pop() {
        worst = worst.max(m.extends_at_v0);
        for w in 0..2 {
            for n in head_steps(&m, w, cas) {
                stack.push(n);
            }
        }
    }
    worst
}

#[test]
fn cas_head_extension_allows_at_most_one_leaf_extender_per_head() {
    assert_eq!(
        max_extends_at_v0(true),
        1,
        "D6: at most one leaf-extender per head"
    );
}

#[test]
fn the_checker_catches_a_blind_head_extension() {
    assert_eq!(
        max_extends_at_v0(false),
        2,
        "blind extension forks the head; the check must see it"
    );
}
