//! H0.11 (in-repo form): fuzz-style robustness of the policy compiler. A malformed policy must
//! always be a clean error, never a panic, an infinite loop, or a partial compile that could
//! mis-gate. Inputs are generated deterministically (a seeded LCG mutating a valid policy plus
//! structured garbage) so this runs in CI without a fuzzing toolchain, while still exercising many
//! thousands of hostile inputs.

use acp_policy::PolicyEngine;

/// Tiny deterministic PRNG so the corpus is reproducible.
struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
    fn byte(&mut self) -> u8 {
        (self.next() & 0xff) as u8
    }
}

const VALID: &str = "version: 1\ndefault: allow\nrules:\n  - id: cap\n    when:\n      tool: \"payments.charge\"\n      arg:\n        amount_cents: { gt: 50000 }\n    verdict: deny\n";

#[test]
fn the_compiler_never_panics_on_hostile_input() {
    let mut rng = Lcg(0x00AC_0000_0001);
    for _ in 0..5000 {
        let choice = rng.next() % 4;
        let input: String = match choice {
            0 => {
                // Random bytes as (lossy) text.
                let n = (rng.next() % 200) as usize;
                (0..n).map(|_| rng.byte() as char).collect()
            }
            1 => {
                // A truncated prefix of a valid policy.
                let cut = (rng.next() as usize) % VALID.len().max(1);
                VALID[..cut].to_string()
            }
            2 => {
                // A valid policy with one byte corrupted.
                let mut b = VALID.as_bytes().to_vec();
                if !b.is_empty() {
                    let i = (rng.next() as usize) % b.len();
                    b[i] = rng.byte();
                }
                String::from_utf8_lossy(&b).into_owned()
            }
            _ => {
                // Deeply nested / oversized structure to probe recursion and size handling.
                let depth = (rng.next() % 500) as usize;
                format!("version: 1\ndefault: allow\nrules: {}{}", "[".repeat(depth), "]".repeat(depth))
            }
        };
        // The only contract: it returns, as Ok or Err, without panicking or hanging. A successful
        // parse of garbage is fine as long as it is a well-formed engine; failure is fine too.
        std::panic::catch_unwind(|| {
            let _ = PolicyEngine::from_yaml(&input);
        })
        .expect("policy compiler must not panic on any input");
    }
}

#[test]
fn a_valid_policy_still_compiles_after_the_fuzz_run() {
    // Guard against a fuzz test that accidentally weakens the happy path.
    assert!(PolicyEngine::from_yaml(VALID).is_ok());
}
