//! H0.11 (in-repo form): fuzz-style robustness of frame inspection. The proxy inspects every byte
//! stream a client sends; a malformed frame must never panic the proxy (which would be a denial of
//! service and, worse, could drop a call out of governance). Deterministic corpus, no toolchain.

use acp_jsonrpc::{classify, inspect};

struct Lcg(u64);
impl Lcg {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        self.0 >> 33
    }
}

#[test]
fn frame_inspection_never_panics() {
    let mut rng = Lcg(0xF00D_1234);
    let seeds: [&[u8]; 3] = [
        br#"{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"x","arguments":{}}}"#,
        br#"{"jsonrpc":"2.0","id":1}"#,
        b"not json at all",
    ];
    for _ in 0..5000 {
        let mut buf = seeds[(rng.next() as usize) % seeds.len()].to_vec();
        // Apply a handful of random mutations.
        for _ in 0..(rng.next() % 8) {
            if buf.is_empty() {
                break;
            }
            let i = (rng.next() as usize) % buf.len();
            match rng.next() % 3 {
                0 => buf[i] = (rng.next() & 0xff) as u8,
                1 => {
                    buf.truncate(i);
                }
                _ => buf.insert(i, (rng.next() & 0xff) as u8),
            }
        }
        std::panic::catch_unwind(|| {
            let _ = classify(&buf);
            let _ = inspect(&buf);
        })
        .expect("frame inspection must not panic on any byte stream");
    }
}
