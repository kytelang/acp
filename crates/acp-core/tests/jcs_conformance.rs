//! H1.4 canonicalisation conformance on ACP's record value domain. These pin the byte output for
//! the value shapes records actually use (sorted keys, normalised integers, escaped strings), so a
//! change to the canonicaliser that would alter a leaf hash is caught. Arbitrary-precision floats
//! remain a documented boundary, not covered here.

use acp_core::canonical::canonical_bytes;
use serde_json::json;

fn canon(v: serde_json::Value) -> String {
    String::from_utf8(canonical_bytes(&v)).unwrap()
}

#[test]
fn keys_are_sorted_regardless_of_insertion_order() {
    assert_eq!(
        canon(json!({"b": 1, "a": 2, "c": 3})),
        r#"{"a":2,"b":1,"c":3}"#
    );
    assert_eq!(
        canon(json!({"z": {"y": 1, "x": 2}})),
        r#"{"z":{"x":2,"y":1}}"#
    );
}

#[test]
fn integer_valued_floats_canonicalise_as_integers() {
    // 1.0 and 1 must produce identical bytes so they hash the same.
    assert_eq!(canon(json!(1.0)), canon(json!(1)));
    assert_eq!(canon(json!({"n": 42.0})), r#"{"n":42}"#);
}

#[test]
fn strings_and_nulls_and_bools_are_stable() {
    assert_eq!(
        canon(json!({"s": "a\"b", "t": true, "n": null})),
        r#"{"n":null,"s":"a\"b","t":true}"#
    );
}

#[test]
fn the_same_logical_value_two_ways_hashes_identically() {
    use acp_core::canonical::sha256_hex;
    let a = json!({"amount": 100.0, "tool": "x"});
    let b = json!({"tool": "x", "amount": 100});
    assert_eq!(
        sha256_hex(&a),
        sha256_hex(&b),
        "order + number form must not change the hash"
    );
}
