use acp_jsonrpc::message::{classify, ParsedFrame};

#[test]
fn non_toolcall_is_passthrough() {
    for raw in [
        br#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#.as_slice(),
        br#"{"jsonrpc":"2.0","method":"notifications/message","params":{}}"#.as_slice(),
        br#"{"jsonrpc":"2.0","id":3,"result":{"ok":true}}"#.as_slice(),
    ] {
        assert_eq!(classify(raw), ParsedFrame::Passthrough, "raw: {:?}", raw);
    }
}

#[test]
fn invalid_json_is_opaque_not_an_error() {
    assert_eq!(classify(b"not json at all"), ParsedFrame::Opaque);
    assert_eq!(classify(b""), ParsedFrame::Opaque);
}

#[test]
fn toolcall_is_extracted() {
    let raw = br#"{"jsonrpc":"2.0","id":7,"method":"tools/call",
        "params":{"name":"payments.charge","arguments":{"amount_cents":90000}}}"#;
    match classify(raw) {
        ParsedFrame::ToolCall(tc) => {
            assert_eq!(tc.name, "payments.charge");
            assert_eq!(tc.arguments["amount_cents"], 90000);
            assert_eq!(tc.id, serde_json::json!(7));
        }
        other => panic!("expected ToolCall, got {other:?}"),
    }
}
