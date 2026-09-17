use serde_json::Value;

/// The interesting shape extracted from a `tools/call` request.
#[derive(Debug, Clone, PartialEq)]
pub struct ToolCall {
    pub id: Value,
    pub name: String,
    pub arguments: Value,
}

/// A classified JSON-RPC frame. The original bytes are always retained for verbatim relay.
#[derive(Debug, Clone, PartialEq)]
pub enum ParsedFrame {
    /// A `tools/call` request we must decide on.
    ToolCall(ToolCall),
    /// Any other request/response/notification: relay untouched.
    Passthrough,
    /// Not valid JSON: relay untouched (do not become a failure point in the path).
    Opaque,
}

/// Classify a single JSON-RPC frame without altering it.
pub fn classify(raw: &[u8]) -> ParsedFrame {
    let v: Value = match serde_json::from_slice(raw) {
        Ok(v) => v,
        Err(_) => return ParsedFrame::Opaque,
    };
    let method = v.get("method").and_then(Value::as_str);
    if method != Some("tools/call") {
        return ParsedFrame::Passthrough;
    }
    let id = v.get("id").cloned().unwrap_or(Value::Null);
    let params = v.get("params");
    let name = params
        .and_then(|p| p.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_string();
    let arguments = params
        .and_then(|p| p.get("arguments"))
        .cloned()
        .unwrap_or(Value::Object(Default::default()));
    ParsedFrame::ToolCall(ToolCall { id, name, arguments })
}
