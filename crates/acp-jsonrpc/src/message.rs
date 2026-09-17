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
    ParsedFrame::ToolCall(ToolCall {
        id,
        name,
        arguments,
    })
}

/// A lightweight structural read of a frame, used by the proxy to route without re-serialising.
#[derive(Debug, Clone, PartialEq)]
pub struct Inspected {
    /// The JSON-RPC method, if present (absent for responses).
    pub method: Option<String>,
    /// The request id, if present (absent for notifications and some responses).
    pub id: Option<Value>,
    /// True when the frame parsed as JSON at all.
    pub valid_json: bool,
    /// True when method == "tools/call".
    pub is_tool_call: bool,
}

/// Inspect a frame: extract method and id without mutating anything.
pub fn inspect(raw: &[u8]) -> Inspected {
    match serde_json::from_slice::<Value>(raw) {
        Ok(v) => {
            let method = v
                .get("method")
                .and_then(Value::as_str)
                .map(|s| s.to_string());
            let id = v.get("id").cloned();
            let is_tool_call = method.as_deref() == Some("tools/call");
            Inspected {
                method,
                id,
                valid_json: true,
                is_tool_call,
            }
        }
        Err(_) => Inspected {
            method: None,
            id: None,
            valid_json: false,
            is_tool_call: false,
        },
    }
}

/// A request has both a method and an id (as opposed to a notification, which has no id).
pub fn is_request(insp: &Inspected) -> bool {
    insp.method.is_some() && insp.id.is_some()
}

/// Build a single-line JSON-RPC error response for a given request id.
pub fn error_response(id: &Value, code: i64, message: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    })
    .to_string()
}
