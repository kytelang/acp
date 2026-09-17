//! Output-encoding helpers for rendering untrusted content safely (R1/M4.5).
//!
//! The Slack Block Kit and web-inbox renderers land with the approval UI (acp-server); this
//! module holds the sink-agnostic escapers that are needed now, notably CSV/spreadsheet formula
//! injection, so an exported field beginning with `= + - @` is not executed as a formula in a
//! reviewer's spreadsheet.

/// Make a field safe for CSV / spreadsheet export: neutralise leading formula triggers.
pub fn csv_safe(field: &str) -> String {
    if field.starts_with(['=', '+', '-', '@', '\t', '\r']) {
        format!("'{field}")
    } else {
        field.to_string()
    }
}
