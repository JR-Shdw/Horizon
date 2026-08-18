// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (C) 2024-2026 shdw <horizon@resurgamus.com>
//! Runtime-independent length-prefixed RPC framing.

use std::io::{self, Read, Write};

use serde_json::{json, Value};
use zeroize::Zeroize;
use zeroize::Zeroizing;

const LENGTH_PREFIX_BYTES: usize = 4;

/// Owns a parsed JSON tree and wipes every string when it leaves scope. JSON
/// numbers and booleans contain no heap-backed secret bytes to clear.
pub struct ZeroizingJson(Value);

impl ZeroizingJson {
    pub fn new(value: Value) -> Self {
        Self(value)
    }

    pub fn as_value(&self) -> &Value {
        &self.0
    }

    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(self.0.to_string().into_bytes())
    }
}

impl Drop for ZeroizingJson {
    fn drop(&mut self) {
        zeroize_json_strings(&mut self.0);
    }
}

/// Apply the legacy `{op,args}` request defaults and produce the established
/// `{result|error}` response envelope. Operation implementations return a JSON
/// value so the existing master can keep string results while control-plane
/// operations can return structured status.
pub fn dispatch_request<F>(request: Value, dispatch: F) -> ZeroizingJson
where
    F: FnOnce(&str, &Value) -> Result<Value, String>,
{
    let request = ZeroizingJson::new(request);
    let operation = request
        .as_value()
        .get("op")
        .and_then(Value::as_str)
        .unwrap_or("");
    let empty_arguments = json!({});
    let arguments = request.as_value().get("args").unwrap_or(&empty_arguments);
    ZeroizingJson::new(match dispatch(operation, arguments) {
        Ok(result) => json!({"result": result}),
        Err(error) => json!({"error": error}),
    })
}

pub fn error_response(error: impl Into<String>) -> ZeroizingJson {
    ZeroizingJson::new(json!({"error": error.into()}))
}

#[doc(hidden)]
pub fn zeroize_json_strings(value: &mut Value) {
    match value {
        Value::String(value) => value.zeroize(),
        Value::Array(values) => {
            for value in values {
                zeroize_json_strings(value);
            }
        }
        Value::Object(values) => {
            for value in values.values_mut() {
                zeroize_json_strings(value);
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
}

/// Read one `u32` big-endian length-prefixed frame. The declared length is
/// validated before allocation, and the returned payload wipes itself on drop.
pub fn read_frame<R: Read>(reader: &mut R, max_payload: usize) -> io::Result<Zeroizing<Vec<u8>>> {
    let mut length_bytes = [0u8; LENGTH_PREFIX_BYTES];
    reader.read_exact(&mut length_bytes)?;
    let length = u32::from_be_bytes(length_bytes) as usize;
    if length == 0 || length > max_payload {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "frame length out of bounds",
        ));
    }
    let mut payload = Zeroizing::new(vec![0u8; length]);
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

/// Write one `u32` big-endian length-prefixed frame.
pub fn write_frame<W: Write>(writer: &mut W, payload: &[u8], max_payload: usize) -> io::Result<()> {
    if payload.len() > max_payload || payload.len() > u32::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "response too large",
        ));
    }
    writer.write_all(&(payload.len() as u32).to_be_bytes())?;
    writer.write_all(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use serde_json::json;

    #[test]
    fn frame_roundtrip_is_transport_independent() {
        let mut wire = Vec::new();
        write_frame(&mut wire, b"custody", 64).expect("frame writes");
        let mut cursor = Cursor::new(wire);
        let payload = read_frame(&mut cursor, 64).expect("frame reads");
        assert_eq!(payload.as_slice(), b"custody");
    }

    #[test]
    fn zero_and_oversized_frames_fail_before_payload_allocation() {
        let mut zero = Cursor::new(0u32.to_be_bytes());
        assert_eq!(
            read_frame(&mut zero, 64)
                .expect_err("zero length is invalid")
                .kind(),
            io::ErrorKind::InvalidData
        );

        let mut oversized = Cursor::new(65u32.to_be_bytes());
        assert_eq!(
            read_frame(&mut oversized, 64)
                .expect_err("oversized frame is invalid")
                .kind(),
            io::ErrorKind::InvalidData
        );
    }

    #[test]
    fn truncated_payload_is_reported() {
        let mut wire = 4u32.to_be_bytes().to_vec();
        wire.extend_from_slice(b"abc");
        let error = read_frame(&mut Cursor::new(wire), 64).expect_err("payload is truncated");
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[test]
    fn writer_rejects_empty_limit_overflow() {
        let error = write_frame(&mut Vec::new(), b"x", 0).expect_err("limit is enforced");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(error.to_string(), "response too large");
    }

    #[test]
    fn json_guard_serializes_and_wipes_nested_strings() {
        let mut value = json!({
            "secret": "top-secret",
            "nested": ["second-secret", {"value": "third-secret"}],
            "number": 7,
        });
        zeroize_json_strings(&mut value);
        assert_eq!(value["secret"], "");
        assert_eq!(value["nested"][0], "");
        assert_eq!(value["nested"][1]["value"], "");
        assert_eq!(value["number"], 7);

        let guarded = ZeroizingJson::new(json!({"result": "ok"}));
        assert_eq!(guarded.to_bytes().as_slice(), br#"{"result":"ok"}"#);
    }

    #[test]
    fn shared_dispatch_preserves_legacy_defaults_and_envelope() {
        let response = dispatch_request(json!({"op": "ping"}), |operation, arguments| {
            assert_eq!(operation, "ping");
            assert_eq!(arguments, &json!({}));
            Ok(Value::String("pong".to_string()))
        });
        assert_eq!(response.to_bytes().as_slice(), br#"{"result":"pong"}"#);

        let error = dispatch_request(json!({}), |operation, _| {
            Err(format!("unknown op: {operation}"))
        });
        assert_eq!(error.to_bytes().as_slice(), br#"{"error":"unknown op: "}"#);
        assert_eq!(
            error_response("invalid JSON request").to_bytes().as_slice(),
            br#"{"error":"invalid JSON request"}"#
        );
    }
}
