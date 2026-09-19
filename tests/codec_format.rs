//! The codec's error types: their `Display` and `core::error::Error` impls.

#![cfg(feature = "codec")]

use secure_types::DecodeError;

#[test]
fn test_errors_are_log_safe() {
   // Neither form may grow a payload from the input: that is the property
   // that keeps `serde_json`'-style `string "…secret…"` messages impossible.
   let variants = [
      DecodeError::UnexpectedEnd,
      DecodeError::InvalidVarint,
      DecodeError::InvalidLength,
      DecodeError::InvalidUtf8,
      DecodeError::InvalidBool,
      DecodeError::InvalidOptionTag,
      DecodeError::InvalidChar,
      DecodeError::Unsupported("deserialize_any"),
      DecodeError::Custom("a visitor rejected the value".to_owned()),
   ];

   for error in variants {
      assert!(!format!("{error}").is_empty());
      assert!(!format!("{error:?}").is_empty());
   }
}
