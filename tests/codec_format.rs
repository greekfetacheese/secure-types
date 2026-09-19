//! The codec's error types: their `Display` and `core::error::Error` impls.

#![cfg(feature = "codec")]

use secure_types::DecodeError;

#[test]
fn test_errors_are_log_safe() {
   const MARKER: &str = "SECRET-MARK-SHOULD-NOT-APPEAR";

   let variants = [
      DecodeError::UnexpectedEnd,
      DecodeError::InvalidVarint,
      DecodeError::InvalidLength,
      DecodeError::InvalidUtf8,
      DecodeError::InvalidBool,
      DecodeError::InvalidOptionTag,
      DecodeError::InvalidChar,
      DecodeError::UnsupportedVersion(1),
      DecodeError::TrailingBytes { extra: 7 },
      DecodeError::FrameMismatch { unconsumed: 3 },
      DecodeError::Unsupported("deserialize_any"),
      DecodeError::Custom("a visitor rejected the value".to_owned()),
   ];

   for error in variants {
      let display = format!("{error}");
      let debug = format!("{error:?}");
      assert!(!display.is_empty());
      assert!(!debug.is_empty());
      assert!(
         !display.contains(MARKER) && !debug.contains(MARKER),
         "error echoed planted marker: {display} / {debug}"
      );
   }
}
