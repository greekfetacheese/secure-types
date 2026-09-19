//! The codec's error types: their `Display` and `core::error::Error` impls.

#![cfg(feature = "codec")]

use secure_types::{DecodeError, EncodeError};

/// Every variant must render in both `Display` and `Debug` without panicking.
///
/// This test deliberately makes **no** claim that errors are free of payload
/// bytes: that property cannot be exercised by rendering hand-built variants.
/// It is pinned instead by the codec's own failing-decode / failing-encode
/// tests (`codec_decoder.rs`, `codec_encoder.rs`), which render an error
/// produced from a document that contains a planted marker. What is guarded
/// here is only the `Display`/`Debug` impls themselves.
#[test]
fn test_every_error_variant_renders() {
   let decode_variants = [
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
      DecodeError::Custom,
   ];

   for error in decode_variants {
      let display = error.to_string();
      let debug = format!("{error:?}");
      assert!(!display.is_empty(), "empty Display for {debug}");
      assert!(!debug.is_empty(), "empty Debug for {display}");
   }

   let encode_variants = [
      EncodeError::Secure(secure_types::Error::AllocationFailed),
      EncodeError::LengthOverflow,
      EncodeError::ElementCountMismatch,
      EncodeError::Unsupported("a bespoke Serialize trait"),
      EncodeError::Custom("a Serialize impl rejected the value".to_owned()),
   ];

   for error in encode_variants {
      let display = error.to_string();
      let debug = format!("{error:?}");
      assert!(!display.is_empty(), "empty Display for {debug}");
      assert!(!debug.is_empty(), "empty Debug for {display}");
   }
}
