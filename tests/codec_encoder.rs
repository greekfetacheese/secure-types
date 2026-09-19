//! The codec encoder, exercised through the public API.

#![cfg(feature = "codec")]

use core::fmt;
use std::collections::BTreeMap;

use secure_types::{EncodeError, FORMAT_VERSION, SecureBytes, SecureVec};
use serde::Serialize;
use serde::ser::{self, SerializeMap as _, SerializeSeq as _, SerializeStruct as _};

#[test]
fn test_scalars_are_little_endian_and_fixed_width() {
   assert_encodes_to(&true, &[FORMAT_VERSION, 0x01]);
   assert_encodes_to(&false, &[FORMAT_VERSION, 0x00]);

   assert_encodes_to(&1u8, &[FORMAT_VERSION, 0x01]);
   assert_encodes_to(&0x0102u16, &[FORMAT_VERSION, 0x02, 0x01]);
   assert_encodes_to(&1u32, &[FORMAT_VERSION, 0x01, 0x00, 0x00, 0x00]);
   assert_encodes_to(
      &1u64,
      &[FORMAT_VERSION, 0x01, 0, 0, 0, 0, 0, 0, 0],
   );
   assert_encodes_to(
      &1u128,
      &[
         FORMAT_VERSION,
         0x01,
         0,
         0,
         0,
         0,
         0,
         0,
         0,
         0,
         0,
         0,
         0,
         0,
         0,
         0,
         0,
      ],
   );

   assert_encodes_to(&(-1i8), &[FORMAT_VERSION, 0xFF]);
   assert_encodes_to(&(-2i16), &[FORMAT_VERSION, 0xFE, 0xFF]);
   assert_encodes_to(
      &(-1i32),
      &[FORMAT_VERSION, 0xFF, 0xFF, 0xFF, 0xFF],
   );
   assert_encodes_to(
      &(-1i64),
      &[
         FORMAT_VERSION,
         0xFF,
         0xFF,
         0xFF,
         0xFF,
         0xFF,
         0xFF,
         0xFF,
         0xFF,
      ],
   );
   assert_encodes_to(
      &(-1i128),
      &[
         FORMAT_VERSION,
         0xFF,
         0xFF,
         0xFF,
         0xFF,
         0xFF,
         0xFF,
         0xFF,
         0xFF,
         0xFF,
         0xFF,
         0xFF,
         0xFF,
         0xFF,
         0xFF,
         0xFF,
         0xFF,
      ],
   );

   assert_encodes_to(&1.5f32, &[FORMAT_VERSION, 0x00, 0x00, 0xC0, 0x3F]);
   assert_encodes_to(
      &1.5f64,
      &[
         FORMAT_VERSION,
         0x00,
         0x00,
         0x00,
         0x00,
         0x00,
         0x00,
         0xF8,
         0x3F,
      ],
   );

   assert_encodes_to(&'A', &[FORMAT_VERSION, 0x41, 0x00, 0x00, 0x00]);
}

#[test]
fn test_str_is_length_prefixed_raw_utf8() {
   assert_encodes_to(&"", &[FORMAT_VERSION, 0x00]);
   assert_encodes_to(&"ab", &[FORMAT_VERSION, 0x02, b'a', b'b']);

   // Multi-byte UTF-8 is length-prefixed in bytes, not chars, and is not
   // escaped in any way.
   assert_encodes_to(&"é", &[FORMAT_VERSION, 0x02, 0xC3, 0xA9]);
}

#[test]
fn test_bytes_are_a_single_length_prefixed_blob() {
   // `SecureVec<u8>` serializes through `serialize_bytes`, so a key is one
   // framed blob rather than an element-per-byte sequence.
   let secret = SecureVec::from_slice(&[1u8, 2, 3]).unwrap();

   assert_encodes_to(&secret, &[FORMAT_VERSION, 0x03, 0x01, 0x02, 0x03]);
}

#[test]
fn test_option_unit_and_newtype() {
   assert_encodes_to(&Option::<u8>::None, &[FORMAT_VERSION, 0x00]);
   assert_encodes_to(&Some(7u8), &[FORMAT_VERSION, 0x01, 0x07]);

   assert_encodes_to(&(), &[FORMAT_VERSION]);
   assert_encodes_to(&UnitStruct, &[FORMAT_VERSION]);

   assert_encodes_to(&NewtypeStruct(9), &[FORMAT_VERSION, 0x09]);
}

#[test]
fn test_sequences_and_tuples_carry_their_length() {
   assert_encodes_to(
      &[1u8, 2, 3],
      &[FORMAT_VERSION, 0x03, 0x01, 0x02, 0x03],
   );
   assert_encodes_to(
      &[1u8, 2, 3][..],
      &[FORMAT_VERSION, 0x03, 0x01, 0x02, 0x03],
   );
   assert_encodes_to(
      &(1u8, 2u16),
      &[FORMAT_VERSION, 0x02, 0x01, 0x02, 0x00],
   );

   // A long count takes a multi-byte varint, so the prefix is not always one byte.
   let long = [0u8; 200];
   encoded(&long[..]).unlock_slice(|bytes| {
      assert_eq!(&bytes[..3], &[FORMAT_VERSION, 0xC8, 0x01]);
      assert_eq!(bytes.len(), 1 + 2 + 200);
   });
}

#[test]
fn test_maps() {
   let mut map = BTreeMap::new();
   map.insert("a", 1u8);
   assert_encodes_to(&map, &[FORMAT_VERSION, 0x01, 0x01, b'a', 0x01]);

   let mut pair = BTreeMap::new();
   pair.insert("a", 1u8);
   pair.insert("b", 2u8);
   assert_encodes_to(
      &pair,
      &[FORMAT_VERSION, 0x02, 0x01, b'a', 0x01, 0x01, b'b', 0x02],
   );
}

/// Pins the whole field layout: count, then name, `u32` length, and body.
#[test]
fn test_struct_field_layout() {
   assert_encodes_to(
      &Point { x: 1, y: 300 },
      &[
         FORMAT_VERSION,
         0x02,
         0x01,
         b'x',
         0x01,
         0x00,
         0x00,
         0x00,
         0x01,
         0x01,
         b'y',
         0x02,
         0x00,
         0x00,
         0x00,
         0x2C,
         0x01,
      ],
   );
}

/// The frame of `point` must cover the nested struct's whole encoding and
/// nothing more: a nested struct's first field must not close the frame of
/// the field holding it.
#[test]
fn test_nested_struct_frames_close_only_their_own_scope() {
   assert_encodes_to(
      &Outer {
         name: "ab",
         point: Point { x: 1, y: 300 },
      },
      &[
         FORMAT_VERSION,
         0x02,
         // "name" -> 2-byte string "ab"
         0x04,
         b'n',
         b'a',
         b'm',
         b'e',
         0x03,
         0x00,
         0x00,
         0x00,
         0x02,
         b'a',
         b'b',
         // "point" -> 16-byte nested struct
         0x05,
         b'p',
         b'o',
         b'i',
         b'n',
         b't',
         0x10,
         0x00,
         0x00,
         0x00,
         0x02,
         0x01,
         b'x',
         0x01,
         0x00,
         0x00,
         0x00,
         0x01,
         0x01,
         b'y',
         0x02,
         0x00,
         0x00,
         0x00,
         0x2C,
         0x01,
      ],
   );
}

#[test]
fn test_empty_and_fully_skipped_structs_emit_a_zero_count() {
   assert_encodes_to(&EmptyStruct {}, &[FORMAT_VERSION, 0x00]);
}

#[test]
fn test_skipped_fields_shift_the_count_and_nothing_else() {
   assert_encodes_to(
      &MidSkip {
         first: 1,
         middle: None,
         last: 2,
      },
      &[
         FORMAT_VERSION,
         0x02,
         0x05,
         b'f',
         b'i',
         b'r',
         b's',
         b't',
         0x01,
         0x00,
         0x00,
         0x00,
         0x01,
         0x04,
         b'l',
         b'a',
         b's',
         b't',
         0x01,
         0x00,
         0x00,
         0x00,
         0x02,
      ],
   );

   assert_encodes_to(
      &MidSkip {
         first: 1,
         middle: Some(9),
         last: 2,
      },
      &[
         FORMAT_VERSION,
         0x03,
         0x05,
         b'f',
         b'i',
         b'r',
         b's',
         b't',
         0x01,
         0x00,
         0x00,
         0x00,
         0x01,
         0x06,
         b'm',
         b'i',
         b'd',
         b'd',
         b'l',
         b'e',
         0x02,
         0x00,
         0x00,
         0x00,
         0x01,
         0x09,
         0x04,
         b'l',
         b'a',
         b's',
         b't',
         0x01,
         0x00,
         0x00,
         0x00,
         0x02,
      ],
   );
}

#[test]
fn test_skip_serializing_removes_the_field_entirely() {
   assert_encodes_to(
      &WithNever { kept: 1, never: 9 },
      &[
         FORMAT_VERSION,
         0x01,
         0x04,
         b'k',
         b'e',
         b'p',
         b't',
         0x01,
         0x00,
         0x00,
         0x00,
         0x01,
      ],
   );
}

#[test]
fn test_enum_variants_are_name_tagged() {
   assert_encodes_to(
      &Shape::Unit,
      &[FORMAT_VERSION, 0x04, b'U', b'n', b'i', b't'],
   );
   assert_encodes_to(
      &Shape::New(7),
      &[FORMAT_VERSION, 0x03, b'N', b'e', b'w', 0x07],
   );
   assert_encodes_to(
      &Shape::Tup(1, 300),
      &[
         FORMAT_VERSION,
         0x03,
         b'T',
         b'u',
         b'p',
         0x02,
         0x01,
         0x2C,
         0x01,
      ],
   );
   assert_encodes_to(
      &Shape::Named { a: 5 },
      &[
         FORMAT_VERSION,
         0x05,
         b'N',
         b'a',
         b'm',
         b'e',
         b'd',
         0x01,
         0x01,
         b'a',
         0x01,
         0x00,
         0x00,
         0x00,
         0x05,
      ],
   );
}

/// `serde`'s `collect_seq` passes `None` whenever `size_hint` is not exact,
/// so this path is reachable without a hand-written `Serialize` impl.
#[test]
fn test_unknown_length_seq_is_buffered_in_locked_memory() {
   assert_encodes_to(
      &UnknownLengthSeq,
      &[FORMAT_VERSION, 0x03, 0x01, 0x02, 0x03],
   );
}

#[test]
fn test_unknown_length_map_counts_entries_not_values() {
   assert_encodes_to(
      &UnknownLengthMap,
      &[FORMAT_VERSION, 0x02, 0x01, b'a', 0x01, 0x01, b'b', 0x02],
   );
}

/// A length prefix that lies about the payload would decode subtly wrong, so
/// a mis-counting `Serialize` impl is rejected instead of producing a buffer.
#[test]
fn test_element_count_mismatches_are_rejected() {
   assert!(matches!(
      secure_types::encode(&DeclaresTooMany),
      Err(EncodeError::ElementCountMismatch)
   ));

   assert!(matches!(
      secure_types::encode(&WritesMoreThanDeclared),
      Err(EncodeError::ElementCountMismatch)
   ));

   assert!(matches!(
      secure_types::encode(&StructDeclaresTooMany),
      Err(EncodeError::ElementCountMismatch)
   ));
}

/// `serde`'s default `collect_str` would build this string in a plain
/// `String`; ours streams it into locked memory and encodes it as a `str`.
#[test]
fn test_collect_str_encodes_as_a_length_prefixed_str() {
   assert_encodes_to(
      &Displays(7),
      &[FORMAT_VERSION, 0x04, b'i', b'd', b'-', b'7'],
   );
}

#[test]
fn test_is_not_human_readable() {
   struct RecordsReadability;

   impl Serialize for RecordsReadability {
      fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
      where
         S: ser::Serializer,
      {
         let readable = serializer.is_human_readable();
         serializer.serialize_bool(readable)
      }
   }

   assert_encodes_to(&RecordsReadability, &[FORMAT_VERSION, 0x00]);
}

// Brings in the `Serialize` *derive* as well as the trait, which is what the
// fixtures below are written with.
// Needed to call the sink methods on the associated types the manual
// `Serialize` impls below build. `as _` keeps the names out of the way.

/// Encodes `value` into a fresh locked buffer, version byte included.
fn encoded<T>(value: &T) -> SecureBytes
where
   T: ?Sized + Serialize,
{
   secure_types::encode(value).unwrap()
}

fn assert_encodes_to<T>(value: &T, expected: &[u8])
where
   T: ?Sized + Serialize,
{
   encoded(value).unlock_slice(|bytes| {
      assert_eq!(
         bytes, expected,
         "\n  actual:   {bytes:02X?}\n  expected: {expected:02X?}"
      )
   });
}

#[derive(Serialize)]
struct EmptyStruct {}

#[derive(Serialize)]
struct UnitStruct;

#[derive(Serialize)]
struct NewtypeStruct(u8);

#[derive(Serialize)]
struct Point {
   x: u8,
   y: u16,
}

#[derive(Serialize)]
struct Outer {
   name: &'static str,
   point: Point,
}

#[derive(Serialize)]
struct MidSkip {
   first: u8,
   #[serde(skip_serializing_if = "Option::is_none")]
   middle: Option<u8>,
   last: u8,
}

#[derive(Serialize)]
struct WithNever {
   kept: u8,
   #[serde(skip_serializing)]
   #[allow(dead_code)]
   never: u8,
}

#[derive(Serialize)]
enum Shape {
   Unit,
   New(u8),
   Tup(u8, u16),
   Named { a: u8 },
}

struct UnknownLengthSeq;

impl Serialize for UnknownLengthSeq {
   fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
   where
      S: ser::Serializer,
   {
      let mut seq = serializer.serialize_seq(None)?;
      seq.serialize_element(&1u8)?;
      seq.serialize_element(&2u8)?;
      seq.serialize_element(&3u8)?;
      seq.end()
   }
}

struct UnknownLengthMap;

impl Serialize for UnknownLengthMap {
   fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
   where
      S: ser::Serializer,
   {
      let mut map = serializer.serialize_map(None)?;
      map.serialize_entry("a", &1u8)?;
      map.serialize_entry("b", &2u8)?;
      map.end()
   }
}

struct DeclaresTooMany;

impl Serialize for DeclaresTooMany {
   fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
   where
      S: ser::Serializer,
   {
      let mut seq = serializer.serialize_seq(Some(3))?;
      seq.serialize_element(&1u8)?;
      seq.serialize_element(&2u8)?;
      seq.end()
   }
}

struct WritesMoreThanDeclared;

impl Serialize for WritesMoreThanDeclared {
   fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
   where
      S: ser::Serializer,
   {
      let mut seq = serializer.serialize_seq(Some(1))?;
      seq.serialize_element(&1u8)?;
      seq.serialize_element(&2u8)?;
      seq.end()
   }
}

struct StructDeclaresTooMany;

impl Serialize for StructDeclaresTooMany {
   fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
   where
      S: ser::Serializer,
   {
      let mut structure = serializer.serialize_struct("Short", 3)?;
      structure.serialize_field("a", &1u8)?;
      structure.end()
   }
}

struct Displays(u8);

impl fmt::Display for Displays {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      write!(f, "id-{}", self.0)
   }
}

impl Serialize for Displays {
   fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
   where
      S: ser::Serializer,
   {
      serializer.collect_str(self)
   }
}

/// The encode-side half of the property the decoder pins in
/// `codec_decoder.rs::test_error_messages_never_echo_wire_bytes`: an error must
/// never carry payload bytes, in `Display` or `Debug`.
#[test]
fn test_encode_errors_never_echo_payload_bytes() {
   const MARKER: &str = "SEED-PHRASE-MARKER-ENCODE";

   /// Writes a secret, then declares a different element count, so encoding
   /// fails *after* the secret has already been written.
   struct FailsAfterWritingTheSecret;

   impl Serialize for FailsAfterWritingTheSecret {
      fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
      where
         S: ser::Serializer,
      {
         let mut seq = serializer.serialize_seq(Some(2))?;
         seq.serialize_element(MARKER)?;
         seq.end()
      }
   }

   // `SecureBytes` deliberately does not implement `Debug`, so `unwrap_err()`
   // (which needs `T: Debug`) is not available here.
   let error = match secure_types::encode(&FailsAfterWritingTheSecret) {
      Ok(_) => panic!("encoding a mismatched element count should have failed"),
      Err(error) => error,
   };

   assert!(
      matches!(&error, EncodeError::ElementCountMismatch),
      "expected the count mismatch to fail the encoding, got {error:?}"
   );

   for form in [error.to_string(), format!("{error:?}")] {
      assert!(
         !form.contains(MARKER),
         "an encode error echoed payload bytes: {form}"
      );
   }
}

/// A `Serialize` impl's own rejection message must not reach the error either.
///
/// `serde::ser::Error::custom` is the only way an impl can attach text, and it is free to
/// format a secret into that text — which is exactly why the codec must not keep it. This is
/// the encode-side counterpart of the decoder's `test_wire_names_never_reach_the_error_message`;
/// before `Custom` lost its payload the marker below was rendered by both `Display` and `Debug`.
#[test]
fn test_a_serialize_impls_rejection_message_never_reaches_the_error() {
   const MARKER: &str = "SEED-PHRASE-MARKER-ENCODE-CUSTOM";

   struct RejectsWithTheSecret;

   impl Serialize for RejectsWithTheSecret {
      fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
      where
         S: ser::Serializer,
      {
         // A hand-written impl can put payload into its message; the codec discards it
         // rather than render it, so nothing reaches a log.
         let _ = serializer;
         Err(ser::Error::custom(format!(
            "refusing to encode {MARKER}"
         )))
      }
   }

   // `SecureBytes` deliberately does not implement `Debug`, so `unwrap_err()` is unavailable.
   let error = match secure_types::encode(&RejectsWithTheSecret) {
      Ok(_) => panic!("a rejected value should not encode"),
      Err(error) => error,
   };

   assert!(
      matches!(&error, EncodeError::Custom),
      "expected the message-free `Custom` variant, got {error:?}"
   );

   for form in [error.to_string(), format!("{error:?}")] {
      assert!(
         !form.contains(MARKER),
         "the encode error echoed the impl's message: {form}"
      );
   }
}
