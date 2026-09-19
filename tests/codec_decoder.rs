//! The codec decoder, exercised through the public API.

#![cfg(feature = "codec")]

use std::collections::BTreeMap;

use secure_types::{
   DecodeError, FORMAT_VERSION, SecureArray, SecureBytes, SecureString, SecureVec,
};
use serde::de::{self, DeserializeOwned};
use serde::{Deserialize, Serialize};

#[test]
fn test_scalars_round_trip() {
   assert!(round_trip(&true));
   assert!(!round_trip(&false));

   assert_eq!(round_trip(&0x12u8), 0x12);
   assert_eq!(round_trip(&u16::MAX), u16::MAX);
   assert_eq!(round_trip(&u32::MAX), u32::MAX);
   assert_eq!(round_trip(&u64::MAX), u64::MAX);
   assert_eq!(round_trip(&u128::MAX), u128::MAX);

   assert_eq!(round_trip(&i8::MIN), i8::MIN);
   assert_eq!(round_trip(&i16::MIN), i16::MIN);
   assert_eq!(round_trip(&i32::MIN), i32::MIN);
   assert_eq!(round_trip(&i64::MIN), i64::MIN);
   assert_eq!(round_trip(&i128::MIN), i128::MIN);

   assert_eq!(round_trip(&1.5f32), 1.5f32);
   assert_eq!(round_trip(&(-0.0f64)), -0.0f64);
   assert!(round_trip(&f32::NAN).is_nan());
   assert!(round_trip(&f64::INFINITY).is_infinite());

   assert_eq!(round_trip(&'λ'), 'λ');
   assert_eq!(round_trip(&'\u{10FFFF}'), '\u{10FFFF}');
}

#[test]
fn test_option_and_unit_round_trip() {
   assert_eq!(round_trip(&None::<u8>), None);
   assert_eq!(round_trip(&Some(7u8)), Some(7));
   assert_eq!(round_trip(&Option::<String>::None), None);

   assert_eq!(round_trip(&()), ());
}

#[test]
fn test_containers_round_trip() {
   assert_eq!(round_trip(&[1u8, 2, 3]), [1u8, 2, 3]);
   assert_eq!(round_trip(&(1u8, 2u16, 3u32)), (1u8, 2u16, 3u32));
   assert_eq!(round_trip(&Vec::<u8>::new()), Vec::<u8>::new());
   assert_eq!(round_trip(&vec![5u16, 6, 7]), vec![5u16, 6, 7]);

   let mut map = BTreeMap::new();
   map.insert("a".to_owned(), 1u8);
   map.insert("b".to_owned(), 2u8);
   assert_eq!(round_trip(&map), map);
}

/// The secure types deserialize into themselves: the borrowed string or byte
/// slice is copied into locked memory and then dropped.
#[test]
fn test_secure_types_round_trip() {
   let decoded = round_trip(&SecureString::from("hunter2"));
   decoded.unlock_str(|value| assert_eq!(value, "hunter2"));

   let decoded = round_trip(&SecureVec::from_slice(&[1u8, 2, 3]).unwrap());
   decoded.unlock_slice(|value| assert_eq!(value, &[1, 2, 3]));

   let decoded = round_trip(&SecureArray::<u8, 32>::from_slice(&[0xAB; 32]).unwrap());
   decoded.unlock(|value| assert_eq!(value, &[0xAB; 32]));
}

#[test]
fn test_struct_and_enum_round_trip() {
   assert_eq!(round_trip(&fixture()), fixture());

   assert_eq!(round_trip(&Kind::Empty), Kind::Empty);
   assert_eq!(round_trip(&Kind::One(3)), Kind::One(3));
   assert_eq!(round_trip(&Kind::Two(3, 4)), Kind::Two(3, 4));
   assert_eq!(
      round_trip(&Kind::Named { a: 5 }),
      Kind::Named { a: 5 }
   );
}

#[test]
fn test_unknown_struct_fields_are_skipped() {
   let decoded: Narrow = reencode_as(&Wide {
      a: 1,
      b: vec![0xFF; 64],
      c: 3,
   });

   assert_eq!(decoded, Narrow { a: 1, c: 3 });
}

#[test]
fn test_missing_fields_take_their_default() {
   let decoded: TargetWithMiddle = reencode_as(&SourceNoMiddle { first: 1, last: 2 });

   assert_eq!(
      decoded,
      TargetWithMiddle {
         first: 1,
         middle: 0,
         last: 2,
      }
   );
}

#[test]
fn test_both_sides_agree_the_format_is_not_human_readable() {
   assert_eq!(
      round_trip(&BranchesOnReadability(7)),
      BranchesOnReadability(7)
   );
}

#[test]
fn test_truncation_and_header_errors() {
   assert!(matches!(
      secure_types::decode_slice::<u8>(&[]),
      Err(DecodeError::UnexpectedEnd)
   ));

   // A short input cannot satisfy a declared count.
   assert!(matches!(
      secure_types::decode_slice::<Vec<u8>>(&[FORMAT_VERSION, 0xC8, 0x01]),
      Err(DecodeError::InvalidLength)
   ));

   // A wrong version byte is refused rather than guessed at.
   assert!(matches!(
      secure_types::decode_slice::<u8>(&[0x02, 0x01]),
      Err(DecodeError::UnsupportedVersion(2))
   ));

   // Bytes left over mean the reader and writer disagree about the layout.
   assert!(matches!(
      secure_types::decode_slice::<u8>(&[FORMAT_VERSION, 0x01, 0xFF]),
      Err(DecodeError::TrailingBytes { extra: 1 })
   ));
}

#[test]
fn test_invalid_encodings_are_rejected() {
   assert!(matches!(
      secure_types::decode_slice::<bool>(&[FORMAT_VERSION, 0x02]),
      Err(DecodeError::InvalidBool)
   ));

   assert!(matches!(
      secure_types::decode_slice::<Option<u8>>(&[FORMAT_VERSION, 0x02]),
      Err(DecodeError::InvalidOptionTag)
   ));

   // A surrogate is not a Unicode scalar value.
   assert!(matches!(
      secure_types::decode_slice::<char>(&[FORMAT_VERSION, 0x00, 0xD8, 0x00, 0x00]),
      Err(DecodeError::InvalidChar)
   ));

   // 0xFF 0xFE is not valid UTF-8.
   assert!(matches!(
      secure_types::decode_slice::<String>(&[FORMAT_VERSION, 0x02, 0xFF, 0xFE]),
      Err(DecodeError::InvalidUtf8)
   ));
}

/// A field body that does not fill its frame means the writer and reader
/// disagree about the field's type, so it is rejected rather than accepted
/// with a silently shifted cursor.
#[test]
fn test_a_field_body_that_does_not_fill_its_frame_is_rejected() {
   let document = [
      FORMAT_VERSION,
      0x01, // one field
      0x01,
      b'a', // name "a"
      0x02,
      0x00,
      0x00,
      0x00, // frame says two bytes
      0x07,
      0x00, // but a `u8` only consumes one
   ];

   assert!(matches!(
      secure_types::decode_slice::<OneField>(&document),
      Err(DecodeError::FrameMismatch { unconsumed: 1 })
   ));
}

/// Skipping a value whose extent is unknown is impossible, so it is refused
/// instead of guessing.
#[test]
fn test_ignored_any_outside_a_struct_field_is_unsupported() {
   assert!(matches!(
      secure_types::decode_slice::<de::IgnoredAny>(&[FORMAT_VERSION, 0x07]),
      Err(DecodeError::Unsupported(_))
   ));
}

/// Nothing here may panic: a corrupt document is an error, and the count guard
/// keeps a corrupt length from pre-allocating or looping without bound.
#[test]
fn test_every_truncation_and_bit_flip_is_an_error_not_a_panic() {
   let encoded = encode(&fixture());

   encoded.unlock_slice(|bytes| {
      let original = bytes.to_vec();
      assert!(secure_types::decode_slice::<Fixture>(&original).is_ok());

      for len in 0..original.len() {
         assert!(
            secure_types::decode_slice::<Fixture>(&original[..len]).is_err(),
            "a {len}-byte prefix decoded successfully"
         );
      }

      for index in 0..original.len() {
         for bit in 0..8 {
            let mut mutated = original.clone();
            mutated[index] ^= 1 << bit;

            // Either an error or a different value, but never a panic.
            let _ = secure_types::decode_slice::<Fixture>(&mutated);
         }
      }
   });
}

#[test]
fn test_error_messages_never_echo_wire_bytes() {
   // A distinctive secret in the payload, then a decode that fails inside the
   // same document.
   let document = [
      FORMAT_VERSION,
      0x02,
      // field "label" holding the secret
      0x05,
      b'l',
      b'a',
      b'b',
      b'e',
      b'l',
      0x0B,
      0x00,
      0x00,
      0x00,
      b'S',
      b'E',
      b'C',
      b'R',
      b'E',
      b'T',
      b'-',
      b'M',
      b'A',
      b'R',
      b'K',
      // field "a" whose frame is bogus, so decoding fails after the secret
      0x01,
      b'a',
      0x02,
      0x00,
      0x00,
      0x00,
      0x07,
   ];

   let error = secure_types::decode_slice::<OneField>(&document).unwrap_err();
   let rendered = error.to_string();
   let debugged = format!("{error:?}");

   for form in [&rendered, &debugged] {
      assert!(
         !form.contains("SECRET-MARK"),
         "an error echoed payload bytes: {form}"
      );
   }
}

#[test]
fn test_unsupported_any_is_reported() {
   // `deserialize_any` is what a self-describing format would provide.
   struct WantsAny;

   impl<'de> Deserialize<'de> for WantsAny {
      fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
      where
         D: de::Deserializer<'de>,
      {
         deserializer
            .deserialize_any(de::IgnoredAny)
            .map(|_| WantsAny)
      }
   }

   assert!(matches!(
      secure_types::decode_slice::<WantsAny>(&[FORMAT_VERSION, 0x07]),
      Err(DecodeError::Unsupported(_))
   ));
}

/// Encodes `value` and decodes it straight back.
fn round_trip<T>(value: &T) -> T
where
   T: Serialize + DeserializeOwned,
{
   encode(value)
      .unlock_slice(|bytes| secure_types::decode_slice::<T>(bytes).expect("round trip failed"))
}

/// Encodes as `T` would and decodes the result as `U` would.
fn reencode_as<T, U>(value: &T) -> U
where
   T: ?Sized + Serialize,
   U: DeserializeOwned,
{
   encode(value)
      .unlock_slice(|bytes| secure_types::decode_slice::<U>(bytes).expect("re-encode failed"))
}

fn encode<T>(value: &T) -> SecureBytes
where
   T: ?Sized + Serialize,
{
   secure_types::encode(value).unwrap()
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Inner {
   label: String,
   key: Vec<u8>,
   shifted: u16,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
struct Fixture {
   id: u64,
   flag: bool,
   name: String,
   inner: Inner,
   items: Vec<u32>,
   maybe: Option<u8>,
   kind: Kind,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
enum Kind {
   Empty,
   One(u8),
   Two(u8, u8),
   Named { a: u8 },
}

fn fixture() -> Fixture {
   Fixture {
      id: 0xDEAD_BEEF_CAFE_F00D,
      flag: true,
      name: "vault".to_owned(),
      inner: Inner {
         label: "seed".to_owned(),
         key: vec![0xAB; 32],
         shifted: 4096,
      },
      items: vec![1, 2, 3, u32::MAX],
      maybe: Some(9),
      kind: Kind::Named { a: 7 },
   }
}

/// A field the reader does not know is skipped through its length frame,
/// which is what makes adding a field a compatible change.
#[derive(Serialize)]
struct Wide {
   a: u8,
   b: Vec<u8>,
   c: u8,
}

#[derive(Debug, PartialEq, Deserialize)]
struct Narrow {
   a: u8,
   c: u8,
}

/// The other half of the same property: a field the *writer* omitted takes its
/// `#[serde(default)]`. A positional encoding could not express this — it
/// would have handed `last`'s value to `middle`.
#[derive(Serialize)]
struct SourceNoMiddle {
   first: u8,
   last: u8,
}

#[derive(Debug, PartialEq, Deserialize)]
struct TargetWithMiddle {
   first: u8,
   #[serde(default)]
   middle: u8,
   last: u8,
}

/// The encoder and decoder must agree on `is_human_readable`, or a type that
/// picks its representation from it writes one form and expects the other.
#[derive(Debug, PartialEq)]
struct BranchesOnReadability(u8);

impl Serialize for BranchesOnReadability {
   fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
   where
      S: serde::Serializer,
   {
      if serializer.is_human_readable() {
         serializer.serialize_str("textual")
      } else {
         serializer.serialize_u8(self.0)
      }
   }
}

impl<'de> Deserialize<'de> for BranchesOnReadability {
   fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
   where
      D: de::Deserializer<'de>,
   {
      if deserializer.is_human_readable() {
         return Err(de::Error::custom(
            "expected the compact representation",
         ));
      }

      u8::deserialize(deserializer).map(BranchesOnReadability)
   }
}

#[derive(Debug, PartialEq, Deserialize)]
struct OneField {
   a: u8,
}
