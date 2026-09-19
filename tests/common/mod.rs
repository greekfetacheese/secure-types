//! Helpers shared by the integration test crates under `tests/`.
//!
//! Each file directly under `tests/` is compiled as its own crate, so anything more than
//! one of them needs lives here. Cargo does not treat a subdirectory as a test target, so
//! this module only ever exists as part of the crates that declare `mod common;`.
//!
//! Every crate uses only part of this module, hence the blanket `dead_code` allowance.

#![allow(dead_code)]

#[cfg(feature = "codec")]
use serde::Serialize;
#[cfg(feature = "codec")]
use serde::de::DeserializeOwned;

/// Encodes `value` into the codec's document form, version byte included.
#[cfg(feature = "codec")]
pub fn encoded_bytes<T>(value: &T) -> Vec<u8>
where
   T: ?Sized + Serialize,
{
   secure_types::encode(value)
      .expect("encode failed")
      .unlock_slice(<[u8]>::to_vec)
}

/// Decodes a whole codec document.
#[cfg(feature = "codec")]
pub fn decode_bytes<T>(bytes: &[u8]) -> Result<T, secure_types::DecodeError>
where
   T: DeserializeOwned,
{
   secure_types::decode_slice(bytes)
}

/// A minimal `Deserializer` that owns a `String` and yields it through `visit_string`.
///
/// `serde_json` never calls that method, so without this the "wipe the buffer the format
/// handed over" path in `SecureString`'s `Deserialize` impl would be untested.
#[cfg(feature = "serde")]
pub struct OwnedString(pub String);

/// The same for `visit_byte_buf`, which `SecureVec<u8>` and `SecureArray<u8, N>` wipe.
#[cfg(feature = "serde")]
pub struct OwnedBytes(pub Vec<u8>);

#[cfg(feature = "serde")]
impl<'de> serde::Deserializer<'de> for OwnedString {
   type Error = serde::de::value::Error;

   fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
   where
      V: serde::de::Visitor<'de>,
   {
      visitor.visit_string(self.0)
   }

   serde::forward_to_deserialize_any! {
      bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
      bytes byte_buf option unit unit_struct newtype_struct seq tuple
      tuple_struct map struct enum identifier ignored_any
   }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserializer<'de> for OwnedBytes {
   type Error = serde::de::value::Error;

   fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
   where
      V: serde::de::Visitor<'de>,
   {
      visitor.visit_byte_buf(self.0)
   }

   serde::forward_to_deserialize_any! {
      bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
      bytes byte_buf option unit unit_struct newtype_struct seq tuple
      tuple_struct map struct enum identifier ignored_any
   }
}
