//! A self-owned binary format for secrets, implemented as a
//! [`serde::Serializer`] and a [`serde::Deserializer`].
//!
//! # Why not JSON
//!
//! `serde_json` cannot be made to leave no traces, and the parts that leak are
//! out of our reach:
//!
//! - its `Deserializer` holds a private `scratch: Vec<u8>` that it reuses for
//!   every escaped string and never zeroizes;
//! - `from_reader` copies *every* string into that scratch, escaped or not;
//! - `Value` / `RawValue` deserialize the whole document into plain `String`s;
//! - serde's own error formatting renders `Unexpected::Str(value)` as
//!   `string "…the plaintext…"`, which is exactly what ends up in a log.
//!
//! None of those are serde's trait layer — they belong to `serde_json`. A
//! format we own has no scratch buffer, no escaping pass, no `Value`, and
//! builds every error from a length, an index or a `&'static str`. Errors are
//! then safe to log, and a test pins that.
//!
//! # Why serde traits instead of a new trait pair
//!
//! Because it costs nothing and gives away nothing. Writing a bespoke
//! `SecureSerialize` trait would mean shipping a `#[derive]` macro, which means
//! `syn`, `quote`, `proc-macro2` and a second `proc-macro = true` crate. Using
//! `serde::Serializer` / `serde::Deserializer` needs **no new dependency at
//! all** (serde is already optional here) and keeps the exact attribute surface:
//!
//! ```
//! use secure_types::{decode, encode};
//! use serde::{Deserialize, Serialize};
//!
//! #[derive(Serialize, Deserialize, Debug, PartialEq)]
//! struct VaultData {
//!    label: String,
//!
//!    /// AEAD key for the wallet state
//!    #[serde(default)]
//!    wallet_state_key: Option<u32>,
//!
//!    #[serde(default, skip_serializing)]
//!    contacts: Vec<String>,
//! }
//!
//! let vault = VaultData {
//!    label: "main".to_owned(),
//!    wallet_state_key: Some(7),
//!    contacts: vec!["not persisted".to_owned()],
//! };
//!
//! let encoded = encode(&vault)?;
//!
//! // The plaintext only ever existed in locked memory.
//! let decoded = decode::<VaultData>(&encoded)?;
//!
//! assert_eq!(decoded.wallet_state_key, Some(7));
//! assert!(decoded.contacts.is_empty()); // `skip_serializing` -> default
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! # What is not supported
//!
//! The format is not self-describing, so [`serde::Deserializer::deserialize_any`]
//! cannot be implemented. Anything that depends on it fails with
//! [`DecodeError::Unsupported`] rather than guessing:
//!
//! - `#[serde(flatten)]`
//! - `#[serde(untagged)]`
//! - `serde_json::Value`-shaped fields
//!
//! Note the asymmetry for untagged enums: an untagged variant *serializes*
//! successfully — writing one needs no type tag — and only fails on the way
//! back in. A successful [`encode`] is therefore not on its own a promise that
//! the value is decodable.
//!
//! [`serde::Deserializer::deserialize_ignored_any`] works in exactly one place:
//! the body of a struct field, which is the only position whose extent is known.
//! That is what makes "add a field with `#[serde(default)]`" a compatible
//! change, and it is why struct fields carry a length.
//!
//! # The wire format
//!
//! Integers are little-endian; lengths and counts are unsigned LEB128 varints.
//! [`FORMAT_VERSION`] is the first byte of every document.
//!
//! ```text
//! unit, unit_struct   := (no bytes)
//! bool                := 0x00 | 0x01
//! u8..u64 / i8..i64   := little-endian, fixed width
//! u128 / i128         := little-endian, 16 bytes
//! f32 / f64           := IEEE-754 bits, little-endian
//! char                := u32 LE Unicode scalar value
//! str                 := varint(len) || utf8 bytes
//! bytes               := varint(len) || bytes
//! none                := 0x00
//! some(v)             := 0x01 || v
//! seq / tuple /
//!   tuple_struct      := varint(count) || value * count
//! map                 := varint(count) || (key || value) * count
//! struct / struct_var := varint(count) || (str(field_name) ||
//!                                          u32_le(value_len) || value) * count
//! newtype_struct      := value
//! enum                := str(variant_name) || variant_payload
//! ```
//!
//! Struct fields and enum variants are tagged by *name* rather than by position
//! or index, so reordering or skipping one cannot silently reinterpret old data,
//! and the `u32` length around each field body is what lets a reader skip a
//! field it does not know.

mod decoder;
mod encoder;
mod format;

use crate::SecureBytes;

use serde::Serialize;
use serde::de::DeserializeOwned;

pub use format::{DecodeError, EncodeError, FORMAT_VERSION};

/// Initial buffer size used by [`encode`].
///
/// Matches the JSON helpers' `DEFAULT_JSON_CAPACITY`: large enough that a
/// typical payload does not grow at all, small enough not to lock pages for
/// nothing.
const DEFAULT_CAPACITY: usize = 1024;

/// Encodes `value` into a fresh locked buffer.
///
/// The returned [`SecureBytes`] holds the only copy of the encoded value: it is
/// locked while unused and zeroized on drop, and growth wipes the previous
/// allocation. Use [`encode_with_capacity`] when the payload size is known, so
/// the buffer does not have to be reallocated and re-locked.
///
/// # Errors
///
/// Returns [`EncodeError::Secure`] if the locked buffer cannot be allocated or
/// grown, [`EncodeError::LengthOverflow`] if a value does not fit its length
/// field, and [`EncodeError::ElementCountMismatch`] if a hand-written
/// `Serialize` impl writes a different number of elements than it declared.
///
/// # Example
///
/// ```
/// use secure_types::{decode, encode, SecureString};
///
/// let secret = SecureString::from("hunter2");
///
/// let encoded = encode(&secret)?;
/// let decoded = decode::<SecureString>(&encoded)?;
///
/// decoded.unlock_str(|value| assert_eq!(value, "hunter2"));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn encode<T>(value: &T) -> Result<SecureBytes, EncodeError>
where
   T: ?Sized + Serialize,
{
   encode_with_capacity(value, DEFAULT_CAPACITY)
}

/// Same as [`encode`], with an explicit initial buffer size.
///
/// Sizing the buffer to the expected payload avoids growing (and re-locking) it,
/// which keeps both the `mprotect` traffic and the `RLIMIT_MEMLOCK` pressure
/// predictable.
///
/// # Errors
///
/// Same as [`encode`].
pub fn encode_with_capacity<T>(value: &T, capacity: usize) -> Result<SecureBytes, EncodeError>
where
   T: ?Sized + Serialize,
{
   let mut buffer = SecureBytes::new_with_capacity(capacity).map_err(EncodeError::Secure)?;

   encoder::encode_into(&mut buffer, value)?;

   Ok(buffer)
}

/// Decodes `value` out of a locked buffer.
///
/// The buffer is unlocked only for the duration of the decode, and put back
/// under protection afterwards — including if the decode fails.
///
/// `T: DeserializeOwned` is load-bearing rather than decoration: it statically
/// forbids any type that would borrow out of the buffer, which is what keeps a
/// reference from surviving into the re-locked window.
///
/// # Errors
///
/// Returns [`DecodeError`] if the input is truncated or malformed, carries an
/// unsupported [`FORMAT_VERSION`], has trailing bytes, or does not match `T`.
///
/// # Example
///
/// ```
/// use secure_types::{decode, encode, SecureVec};
///
/// let key = SecureVec::from_slice(&[1u8, 2, 3])?;
///
/// let encoded = encode(&key)?;
/// let decoded = decode::<SecureVec<u8>>(&encoded)?;
///
/// decoded.unlock_slice(|value| assert_eq!(value, &[1, 2, 3]));
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub fn decode<T>(bytes: &SecureBytes) -> Result<T, DecodeError>
where
   T: DeserializeOwned,
{
   bytes.unlock_slice(|unlocked| decode_slice::<T>(unlocked))
}

/// Same as [`decode`], for a slice the caller already holds unlocked.
///
/// `bytes` must be the complete document: trailing bytes are an error, because a
/// document that decodes with bytes left over means the reader and the writer
/// disagree about the layout.
///
/// # Errors
///
/// Same as [`decode`].
pub fn decode_slice<T>(bytes: &[u8]) -> Result<T, DecodeError>
where
   T: DeserializeOwned,
{
   decoder::decode_from(bytes)
}

#[cfg(test)]
mod tests {
   use super::*;

   use crate::{SecureArray, SecureString, SecureVec};

   #[test]
   fn test_the_document_starts_with_the_format_version() {
      let encoded = encode(&7u8).unwrap();

      encoded.unlock_slice(|bytes| {
         assert_eq!(bytes, &[FORMAT_VERSION, 0x07]);
      });
   }

   #[test]
   fn test_scalars_round_trip_through_the_public_api() {
      let encoded = encode(&0xDEAD_BEEFu32).unwrap();

      encoded.unlock_slice(|bytes| {
         assert_eq!(bytes, &[FORMAT_VERSION, 0xEF, 0xBE, 0xAD, 0xDE]);
      });

      assert_eq!(decode::<u32>(&encoded).unwrap(), 0xDEAD_BEEF);
   }

   /// The point of the whole exercise: our own types go in and come back out
   /// through the locked buffer.
   #[test]
   fn test_secure_types_round_trip_through_the_public_api() {
      let secret = SecureString::from("hunter2");
      let encoded = encode(&secret).unwrap();
      decode::<SecureString>(&encoded)
         .unwrap()
         .unlock_str(|value| assert_eq!(value, "hunter2"));

      let key = SecureVec::from_slice(&[1u8, 2, 3]).unwrap();
      let encoded = encode(&key).unwrap();
      decode::<SecureVec<u8>>(&encoded)
         .unwrap()
         .unlock_slice(|value| assert_eq!(value, &[1, 2, 3]));

      let array = SecureArray::<u8, 32>::from_slice(&[0xAB; 32]).unwrap();
      let encoded = encode(&array).unwrap();
      decode::<SecureArray<u8, 32>>(&encoded)
         .unwrap()
         .unlock(|value| assert_eq!(value, &[0xAB; 32]));
   }

   #[test]
   fn test_capacity_changes_nothing_about_the_document() {
      let value = SecureString::from("hunter2");

      let default = encode(&value).unwrap();
      let sized = encode_with_capacity(&value, 4096).unwrap();

      default.unlock_slice(|left| {
         sized.unlock_slice(|right| assert_eq!(left, right));
      });
   }

   #[test]
   fn test_a_zero_capacity_still_works() {
      // `SecureVec::new_with_capacity(0)` bumps to 1 internally, so this must
      // grow rather than fail.
      let encoded = encode_with_capacity(&7u8, 0).unwrap();

      assert_eq!(decode::<u8>(&encoded).unwrap(), 7);
   }

   /// Decoding must leave the buffer usable and protected: the unlock window is
   /// closed again, and nothing about the document was consumed.
   #[test]
   fn test_the_buffer_survives_decoding() {
      let encoded = encode(&42u8).unwrap();

      assert_eq!(decode::<u8>(&encoded).unwrap(), 42);
      assert_eq!(decode::<u8>(&encoded).unwrap(), 42);

      encoded.unlock_slice(|bytes| assert_eq!(bytes, &[FORMAT_VERSION, 42]));
   }

   #[test]
   fn test_decode_slice_matches_decode() {
      let encoded = encode(&1234u32).unwrap();

      let from_slice = encoded.unlock_slice(|bytes| decode_slice::<u32>(bytes).unwrap());

      assert_eq!(from_slice, decode::<u32>(&encoded).unwrap());
   }

   #[test]
   fn test_errors_are_reported_from_a_locked_buffer_too() {
      // Version byte, then a one-field struct header with nothing after it.
      let mut buffer = SecureBytes::new_with_capacity(4).unwrap();
      buffer.push(FORMAT_VERSION);
      buffer.push(0x01);

      assert!(matches!(
         decode::<SecureString>(&buffer),
         Err(DecodeError::UnexpectedEnd)
      ));
   }

   #[test]
   fn test_header_errors_from_a_slice() {
      assert!(matches!(
         decode_slice::<u8>(&[]),
         Err(DecodeError::UnexpectedEnd)
      ));

      assert!(matches!(
         decode_slice::<u8>(&[0x02, 0x01]),
         Err(DecodeError::UnsupportedVersion(2))
      ));

      assert!(matches!(
         decode_slice::<u8>(&[FORMAT_VERSION, 0x01, 0xFF]),
         Err(DecodeError::TrailingBytes { extra: 1 })
      ));
   }
}
