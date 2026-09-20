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
//! builds every error from a length, an index or a `&'static str`. The one
//! message an impl can influence is discarded rather than rendered in both
//! directions — serde's own `unknown_variant` / `unknown_field` helpers format
//! the offending name into it, and a hand-written `Serialize` impl can format
//! payload into it. Errors are then safe to log, and a test pins that.
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
//! # Where the document ends up
//!
//! [`encode`] and [`encode_with_capacity`] write into a [`SecureBytes`]: locked
//! while unused, zeroized on drop, and with the previous allocation wiped on
//! growth. [`encode_to_vec`] and [`encode_into_vec`] write into an ordinary
//! `Vec<u8>` the caller owns — for callers that keep the document in one anyway,
//! such as a codec tag to prefix it with or an API that only takes `Vec<u8>`,
//! and would otherwise allocate a [`SecureBytes`] just to copy out of it. Both
//! go through the same serializer, and every scratch buffer it needs internally
//! is a [`SecureBytes`], so this only decides where the *result* lives.
//!
//! Note that the reader takes a plain `&[u8]` ([`decode_slice`]), so a document
//! produced into a `Vec` decodes without being copied back into locked memory
//! first.
//!
//! [`encoded_len`] reports how many bytes a document would take, measured by the
//! same serializer, so a destination can be sized exactly and never grow — which
//! is what keeps a partially written document out of a freed `Vec` allocation.
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

mod buffer;
mod decoder;
mod encoder;
mod format;

#[cfg(not(feature = "use_os"))]
use alloc::vec::Vec;

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

/// Encodes `value` into `buffer`, appending it after whatever `buffer` already
/// holds.
///
/// For callers that keep the document in an ordinary `Vec<u8>` anyway: a codec
/// tag (or anything else) can be written first and the document appended
/// straight after it, with no [`SecureBytes`] allocated and nothing copied
/// twice. See [`encode_to_vec`] for the same thing into a fresh buffer.
///
/// # Errors
///
/// Same as [`encode`]. A failure to allocate `buffer` itself is not one of
/// them — `Vec` aborts on allocation failure rather than reporting it.
///
/// # Security
///
/// `buffer` is a plain `Vec<u8>`: it is not locked while unused, and neither
/// dropping it nor growing it wipes anything. Growing in particular can leave a
/// copy of the partial document in freed memory, because `Vec` reallocates
/// without wiping — reserve enough capacity up front where that matters. The
/// scratch buffers the encoder uses internally stay [`SecureBytes`]. Use
/// [`encode`] when the document itself should live in locked, zeroizing memory.
///
/// A failed encoding erases what it appended and leaves `buffer` at its previous
/// length, so nothing partial survives in a buffer this crate cannot wipe.
pub fn encode_into_vec<T>(buffer: &mut Vec<u8>, value: &T) -> Result<(), EncodeError>
where
   T: ?Sized + Serialize,
{
   encoder::encode_into(buffer, value)
}

/// Encodes `value` into a fresh `Vec<u8>`.
///
/// Same as [`encode`], except the document is not held in locked memory. Prefer
/// [`encode_to_vec_with_capacity`] when the payload size is known: a `Vec` does
/// not wipe the allocation it grows out of, so sizing it up front avoids leaving
/// a copy of the partial document on the heap.
///
/// # Errors
///
/// Same as [`encode`]. A failure to allocate the returned buffer is not one of
/// them — `Vec` aborts on allocation failure rather than reporting it.
pub fn encode_to_vec<T>(value: &T) -> Result<Vec<u8>, EncodeError>
where
   T: ?Sized + Serialize,
{
   encode_to_vec_with_capacity(value, DEFAULT_CAPACITY)
}

/// Same as [`encode_to_vec`], with an explicit initial buffer size.
///
/// # Errors
///
/// Same as [`encode_to_vec`].
pub fn encode_to_vec_with_capacity<T>(value: &T, capacity: usize) -> Result<Vec<u8>, EncodeError>
where
   T: ?Sized + Serialize,
{
   let mut buffer = Vec::with_capacity(capacity);

   encoder::encode_into(&mut buffer, value)?;

   Ok(buffer)
}

/// The number of bytes [`encode`] / [`encode_into_vec`] would write for `value`,
/// version byte included.
///
/// Measured, not estimated: `value` is serialized once into a sink that only
/// counts, through the same [`serde::Serializer`] that produces a document, so
/// the answer cannot drift from the wire format. Nothing is allocated and no
/// memory is locked; the cost is one extra pass over `value`.
///
/// This is for sizing a destination so that it never has to grow. Growth is not
/// free for a plain `Vec`: reallocating leaves a copy of the partial document in
/// the allocation it walks away from, and nothing wipes that. Sizing with this
/// length and then calling [`encode_into_vec`] keeps the buffer in place:
///
/// ```
/// use secure_types::{encode_into_vec, encoded_len};
///
/// // A codec tag ahead of the document, the way a caller storing the payload
/// // in its own envelope would write it.
/// let mut payload = vec![0x07u8];
/// payload.reserve(encoded_len(&"hunter2")?);
/// encode_into_vec(&mut payload, &"hunter2")?;
///
/// assert_eq!(payload.len(), 1 + encoded_len(&"hunter2")?);
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
///
/// # Errors
///
/// The same errors as [`encode`], because this is the same serialization: a
/// value that cannot be encoded has no length. A `Serialize` impl that wrote a
/// different number of bytes on each call would make this a hint rather than a
/// promise, which is all a buffer capacity needs.
pub fn encoded_len<T>(value: &T) -> Result<usize, EncodeError>
where
   T: ?Sized + Serialize,
{
   let mut counter = buffer::Counter::new();
   encoder::encode_into(&mut counter, value)?;

   Ok(counter.count())
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
