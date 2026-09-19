//! Wire-format primitives: the format version, LEB128 varints, and the two
//! error types shared by the encoder and the decoder.

use core::fmt;

#[cfg(not(feature = "use_os"))]
use alloc::string::{String, ToString};

use zeroize::Zeroize;

use crate::{Error, SecureBytes};

/// Version byte written ahead of every encoded value.
///
/// Bump this whenever the wire layout changes in a way an older reader would
/// misinterpret. A reader that does not recognise the version refuses the input
/// rather than guessing at it, so a type change that keeps the same byte length
/// still needs a bump — the frame check in the decoder catches length changes,
/// not reinterpretation.
pub const FORMAT_VERSION: u8 = 1;

/// Maximum size of a LEB128 varint for a `usize`: 10 bytes covers 64 bits.
pub(crate) const MAX_VARINT_LEN: usize = 10;

/// Encodes `value` as an unsigned LEB128 varint and appends it to `buffer`.
///
/// The varint is assembled in a stack buffer and appended with a single
/// `extend_from_slice`, so one varint costs one unlock/lock cycle rather than
/// one per byte. The stack buffer is wiped before returning — the bytes also
/// live in the destination, which is locked and zeroized, so this copy would
/// otherwise be the only trace left behind.
pub(crate) fn write_varint(buffer: &mut SecureBytes, value: usize) -> Result<(), Error> {
   let mut scratch = [0u8; MAX_VARINT_LEN];

   let mut remaining = value;
   let mut len = 0;

   loop {
      let byte = (remaining & 0x7F) as u8;
      remaining >>= 7;

      if remaining == 0 {
         scratch[len] = byte;
         len += 1;
         break;
      }

      scratch[len] = byte | 0x80;
      len += 1;
   }

   let result = buffer.extend_from_slice(&scratch[..len]);
   scratch.zeroize();
   result
}

/// Decodes an unsigned LEB128 varint from `buf` starting at `*pos`.
///
/// Advances `*pos` past the varint on success. On error `*pos` is left at an
/// unspecified position, so callers must treat it as invalid.
///
/// # Errors
///
/// [`DecodeError::UnexpectedEnd`] if `buf` ends mid-varint, and
/// [`DecodeError::InvalidVarint`] if the encoding is longer than
/// [`MAX_VARINT_LEN`] or carries bits that cannot fit a `usize`.
pub(crate) fn read_varint(buf: &[u8], pos: &mut usize) -> Result<usize, DecodeError> {
   let mut result: u64 = 0;
   let mut shift: u32 = 0;
   let mut read: usize = 0;

   loop {
      let byte = match buf.get(*pos) {
         Some(byte) => *byte,
         None => return Err(DecodeError::UnexpectedEnd),
      };
      *pos += 1;
      read += 1;

      let chunk = u64::from(byte & 0x7F);

      // Shifting `chunk` up by `shift` must not drop bits: that is exactly what
      // an over-long or corrupt varint looks like. `u64::BITS` is checked first
      // so the shift itself can never overflow.
      if shift >= u64::BITS || (chunk << shift) >> shift != chunk {
         return Err(DecodeError::InvalidVarint);
      }
      result |= chunk << shift;

      if byte & 0x80 == 0 {
         break;
      }

      shift += 7;
      if read >= MAX_VARINT_LEN {
         return Err(DecodeError::InvalidVarint);
      }
   }

   usize::try_from(result).map_err(|_| DecodeError::InvalidVarint)
}

/// Why encoding a value into the binary format failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum EncodeError {
   /// The locked destination buffer could not be allocated or locked.
   Secure(Error),
   /// A length did not fit its wire representation, such as a struct field body
   /// longer than the `u32` frame that precedes it.
   LengthOverflow,
   /// A container's `Serialize` impl wrote a different number of elements than
   /// the length it declared to `serialize_seq` / `serialize_map` /
   /// `serialize_struct`.
   ///
   /// The count is written to the wire before the elements are, so a mismatch
   /// would leave a length prefix that lies about the payload. That is rejected
   /// here rather than turned into a buffer that decodes subtly wrong.
   ///
   /// `Serialize` impls derived by `serde` always declare the exact length;
   /// this catches hand-written ones.
   ElementCountMismatch,
   /// The value's `Serialize` impl asked for something the format cannot express.
   Unsupported(&'static str),
   /// The value's `Serialize` impl rejected the value.
   Custom(String),
}

impl fmt::Display for EncodeError {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      match self {
         Self::Secure(error) => write!(f, "Failed to allocate the secure buffer: {error}"),
         Self::LengthOverflow => write!(
            f,
            "Value is too large for the format's length field"
         ),
         Self::ElementCountMismatch => write!(
            f,
            "A container declared a different number of elements than it wrote"
         ),
         Self::Unsupported(what) => write!(f, "The binary codec does not support {what}"),
         Self::Custom(message) => write!(f, "Failed to encode the value: {message}"),
      }
   }
}

impl core::error::Error for EncodeError {
   fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
      match self {
         Self::Secure(error) => Some(error),
         Self::LengthOverflow
         | Self::ElementCountMismatch
         | Self::Unsupported(_)
         | Self::Custom(_) => None,
      }
   }
}

/// Why decoding a value from the binary format failed.
///
/// Every variant is built from a length, an index or a `&'static str`, so an
/// error never carries bytes from the input. Both `Display` and `Debug` are
/// therefore safe to log, unlike serde's `Unexpected::Str`, which renders the
/// plaintext it was handed.
#[derive(Debug)]
#[non_exhaustive]
pub enum DecodeError {
   /// The input ended before the value was complete.
   UnexpectedEnd,
   /// A length or count varint was malformed, or did not fit a `usize`.
   InvalidVarint,
   /// A length or element count exceeded what the remaining input can hold.
   InvalidLength,
   /// A string was not valid UTF-8.
   InvalidUtf8,
   /// A `bool` tag was neither `0x00` nor `0x01`.
   ///
   /// The offending tag is deliberately not carried: keeping every variant free
   /// of input bytes is what makes an error unconditionally safe to log.
   InvalidBool,
   /// An `Option` tag was neither `0x00` nor `0x01`.
   InvalidOptionTag,
   /// A `char` was not a Unicode scalar value.
   InvalidChar,
   /// The input carries a format version this build does not understand.
   UnsupportedVersion(u8),
   /// Bytes remained after the top-level value was decoded.
   TrailingBytes {
      /// Number of unconsumed bytes.
      extra: usize,
   },
   /// A length-framed value did not consume exactly its frame.
   FrameMismatch {
      /// Bytes the value left unconsumed inside its frame.
      unconsumed: usize,
   },
   /// The value needs a serde feature the format does not support:
   /// `deserialize_any` (and therefore `#[serde(flatten)]`, `#[serde(untagged)]`
   /// and `Value`-shaped fields), or `deserialize_ignored_any` outside a struct
   /// field body.
   Unsupported(&'static str),
   /// The value's `Deserialize` impl rejected the decoded value, or drove the
   /// codec incorrectly — asking for a map value before a key, for instance.
   ///
   /// Only reachable from a `Deserialize` impl. The codec's own paths never
   /// build one, and never format input bytes into one either.
   Custom(String),
}

impl fmt::Display for DecodeError {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      match self {
         Self::UnexpectedEnd => write!(f, "Input ended before the value was complete"),
         Self::InvalidVarint => write!(f, "Invalid length prefix"),
         Self::InvalidLength => write!(f, "Length prefix exceeds the remaining input"),
         Self::InvalidUtf8 => write!(f, "Bytes are not valid UTF-8"),
         Self::InvalidBool => write!(f, "Invalid bool tag"),
         Self::InvalidOptionTag => write!(f, "Invalid Option tag"),
         Self::InvalidChar => write!(f, "Value is not a Unicode scalar value"),
         Self::UnsupportedVersion(version) => {
            write!(f, "Unsupported format version: {version}")
         }
         Self::TrailingBytes { extra } => {
            write!(f, "{extra} bytes remained after the value")
         }
         Self::FrameMismatch { unconsumed } => {
            write!(
               f,
               "Value left {unconsumed} bytes unconsumed inside its frame"
            )
         }
         Self::Unsupported(what) => write!(f, "The binary codec does not support {what}"),
         Self::Custom(message) => write!(f, "Failed to decode the value: {message}"),
      }
   }
}

impl core::error::Error for DecodeError {}

impl serde::ser::Error for EncodeError {
   fn custom<T: fmt::Display>(msg: T) -> Self {
      Self::Custom(msg.to_string())
   }
}

impl serde::de::Error for DecodeError {
   fn custom<T: fmt::Display>(msg: T) -> Self {
      Self::Custom(msg.to_string())
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   /// Encodes `value` into a fresh locked buffer of exactly the varint size.
   fn varint_bytes(value: usize) -> SecureBytes {
      let mut buffer = SecureBytes::new_with_capacity(MAX_VARINT_LEN).unwrap();
      write_varint(&mut buffer, value).unwrap();
      buffer
   }

   #[test]
   fn test_varint_appends_without_clobbering() {
      let mut buffer = SecureBytes::new_with_capacity(16).unwrap();
      buffer.extend_from_slice(b"ab").unwrap();
      write_varint(&mut buffer, 300).unwrap();

      buffer.unlock_slice(|bytes| assert_eq!(bytes, [b'a', b'b', 0xAC, 0x02]));
   }

   #[test]
   fn test_varint_round_trip() {
      let values = [
         0usize,
         1,
         127,
         128,
         300,
         u16::MAX.into(),
         u32::MAX as usize,
         usize::MAX,
      ];

      for value in values {
         let buffer = varint_bytes(value);

         buffer.unlock_slice(|bytes| {
            let mut pos = 0;
            assert_eq!(
               read_varint(bytes, &mut pos).unwrap(),
               value,
               "value {value}"
            );
            assert_eq!(
               pos,
               bytes.len(),
               "value {value} consumed the whole varint"
            );
         });
      }
   }

   #[test]
   fn test_read_varint_rejects_truncated() {
      let mut pos = 0;
      assert!(matches!(
         read_varint(&[], &mut pos),
         Err(DecodeError::UnexpectedEnd)
      ));

      // A continuation bit with nothing after it.
      let mut pos = 0;
      assert!(matches!(
         read_varint(&[0x80], &mut pos),
         Err(DecodeError::UnexpectedEnd)
      ));
   }

   #[test]
   fn test_read_varint_rejects_overlong() {
      // All continuation bits set: it never terminates inside the allowed width,
      // and the tenth group would silently lose bits.
      let mut pos = 0;
      assert!(matches!(
         read_varint(&[0xFF; MAX_VARINT_LEN + 1], &mut pos),
         Err(DecodeError::InvalidVarint)
      ));

      let mut pos = 0;
      assert!(matches!(
         read_varint(&[0xFF; MAX_VARINT_LEN], &mut pos),
         Err(DecodeError::InvalidVarint)
      ));
   }

   #[test]
   fn test_read_varint_accepts_usize_max_encoding() {
      // The canonical 10-byte encoding of `u64::MAX` / `usize::MAX` on 64-bit.
      let encoded = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01];
      let mut pos = 0;
      assert_eq!(
         read_varint(&encoded, &mut pos).unwrap(),
         usize::MAX
      );
      assert_eq!(pos, encoded.len());
   }

   #[test]
   fn test_varint_zero_is_a_single_byte() {
      varint_bytes(0).unlock_slice(|bytes| assert_eq!(bytes, [0x00]));
   }

   #[test]
   fn test_varint_is_minimal() {
      // 127 fits in one byte, 128 needs two, and 16383 fits in exactly two.
      varint_bytes(127).unlock_slice(|bytes| assert_eq!(bytes.len(), 1));
      varint_bytes(128).unlock_slice(|bytes| assert_eq!(bytes.len(), 2));
      varint_bytes(16_383).unlock_slice(|bytes| assert_eq!(bytes.len(), 2));
      varint_bytes(16_384).unlock_slice(|bytes| assert_eq!(bytes.len(), 3));
   }
}
