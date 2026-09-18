//! An [`std::io::Write`] adapter that appends into locked, zeroizing memory.

use std::io::{self, Write};

use crate::SecureBytes;

/// An [`io::Write`] that appends everything written to it into a [`SecureBytes`].
///
/// Handing a secret to `serde_json::to_string`/`to_vec` leaves the plaintext in an
/// ordinary `String`/`Vec` that nothing zeroizes, and `impl Serialize` cannot wipe
/// that buffer for you — a `Serialize` impl only ever sees a generic
/// [`serde::Serializer`]. Building the serializer around this writer instead keeps the
/// only heap copy of the plaintext in memory that is locked while unused and zeroized
/// on drop. Growth cannot leave a stale copy behind either: `SecureVec::reserve`
/// zeroizes the old allocation after moving the elements.
///
/// # Example
///
/// ```
/// use secure_types::{SecureBytes, SecureBytesWriter};
/// use std::io::Write;
///
/// let mut buffer = SecureBytes::new_with_capacity(32).unwrap();
/// write!(SecureBytesWriter::new(&mut buffer), "secret").unwrap();
///
/// buffer.unlock_slice(|bytes| assert_eq!(bytes, b"secret"));
/// ```
///
/// For JSON in particular, `serialize_json_into_secure_string` (feature `serde_json`)
/// wires this up for you.
///
/// This writer targets [`SecureBytes`]. If you want the result as a [`SecureString`]
/// (what `serialize_json_into_secure_string` returns), follow up with
/// [`SecureString::try_from`], which validates the UTF-8 in a single pass.
pub struct SecureBytesWriter<'a> {
   bytes: &'a mut SecureBytes,
}

impl<'a> SecureBytesWriter<'a> {
   /// Wraps `bytes`, which receives everything written to the returned writer.
   pub fn new(bytes: &'a mut SecureBytes) -> Self {
      Self { bytes }
   }
}

impl Write for SecureBytesWriter<'_> {
   fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
      self.bytes.extend_from_slice(buf);
      Ok(buf.len())
   }

   /// Appends in one go, where the default implementation would call [`write`]
   /// repeatedly and pay an `mprotect` pair per fragment.
   ///
   /// [`write`]: Write::write
   fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
      self.bytes.extend_from_slice(buf);
      Ok(())
   }

   fn flush(&mut self) -> io::Result<()> {
      // Nothing is buffered outside the `SecureBytes`.
      Ok(())
   }
}

#[cfg(test)]
mod tests {
   use super::*;

   #[test]
   fn test_writer_appends_to_secure_bytes() {
      let mut buffer = SecureBytes::new_with_capacity(8).unwrap();

      {
         let mut writer = SecureBytesWriter::new(&mut buffer);
         writer.write_all(b"hello ").unwrap();
         writer.write_all(b"world").unwrap();
         assert_eq!(writer.write(b"!").unwrap(), 1);
         writer.flush().unwrap();
      }

      buffer.unlock_slice(|bytes| assert_eq!(bytes, b"hello world!"));
   }

   #[test]
   fn test_writer_grows_without_losing_data() {
      let mut buffer = SecureBytes::new().unwrap();

      {
         let mut writer = SecureBytesWriter::new(&mut buffer);
         // Far beyond the initial capacity, so the buffer reallocates repeatedly.
         for _ in 0..64 {
            writer.write_all(&[0xAB; 32]).unwrap();
         }
      }

      buffer.unlock_slice(|bytes| {
         assert_eq!(bytes.len(), 64 * 32);
         assert!(bytes.iter().all(|byte| *byte == 0xAB));
      });
   }
}
