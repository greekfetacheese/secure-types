//! An [`std::io::Write`] adapter that appends into locked, zeroizing memory.

use std::io::{self, Write};

use crate::SecureBytes;

/// An [`io::Write`] that appends everything written to it into a [`SecureBytes`].
///
/// Handing a secret to `serde_json::to_string`/`to_vec` leaves the plaintext in an
/// ordinary `String`/`Vec` that nothing zeroizes, and `impl Serialize` cannot wipe
/// that buffer for you — a `Serialize` impl only ever sees a generic
/// `serde::Serializer`. Building the serializer around this writer instead keeps the
/// plaintext it hands over out of ordinary memory: the bytes it receives are written
/// straight into locked, zeroizing storage. Growth cannot leave a stale copy behind
/// either: `SecureVec::reserve` zeroizes the old allocation after moving the elements.
/// A serializer that materialises a plaintext copy before writing it is still its own
/// exposure.
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
/// This writer targets [`SecureBytes`]. If you want the result as a
/// [`SecureString`](crate::SecureString), follow up with `SecureString::try_from`,
/// which validates the UTF-8 in a single pass.
///
/// The `codec` feature's `encode` writes its own format into locked memory; this writer is
/// for pointing some *other* serializer at locked memory.
///
/// This writer is compiled only with the `use_os` feature, like the rest of the OS-backed
/// API.
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
      self
         .bytes
         .extend_from_slice(buf)
         .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
      Ok(buf.len())
   }

   /// Appends the whole buffer in one explicit `extend_from_slice`, exactly as
   /// [`write`] does. The default `io::Write::write_all` would also call `write`
   /// once here, because this `write` always accepts the whole buffer; the
   /// override just makes that one append explicit.
   ///
   /// [`write`]: Write::write
   fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
      self
         .bytes
         .extend_from_slice(buf)
         .map_err(|error| io::Error::new(io::ErrorKind::OutOfMemory, error))?;
      Ok(())
   }

   fn flush(&mut self) -> io::Result<()> {
      // Nothing is buffered outside the `SecureBytes`.
      Ok(())
   }
}
