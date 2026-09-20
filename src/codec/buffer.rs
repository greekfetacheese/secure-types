//! The destination the encoder appends its encoded document to.
//!
//! Both encoder entry points share one [`serde::Serializer`](super::encoder), so
//! the buffer it writes through is abstracted behind [`Buffer`]. The two
//! implementations differ in exactly the guarantee this crate exists for.

#[cfg(not(feature = "use_os"))]
use alloc::vec::Vec;

use zeroize::Zeroize;

use crate::{Error, SecureBytes};

/// The buffer an encoded document is appended to.
///
/// - [`SecureBytes`] locks its pages while unused, zeroizes on drop, and wipes
///   the previous allocation when it grows. [`encode`](crate::encode) and
///   [`encode_with_capacity`](crate::encode_with_capacity) write here.
/// - `Vec<u8>` does none of that. [`encode_into_vec`](crate::encode_into_vec)
///   writes here so a caller who is going to hold the document in an ordinary
///   buffer anyway — to prefix it with a codec tag, say, or to hand it to
///   something that only takes a `Vec<u8>` — does not have to allocate a
///   [`SecureBytes`] first and copy out of it.
///
/// The encoder keeps no scratch of this kind: everything it needs internally is a
/// [`SecureBytes`], so this choice only decides where the *result* lives.
pub(crate) trait Buffer {
   /// The number of bytes written so far.
   fn len(&self) -> usize;

   /// Appends `bytes` to the document.
   fn append(&mut self, bytes: &[u8]) -> Result<(), Error>;

   /// Overwrites `bytes` at `offset` without changing the length.
   ///
   /// # Panics
   ///
   /// Panics if `offset + bytes.len()` exceeds the current length. The encoder
   /// only ever patches the `u32` length frame it wrote itself, so this is a
   /// broken-invariant check rather than a reachable runtime error.
   fn patch_at(&mut self, offset: usize, bytes: &[u8]);

   /// Erases everything written after the first `len` bytes, restoring the sink
   /// to what it held before an encoding started.
   ///
   /// A failed encoding stops wherever it stopped, and the sink would otherwise
   /// keep a partial document — plaintext that nothing wipes. Each sink says for
   /// itself what erasing costs: [`SecureBytes`] is zeroized on drop already, so
   /// it has nothing to do here.
   fn rollback(&mut self, len: usize);
}

impl Buffer for SecureBytes {
   fn len(&self) -> usize {
      SecureBytes::len(self)
   }

   fn append(&mut self, bytes: &[u8]) -> Result<(), Error> {
      self.extend_from_slice(bytes)
   }

   fn patch_at(&mut self, offset: usize, bytes: &[u8]) {
      SecureBytes::patch_at(self, offset, bytes);
   }

   fn rollback(&mut self, _len: usize) {
      // Nothing to do. The only buffers the encoder is handed are allocated by
      // `encode` / `encode_with_capacity` for this one call, and both drop them
      // — which zeroizes the whole document — on the error path.
   }
}

impl Buffer for Vec<u8> {
   fn len(&self) -> usize {
      Vec::len(self)
   }

   fn append(&mut self, bytes: &[u8]) -> Result<(), Error> {
      self.extend_from_slice(bytes);
      Ok(())
   }

   fn patch_at(&mut self, offset: usize, bytes: &[u8]) {
      let end = offset
         .checked_add(bytes.len())
         .expect("Vec::patch_at: offset overflow");
      assert!(
         end <= self.len(),
         "Vec::patch_at: range {offset}..{end} exceeds length {}",
         self.len()
      );

      self[offset..end].copy_from_slice(bytes);
   }

   fn rollback(&mut self, len: usize) {
      // Wipe before truncating: `truncate` only forgets the bytes, it does not
      // erase them from the allocation, and this is the sink nothing else wipes.
      self[len..].zeroize();
      self.truncate(len);
   }
}

/// A sink that stores nothing and only measures.
///
/// The encoder writes through [`Buffer`], so a document's length is measured by
/// the *same* serializer that produces it: every byte the encoder would append
/// passes through [`append`](Buffer::append). That is what makes
/// [`encoded_len`](crate::encoded_len) exact instead of an estimate of a rule
/// re-derived outside this crate — including for the values whose size is only
/// known at the end (`collect_str`, and the sequences and maps whose length was
/// not declared up front).
pub(crate) struct Counter {
   len: usize,
}

impl Counter {
   pub(crate) fn new() -> Self {
      Self { len: 0 }
   }

   /// The number of bytes the encoder appended.
   pub(crate) fn count(&self) -> usize {
      self.len
   }
}

impl Buffer for Counter {
   fn len(&self) -> usize {
      self.len
   }

   fn append(&mut self, bytes: &[u8]) -> Result<(), Error> {
      self.len += bytes.len();
      Ok(())
   }

   /// Patching the `u32` length frame overwrites bytes that were already
   /// counted, so it cannot change the length.
   fn patch_at(&mut self, offset: usize, bytes: &[u8]) {
      debug_assert!(
         offset + bytes.len() <= self.len,
         "Counter::patch_at: range {offset}..{} exceeds length {}",
         offset + bytes.len(),
         self.len
      );
   }

   /// Discards everything written after the first `len` bytes — what
   /// `encode_into` calls when an encoding fails partway.
   fn rollback(&mut self, len: usize) {
      self.len = len;
   }
}
