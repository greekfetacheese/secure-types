use super::{
   Error,
   vec::{SecureVec, UnlockGuard},
};
use core::ops::Range;
use zeroize::Zeroize;
#[cfg(feature = "serde")]
use zeroize::Zeroizing;

// `String` is only used by the serde visitor below; in a `no_std` build it has to come
// from `alloc` (with `use_os` the prelude provides it).
#[cfg(all(feature = "serde", not(feature = "use_os")))]
use alloc::{string::String, vec::Vec};

/// A securely allocated, growable UTF-8 string, just like `std::string::String`.
///
/// It is a wrapper around [`SecureVec<u8>`](SecureVec) and inherits all of its security guarantees.
///
/// Access to the string contents is provided through scoped methods like `unlock_str`,
/// which ensure the memory is only unlocked for the briefest possible time.
///
/// # Thread Safety
///
/// Same as [`SecureVec`]: `Send` but not `Sync`. Share as `Arc<Mutex<SecureString>>`.
///
/// # Notes
///
/// If you return a new allocated `String` from one of the unlock methods you are responsible for zeroizing the memory.
///
/// # Example
///
/// ```
/// use secure_types::{SecureString, Zeroize};
///
/// // Create a SecureString
/// let mut secret = SecureString::from("my_super_secret");
///
/// // The memory is locked here
///
/// // Safely append more data.
/// secret.push_str("_password");
///
/// // The memory is locked here.
///
/// // Use a scope to safely access the content as a &str.
/// secret.unlock_str(|exposed_str| {
///     assert_eq!(exposed_str, "my_super_secret_password");
/// });
///
/// // Not recommended but if you allocate a new String make sure to zeroize it
/// let mut exposed = secret.unlock_str(|exposed_str| {
///     String::from(exposed_str)
/// });
///
/// // Do what you need to to do with the new string
/// // When you are done with it, zeroize it
/// exposed.zeroize();
///
/// // When `secret` is dropped, its data zeroized.
/// ```
#[derive(Clone)]
pub struct SecureString {
   vec: SecureVec<u8>,
}

impl SecureString {
   pub fn new() -> Result<Self, Error> {
      let vec = SecureVec::new()?;
      Ok(SecureString { vec })
   }

   pub fn new_with_capacity(capacity: usize) -> Result<Self, Error> {
      let vec = SecureVec::new_with_capacity(capacity)?;
      Ok(SecureString { vec })
   }

   /// Creates a `SecureString` from a `SecureVec<u8>` without checking UTF-8.
   ///
   /// # Safety
   ///
   /// The caller must guarantee `vec` holds valid UTF-8. Violating that is undefined
   /// behaviour, not only a panic: [`unlock_str`](Self::unlock_str) and
   /// [`char_len`](Self::char_len) do reject the bytes, but
   /// [`unlock_str_unchecked`](Self::unlock_str_unchecked) and
   /// [`char_len_unchecked`](Self::char_len_unchecked) are safe functions that hand
   /// them straight to `str::from_utf8_unchecked`, and so does the safe
   /// [`delete_text_char_range`](Self::delete_text_char_range).
   pub unsafe fn from_utf8_unchecked(vec: SecureVec<u8>) -> SecureString {
      SecureString { vec }
   }

   pub fn erase(&mut self) {
      self.vec.erase();
   }

   /// Returns the length of the inner `SecureVec`
   ///
   /// If you want the character length use [`char_len`](Self::char_len)
   pub fn byte_len(&self) -> usize {
      self.vec.len()
   }

   pub fn is_empty(&self) -> bool {
      self.vec.is_empty()
   }

   /// Removes the specified byte range from the string.
   ///
   /// `range` is a **byte** range, not a character range: take it from `&str`
   /// byte offsets. For a character range use
   /// [`delete_text_char_range`](Self::delete_text_char_range).
   ///
   /// # Panics
   ///
   /// Panics if the range is not on UTF-8 char boundaries, or if its start is past
   /// its end.
   pub fn drain(&mut self, range: Range<usize>) {
      self.unlock_str(|s| {
         assert!(
            s.is_char_boundary(range.start) && s.is_char_boundary(range.end),
            "SecureString::drain: range {:?} does not lie on UTF-8 char boundaries",
            range
         );
      });
      let _d = self.vec.drain(range);
   }

   /// Returns the number of chars in the string
   ///
   /// This unlocks the string for the count, so it must not be called from inside
   /// another `unlock*` closure on the same string: the nested unlock would re-lock
   /// the pages while the outer closure is still reading them, which faults instead
   /// of returning. See [`unlock_str`](Self::unlock_str).
   ///
   /// # Panics
   /// Panics if the string is not valid UTF-8.
   pub fn char_len(&self) -> usize {
      self.unlock_str(|s| s.chars().count())
   }

   /// Returns the number of chars in the string without validating the bytes
   ///
   /// This is the unchecked counterpart of [`char_len`](Self::char_len): it skips
   /// the UTF-8 pass, which every safe constructor already guarantees. It is only
   /// sound on a string built by [`from_utf8_unchecked`](Self::from_utf8_unchecked)
   /// if that string really does hold valid UTF-8 — a safe function cannot check
   /// that for you, so keep the promise the `unsafe` constructor made.
   ///
   /// Like [`char_len`](Self::char_len), this unlocks the string and must not be
   /// called from inside another `unlock*` closure.
   pub fn char_len_unchecked(&self) -> usize {
      self.unlock_str_unchecked(|s| s.chars().count())
   }

   /// Push a `&str` into the `SecureString`
   ///
   /// # Panics
   ///
   /// Panics if the buffer has to grow and the new capacity overflows `usize` or the
   /// allocation fails — the contract of
   /// [`SecureVec::reserve`](crate::SecureVec::reserve), which this calls once for the
   /// whole `&str` before any byte is written. Growing first is what keeps the string
   /// valid: a reserve per byte would panic halfway through a multi-byte character and
   /// leave the buffer holding truncated UTF-8, which every later safe read rejects and
   /// the `_unchecked` readers would hand to `from_utf8_unchecked`.
   pub fn push_str(&mut self, string: &str) {
      let slice = string.as_bytes();

      // One reserve for the whole slice, so a growth failure happens before the first
      // byte is written: appending byte by byte would let it land in the middle of a
      // multi-byte character and leave the buffer holding invalid UTF-8, breaking the
      // invariant every reader relies on.
      self.vec.reserve(slice.len());

      for s in slice.iter() {
         self.vec.push(*s);
      }
   }

   /// Immutable access as `&str`
   ///
   /// It uses the `from_utf8` function to check the validity of the internal
   /// bytes. If the bytes are not valid UTF-8, the function panics.
   ///
   /// # Re-entrancy
   ///
   /// The closure must not call another `unlock*` method on this string, nor
   /// [`char_len`](Self::char_len), [`char_len_unchecked`](Self::char_len_unchecked) and
   /// `Clone`, which all unlock internally — [`byte_len`](Self::byte_len)
   /// does not unlock and is fine. The pages are unprotected once and re-protected
   /// when this call returns, so a nested unlock re-locks the memory while this
   /// closure is still reading it, and the read faults. Use the `&str` you were
   /// given instead, or measure before/after the call.
   ///
   /// Aborts with a diagnostic if the memory-protection call fails.
   pub fn unlock_str<F, R>(&self, f: F) -> R
   where
      F: FnOnce(&str) -> R,
   {
      self.vec.unlock_slice(|slice| {
         let str = core::str::from_utf8(slice)
            .expect("SecureString invariant violated: internal bytes are not valid UTF-8");
         f(str)
      })
   }

   /// Immutable access as `&str` without validating the bytes
   ///
   /// It uses `from_utf8_unchecked` to bypass the validity check. Every safe
   /// constructor keeps the contents valid UTF-8, so this is only a hazard for a
   /// string built by [`from_utf8_unchecked`](Self::from_utf8_unchecked) with bytes
   /// that are not valid UTF-8; keeping that promise is the caller's job.
   ///
   /// The re-entrancy rule of [`unlock_str`](Self::unlock_str) applies here too.
   ///
   /// Aborts with a diagnostic if the memory-protection call fails.
   pub fn unlock_str_unchecked<F, R>(&self, f: F) -> R
   where
      F: FnOnce(&str) -> R,
   {
      self.vec.unlock_slice(|slice| {
         // SAFETY: this is the `unchecked` variant — the caller promised the
         // internal bytes are valid UTF-8.
         let str = unsafe { core::str::from_utf8_unchecked(slice) };
         f(str)
      })
   }

   /// Mutable access to the `SecureString`
   ///
   /// This method does not unlock the memory.
   pub fn secure_mut<F, R>(&mut self, f: F) -> R
   where
      F: FnOnce(&mut SecureString) -> R,
   {
      f(self)
   }

   /// Inserts text at the given character index
   ///
   /// # Returns
   ///
   /// The number of characters inserted
   ///
   /// # Panics
   ///
   /// Panics if the buffer has to grow for the inserted text and the new capacity
   /// overflows `usize` or the allocation fails — the contract of
   /// [`SecureVec::reserve`](crate::SecureVec::reserve).
   ///
   /// # Example
   ///
   /// ```
   /// use secure_types::SecureString;
   ///
   /// let mut string = SecureString::from("GreekFeta");
   /// string.insert_text_at_char_idx(9, "Cheese");
   /// string.unlock_str(|str| {
   ///     assert_eq!(str, "GreekFetaCheese");
   /// });
   /// ```
   pub fn insert_text_at_char_idx(&mut self, char_idx: usize, text_to_insert: &str) -> usize {
      let chars_to_insert_count = text_to_insert.chars().count();
      if chars_to_insert_count == 0 {
         return 0;
      }

      let bytes_to_insert = text_to_insert.as_bytes();
      let insert_len = bytes_to_insert.len();

      // Get the byte index corresponding to the character index
      let byte_idx = self
         .vec
         .unlock_slice(|current_bytes| char_to_byte_idx(current_bytes, char_idx));

      self.vec.reserve(insert_len);

      let old_byte_len = self.vec.len();

      // Taken before the guard borrows the vector: raw pointers do not keep the
      // borrow alive, and the guard must stay alive while writing through it.
      let ptr = self.vec.as_mut_ptr();

      // Perform the insertion in-place. `UnlockGuard` re-locks the memory on
      // drop, including when the block unwinds.
      let new_byte_len = {
         let _guard = UnlockGuard::new(&self.vec);

         // SAFETY: the guard has unprotected `self.vec`'s live buffer for this
         // block. `reserve(insert_len)` above guaranteed room for
         // `old_byte_len + insert_len` bytes and `byte_idx <= old_byte_len`, so
         // both the shifted tail and the inserted span stay inside the
         // allocation. `ptr::copy` tolerates source/destination overlap; the
         // `copy_nonoverlapping` source is `text_to_insert`, a distinct `&str`.
         unsafe {
            // Shift the "tail" of the string (from the insertion point to the end)
            // to the right to make a gap for the new content.
            if byte_idx < old_byte_len {
               core::ptr::copy(
                  ptr.add(byte_idx),
                  ptr.add(byte_idx + insert_len),
                  old_byte_len - byte_idx,
               );
            }

            // Copy the new text into the newly created gap.
            core::ptr::copy_nonoverlapping(
               bytes_to_insert.as_ptr(),
               ptr.add(byte_idx),
               insert_len,
            );
         }

         old_byte_len + insert_len
      };

      // Committed after the guard re-locks: the guard holds a shared borrow of
      // `self.vec`, so the length cannot be written inside its scope. Nothing between
      // the mutation above and this line can unwind — a failed re-lock aborts — which is
      // what keeps a stale length off a half-shifted buffer.
      self.vec.len = new_byte_len;

      chars_to_insert_count
   }

   /// Deletes the text in the given **character** range.
   ///
   /// `char_range` is a char range, not a byte range — unlike
   /// [`drain`](Self::drain), which takes byte offsets.
   ///
   /// An out-of-range index is clamped to the string's character length rather than
   /// rejected: a range whose start is past the end is a no-op, and one whose end is
   /// past the end deletes through the end of the string. This matches the
   /// text-field behaviour the method was written for.
   ///
   /// # Example
   ///
   /// ```
   /// use secure_types::SecureString;
   ///
   /// let mut string = SecureString::from("GreekFetaCheese");
   /// string.delete_text_char_range(9..15);
   /// string.unlock_str(|str| {
   ///     assert_eq!(str, "GreekFeta");
   /// });
   /// ```
   pub fn delete_text_char_range(&mut self, char_range: core::ops::Range<usize>) {
      if char_range.start >= char_range.end {
         return;
      }

      let new_len = self.vec.unlock_slice_mut(|current_bytes| {
         // SAFETY: `SecureString` upholds the invariant that its bytes are valid
         // UTF-8 — every constructor but the `unsafe` `from_utf8_unchecked`
         // validates it. `current_bytes` is that buffer, unlocked by the guard.
         let current_text = unsafe { core::str::from_utf8_unchecked(current_bytes) };
         let byte_start = char_to_byte_idx(current_text.as_bytes(), char_range.start);
         let byte_end = char_to_byte_idx(current_text.as_bytes(), char_range.end);

         if byte_start >= byte_end || byte_end > current_bytes.len() {
            return current_bytes.len();
         }

         let remove_len = byte_end - byte_start;
         let old_total_len = current_bytes.len();

         // Shift elements left
         current_bytes.copy_within(byte_end..old_total_len, byte_start);

         let new_len = old_total_len - remove_len;
         // Zeroize the tail end that is now unused
         for byte in current_bytes[new_len..old_total_len].iter_mut() {
            byte.zeroize();
         }
         new_len
      });
      // Same shape as `insert_text_at_char_idx`: the mutation happens inside the
      // guard's scope, the length is committed after it. The shifted prefix is already
      // valid UTF-8 here, so even a stale length would only expose trailing zeros.
      self.vec.len = new_len;
   }
}

#[cfg(feature = "use_os")]
impl From<String> for SecureString {
   /// Creates a new `SecureString` from a `String`.
   ///
   /// The `String` is zeroized afterwards.
   ///
   /// # Panics
   /// Panics if the secure allocation cannot be made or locked — `From` cannot
   /// return an error. Use [`SecureVec::from_vec`] with
   /// [`SecureString::try_from`] for a fallible path.
   fn from(s: String) -> SecureString {
      let vec = SecureVec::from_vec(s.into_bytes()).unwrap();
      SecureString { vec }
   }
}

impl From<&str> for SecureString {
   /// Creates a new `SecureString` from a `&str`.
   ///
   /// The `&str` is not zeroized, you are responsible for zeroizing it.
   ///
   /// # Panics
   /// Panics if the secure allocation cannot be made or locked — `From` cannot
   /// return an error.
   fn from(s: &str) -> SecureString {
      let bytes = s.as_bytes();
      // new_with_capacity bumps 0 -> 1 internally, so empty &str is fine.
      let mut new_vec = SecureVec::new_with_capacity(bytes.len()).unwrap();
      new_vec.init_from_clone(bytes);
      SecureString { vec: new_vec }
   }
}

impl TryFrom<SecureVec<u8>> for SecureString {
   type Error = Error;

   /// Creates a `SecureString` from a `SecureVec<u8>`, validating UTF-8.
   ///
   /// The `SecureVec` is consumed. On invalid UTF-8 it is dropped (and thus
   /// zeroized) and `Error::InvalidUtf8` is returned.
   fn try_from(vec: SecureVec<u8>) -> Result<Self, Self::Error> {
      let valid = vec.unlock_slice(|slice| core::str::from_utf8(slice).is_ok());
      if valid {
         Ok(SecureString { vec })
      } else {
         Err(Error::InvalidUtf8)
      }
   }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SecureString {
   fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
   where
      S: serde::Serializer,
   {
      self.unlock_str(|str| serializer.serialize_str(str))
   }
}

/// Builds a SecureString from a borrowed UTF-8 string through the fallible
/// constructors, so a failed secure allocation is reported instead of unwinding
/// out of a Deserialize impl (and out of a possessed buffer that still needs a wipe).
#[cfg(feature = "serde")]
fn secure_string_from_str<E>(s: &str) -> Result<SecureString, E>
where
   E: serde::de::Error,
{
   let mut vec = SecureVec::new_with_capacity(s.len())
      .map_err(|_| E::custom("SecureString::deserialize: secure allocation failed"))?;
   vec.init_from_clone(s.as_bytes());
   Ok(SecureString { vec })
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SecureString {
   fn deserialize<D>(deserializer: D) -> Result<SecureString, D::Error>
   where
      D: serde::Deserializer<'de>,
   {
      struct SecureStringVisitor;
      impl<'de> serde::de::Visitor<'de> for SecureStringVisitor {
         type Value = SecureString;
         fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            write!(formatter, "an utf-8 encoded string")
         }
         /// The borrowed path, and the one the crate's own codec drives. It goes
         /// through the fallible constructor for the same reason the owned ones do: a
         /// failed secure allocation has to be an error out of a `Deserialize` impl,
         /// not a panic out of a decode.
         fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
         where
            E: serde::de::Error,
         {
            secure_string_from_str(v)
         }

         fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
         where
            E: serde::de::Error,
         {
            let str = core::str::from_utf8(v)
               .map_err(|_| E::custom("SecureString::deserialize: invalid UTF-8"))?;
            secure_string_from_str(str)
         }

         /// Formats that hand over an owned byte buffer, or an owned String built
         /// from bytes (unescaping, normalization). serde's default implementation
         /// would copy out of it and then drop it with the plaintext still inside.
         /// The guard wipes it on every arm, including a panic from the constructor.
         fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
         where
            E: serde::de::Error,
         {
            let v = Zeroizing::new(v);
            self.visit_bytes(v.as_slice())
         }

         fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
         where
            E: serde::de::Error,
         {
            let v = Zeroizing::new(v);
            secure_string_from_str(v.as_str())
         }
      }
      deserializer.deserialize_string(SecureStringVisitor)
   }
}

/// Maps a character index to a byte index.
///
/// An index at or past the end of the string resolves to the string's *length*, so callers
/// clamp rather than fail: `insert_text_at_char_idx` appends, an out-of-range start makes
/// `delete_text_char_range` a no-op, and an out-of-range end makes it delete through the end
/// of the string. That has been the behaviour since the first release, and it matches what
/// the callers expect (Zeus's text field behaves the same way over egui's `TextEdit`), so it
/// is kept deliberately. Revisit if an out-of-range index should be rejected instead.
fn char_to_byte_idx(s_bytes: &[u8], char_idx: usize) -> usize {
   core::str::from_utf8(s_bytes)
      .ok()
      .and_then(|s| s.char_indices().nth(char_idx).map(|(idx, _)| idx))
      .unwrap_or(s_bytes.len()) // Fallback to end if char_idx is out of bounds
}

#[cfg(test)]
mod tests {
   use super::SecureString;

   /// Pushing text reserves the whole slice in one growth instead of one per byte.
   ///
   /// The capacity is the observable: `SecureVec` doubles, so a reserve per byte
   /// grows 1 -> 2 -> 4 for a two-byte append, while one reserve for the whole slice
   /// grows straight to `len + appended`. That single growth is what makes a failed
   /// allocation land *before* the first byte is written. A per-byte reserve can
   /// panic half-way through a multi-byte character and leave the buffer holding
   /// truncated UTF-8: every later `unlock_str` rejects it, and the safe
   /// `unlock_str_unchecked` / `char_len_unchecked` would hand those bytes to
   /// `from_utf8_unchecked`.
   #[test]
   fn test_push_str_reserves_the_whole_slice_once() {
      let mut string = SecureString::from("a");
      assert_eq!(string.byte_len(), 1);
      assert_eq!(string.vec.capacity(), 1);

      string.push_str("\u{e9}");

      assert_eq!(string.byte_len(), 3);
      assert_eq!(
         string.vec.capacity(),
         3,
         "one reserve for the whole slice grows to 3; a reserve per byte grows 1 -> 2 -> 4"
      );
      string.unlock_str(|text| assert_eq!(text, "a\u{e9}"));
   }
}
