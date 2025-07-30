#[cfg(feature = "std")]
use std::vec::Vec;

use super::{Error, vec::SecureVec};
use core::ops::Range;
use zeroize::Zeroize;

/// A securely allocated, growable UTF-8 string, analogous to `std::string::String`.
///
/// It is a wrapper around `SecureVec<u8>` and inherits all of its security guarantees,
/// ensuring that sensitive string data like passwords, API keys, or personal information
/// is handled with care.
///
/// ## Security Model
///
/// `SecureString` enforces the same security model as `SecureVec`:
/// - **Zeroization on Drop**: The string's buffer is securely wiped clean.
/// - **Memory Locking & Encryption**: When the `std` feature is enabled, the buffer is
///   protected against OS-level spying via disk swaps or memory inspection tools.
///
/// Access to the string contents is provided through scoped methods like `str_scope`,
/// which ensure the memory is only unlocked for the briefest possible time.
///
/// ## Security Considerations
///
/// While the crate protects the memory, you must still be careful not to leak the data.
/// For example, creating a new, unsecured `String` from the unlocked slice and returning
/// it from the scope would leak the sensitive data if not handled correctly.
///
/// # Examples
///
/// ```
/// use secure_types::SecureString;
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
/// secret.str_scope(|exposed_str| {
///     assert_eq!(exposed_str, "my_super_secret_password");
/// });
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

   pub fn erase(&mut self) {
      self.vec.erase();
   }

   pub fn len(&self) -> usize {
      self.vec.len()
   }

   pub fn drain(&mut self, range: Range<usize>) {
      let _ = self.vec.drain(range);
   }

   pub fn char_len(&self) -> usize {
      self.str_scope(|s| s.chars().count())
   }

   /// Push a `&str` into the `SecureString`
   pub fn push_str(&mut self, string: &str) {
      let slice = string.as_bytes();
      for s in slice.iter() {
         self.vec.push(*s);
      }
   }

   /// Access the `SecureString` as `&str`
   ///
   /// ## Use with caution
   ///
   ///
   ///  You can actually return a new allocated `String` from this function
   ///
   ///  If you do that you are responsible for zeroizing its contents
   pub fn str_scope<F, R>(&self, f: F) -> R
   where
      F: FnOnce(&str) -> R,
   {
      self.vec.slice_scope(|slice| {
         let str = core::str::from_utf8(slice).unwrap();
         let result = f(str);
         result
      })
   }

   /// Mutable access to the `SecureString`
   ///
   /// ## Use with caution
   ///
   ///
   /// You can actually return a new allocated `String` from this function
   ///
   /// If you do that you are responsible for zeroizing its contents
   pub fn mut_scope<F, R>(&mut self, f: F) -> R
   where
      F: FnOnce(&mut SecureString) -> R,
   {
      f(self)
   }

   #[cfg(feature = "std")]
   pub fn insert_text_at_char_idx(&mut self, char_idx: usize, text_to_insert: &str) -> usize {
      let chars_to_insert_count = text_to_insert.chars().count();
      if chars_to_insert_count == 0 {
         return 0;
      }

      let bytes_to_insert = text_to_insert.as_bytes();
      let insert_len = bytes_to_insert.len();

      // Get byte_idx based on current content (before modification)
      let byte_idx = self
         .vec
         .slice_scope(|current_bytes| char_to_byte_idx(current_bytes, char_idx));

      let old_byte_len = self.vec.len();
      let new_byte_len = old_byte_len + insert_len;

      if new_byte_len > self.vec.capacity {
         // Reallocation
         let mut temp_new_content = Vec::with_capacity(new_byte_len);
         self.vec.slice_scope(|current_bytes| {
            temp_new_content.extend_from_slice(&current_bytes[..byte_idx]);
            temp_new_content.extend_from_slice(bytes_to_insert);
            if byte_idx < old_byte_len {
               // Ensure we don't slice out of bounds if inserting at end
               temp_new_content.extend_from_slice(&current_bytes[byte_idx..]);
            }
         });

         let mut new_secure_vec = SecureVec::new_with_capacity(new_byte_len).unwrap();
         for &b in temp_new_content.iter() {
            new_secure_vec.push(b);
         }
         temp_new_content.zeroize();

         let _old_secure_vec = core::mem::replace(&mut self.vec, new_secure_vec);
      } else {
         self.vec.unlock_memory();
         unsafe {
            let ptr = self.vec.as_mut_ptr();

            if byte_idx < old_byte_len {
               core::ptr::copy(
                  ptr.add(byte_idx),
                  ptr.add(byte_idx + insert_len),
                  old_byte_len - byte_idx,
               );
            }

            core::ptr::copy_nonoverlapping(
               bytes_to_insert.as_ptr(),
               ptr.add(byte_idx),
               insert_len,
            );

            self.vec.len = new_byte_len;
         }
         self.vec.lock_memory();
      }

      chars_to_insert_count
   }

   #[cfg(feature = "std")]
   pub fn delete_text_char_range(&mut self, char_range: core::ops::Range<usize>) {
      if char_range.start >= char_range.end {
         return;
      }

      let (byte_start, byte_end) = self.str_scope(|str| {
         let byte_start = char_to_byte_idx(str.as_bytes(), char_range.start);
         let byte_end = char_to_byte_idx(str.as_bytes(), char_range.end);
         (byte_start, byte_end)
      });

      let new_len = self.vec.slice_mut_scope(|current_bytes| {
         if byte_start >= byte_end || byte_end > current_bytes.len() {
            return 0;
         }

         let remove_len = byte_end - byte_start;
         let old_total_len = current_bytes.len();

         // Shift elements left
         current_bytes.copy_within(byte_end..old_total_len, byte_start);

         let new_len = old_total_len - remove_len;
         // Zeroize the tail end that is now unused
         for i in new_len..old_total_len {
            current_bytes[i].zeroize();
         }
         new_len
      });
      self.vec.len = new_len;
   }
}


#[cfg(feature = "std")]
impl From<String> for SecureString {
   fn from(s: String) -> SecureString {
      let vec = SecureVec::from_vec(s.into_bytes()).unwrap();
      SecureString { vec }
   }
}

impl From<&str> for SecureString {
   fn from(s: &str) -> SecureString {
      let bytes = s.as_bytes();
      let len = bytes.len();

      let mut new_vec = SecureVec::new_with_capacity(len).unwrap();
      new_vec.len = len;

      new_vec.slice_mut_scope(|slice| {
         slice[..len].copy_from_slice(bytes);
      });

      SecureString { vec: new_vec }
   }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SecureString {
   fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
   where
      S: serde::Serializer,
   {
      let res = self.str_scope(|str| serializer.serialize_str(str));
      res
   }
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
         fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
         where
            E: serde::de::Error,
         {
            Ok(SecureString::from(v))
         }
      }
      deserializer.deserialize_string(SecureStringVisitor)
   }
}

#[cfg(feature = "std")]
fn char_to_byte_idx(s_bytes: &[u8], char_idx: usize) -> usize {
   core::str::from_utf8(s_bytes)
      .ok()
      .and_then(|s| s.char_indices().nth(char_idx).map(|(idx, _)| idx))
      .unwrap_or(s_bytes.len()) // Fallback to end if char_idx is out of bounds
}

#[cfg(all(test, feature = "std"))]
mod tests {
   use super::*;

   #[test]
   fn test_clone() {
      let hello_world = "Hello, world!".to_string();
      let secure1 = SecureString::from(hello_world.clone());
      let secure2 = secure1.clone();

      secure2.str_scope(|str| {
         assert_eq!(str, hello_world);
      });
   }

   #[test]
   fn test_insert_text_at_char_idx() {
      let hello_world = "My name is ";
      let mut secure = SecureString::from(hello_world);
      secure.insert_text_at_char_idx(12, "Mike");
      secure.str_scope(|str| {
         assert_eq!(str, "My name is Mike");
      });
   }

   #[test]
   fn test_delete_text_char_range() {
      let hello_world = "My name is Mike";
      let mut secure = SecureString::from(hello_world);
      secure.delete_text_char_range(10..17);
      secure.str_scope(|str| {
         assert_eq!(str, "My name is");
      });
   }

   #[test]
   fn test_drain() {
      let hello_world = "Hello, world!";
      let mut secure = SecureString::from(hello_world);
      secure.drain(0..7);
      secure.str_scope(|str| {
         assert_eq!(str, "world!");
      });
   }

   #[cfg(feature = "serde")]
   #[test]
   fn test_secure_string_serde() {
      let hello_world = "Hello, world!";
      let secure = SecureString::from(hello_world);
      let json = serde_json::to_string(&secure).expect("Serialization failed");
      let deserialized: SecureString = serde_json::from_str(&json).expect("Deserialization failed");
      deserialized.str_scope(|str| {
         assert_eq!(str, hello_world);
      });
   }

   #[test]
   fn test_str_scope() {
      let hello_word = "Hello, world!";
      let string = SecureString::from(hello_word);
      let _exposed_string = string.str_scope(|str| {
         assert_eq!(str, hello_word);
         String::from(str)
      });
   }

   #[test]
   fn test_push_str() {
      let hello_world = "Hello, world!";

      let mut string = SecureString::new().unwrap();
      string.push_str(hello_world);
      string.str_scope(|str| {
         assert_eq!(str, hello_world);
      });
   }

   #[test]
   fn test_mut_scope() {
      let hello_world = "Hello, world!";
      let mut string = SecureString::from("Hello, ");
      string.mut_scope(|string| {
         string.push_str("world!");
      });

      string.str_scope(|str| {
         assert_eq!(str, hello_world);
      });
   }
}
