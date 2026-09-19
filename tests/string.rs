//! `SecureString`, exercised through the public API.

#![cfg(feature = "use_os")]

#[cfg(feature = "serde")]
mod common;

use secure_types::{SecureString, SecureVec};

#[test]
fn test_creation() {
   let hello_world = "Hello, world!";
   let secure = SecureString::from(hello_world);

   secure.unlock_str(|str| {
      assert_eq!(str, hello_world);
   });
}

#[test]
fn test_from_string() {
   let hello_world = String::from("Hello, world!");
   let string = SecureString::from(hello_world);

   string.unlock_str(|str| {
      assert_eq!(str, "Hello, world!");
   });
}

#[test]
fn test_try_from_secure_vec() {
   let hello_world = "Hello, world!".to_string();
   let vec: SecureVec<u8> = SecureVec::from_slice(hello_world.as_bytes()).unwrap();

   let string = SecureString::from(hello_world);
   let string2 = SecureString::try_from(vec).unwrap();

   string.unlock_str(|str| {
      string2.unlock_str(|str2| {
         assert_eq!(str, str2);
      });
   });

   string.unlock_str_unchecked(|str| {
      string2.unlock_str_unchecked(|str2| {
         assert_eq!(str, str2);
      });
   });
}

#[test]
fn test_clone() {
   let hello_world = "Hello, world!".to_string();
   let secure1 = SecureString::from(hello_world.clone());
   let secure2 = secure1.clone();

   secure2.unlock_str(|str| {
      assert_eq!(str, hello_world);
   });

   secure2.unlock_str_unchecked(|str| {
      assert_eq!(str, hello_world);
   });
}

#[test]
fn test_insert_text_at_char_idx() {
   let hello_world = "My name is ";
   let mut secure = SecureString::from(hello_world);
   secure.insert_text_at_char_idx(12, "Mike");
   secure.unlock_str(|str| {
      assert_eq!(str, "My name is Mike");
   });

   secure.unlock_str_unchecked(|str| {
      assert_eq!(str, "My name is Mike");
   });
}

#[test]
fn test_insert_text_at_char_idx_multibyte() {
   // 'é' is 2 bytes and '🎉' is 4, so the char index is not the byte index.
   let mut secure = SecureString::from("héllo");
   let inserted = secure.insert_text_at_char_idx(2, "🎉!");

   assert_eq!(inserted, 2);
   assert_eq!(secure.byte_len(), 11);
   secure.unlock_str(|str| {
      assert_eq!(str, "hé🎉!llo");
   });
}

#[test]
fn test_delete_text_char_range() {
   let hello_world = "My name is Mike";
   let mut secure = SecureString::from(hello_world);
   secure.delete_text_char_range(10..17);
   secure.unlock_str(|str| {
      assert_eq!(str, "My name is");
   });

   secure.unlock_str_unchecked(|str| {
      assert_eq!(str, "My name is");
   });
}

#[test]
fn test_drain() {
   let hello_world = "Hello, world!";
   let mut secure = SecureString::from(hello_world);
   secure.drain(0..7);
   secure.unlock_str(|str| {
      assert_eq!(str, "world!");
   });

   secure.unlock_str_unchecked(|str| {
      assert_eq!(str, "world!");
   });
}

#[cfg(feature = "serde")]
#[test]
fn test_serde() {
   let hello_world = "Hello, world!";
   let secure = SecureString::from(hello_world);

   let json_string = serde_json::to_string(&secure).expect("Serialization failed");
   let json_bytes = serde_json::to_vec(&secure).expect("Serialization failed");

   let deserialized_string: SecureString =
      serde_json::from_str(&json_string).expect("Deserialization failed");

   let deserialized_bytes: SecureString =
      serde_json::from_slice(&json_bytes).expect("Deserialization failed");

   deserialized_string.unlock_str(|str| {
      assert_eq!(str, hello_world);
   });

   deserialized_string.unlock_str_unchecked(|str| {
      assert_eq!(str, hello_world);
   });

   deserialized_bytes.unlock_str(|str| {
      assert_eq!(str, hello_world);
   });

   deserialized_bytes.unlock_str_unchecked(|str| {
      assert_eq!(str, hello_world);
   });
}

#[cfg(feature = "serde")]
#[test]
fn test_deserialize_from_owned_string() {
   use common::OwnedString;
   use serde::Deserialize;

   // A format that hands over an owned `String` reaches `visit_string`, which copies
   // into locked memory and then wipes the buffer it was given.
   let secure = SecureString::deserialize(OwnedString("hunter2".to_owned())).unwrap();

   secure.unlock_str(|str| assert_eq!(str, "hunter2"));
}

#[test]
fn test_unlock_str() {
   let hello_word = "Hello, world!";
   let string = SecureString::from(hello_word);
   let _exposed_string = string.unlock_str(|str| {
      assert_eq!(str, hello_word);
      String::from(str)
   });

   let _exposed_string = string.unlock_str_unchecked(|str| {
      assert_eq!(str, hello_word);
      String::from(str)
   });
}

#[test]
fn test_push_str() {
   let hello_world = "Hello, world!";

   let mut string = SecureString::new().unwrap();
   string.push_str(hello_world);
   string.unlock_str(|str| {
      assert_eq!(str, hello_world);
   });

   string.unlock_str_unchecked(|str| {
      assert_eq!(str, hello_world);
   });
}

#[test]
fn test_unlock_mut() {
   let hello_world = "Hello, world!";
   let mut string = SecureString::from("Hello, ");
   string.secure_mut(|string| {
      string.push_str("world!");
   });

   string.unlock_str(|str| {
      assert_eq!(str, hello_world);
   });

   string.unlock_str_unchecked(|str| {
      assert_eq!(str, hello_world);
   });
}
