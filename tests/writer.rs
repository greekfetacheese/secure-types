//! `SecureBytesWriter`, exercised through the public API.
//!
//! The module itself is `use_os`-only, so these tests are too.

#![cfg(feature = "use_os")]

use std::io::Write;

use secure_types::{SecureBytes, SecureBytesWriter};

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
