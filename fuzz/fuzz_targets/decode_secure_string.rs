//! decode_slice::<SecureString> on arbitrary bytes.
//!
//! The reader's narrowest entry point: a version byte, a varint length, a UTF-8 check,
//! and the SecureString Deserialize impl. A decoded string can only be made of bytes the
//! document carried, which is the invariant asserted here: a length the reader trusted
//! without checking would violate it.

#![no_main]

use libfuzzer_sys::fuzz_target;
use secure_types::SecureString;

fuzz_target!(|data: &[u8]| {
   let Ok(secret) = secure_types::decode_slice::<SecureString>(data) else {
      return;
   };

   assert!(secret.byte_len() <= data.len());
   secret.unlock_str(|text| assert!(data.ends_with(text.as_bytes())));
});
