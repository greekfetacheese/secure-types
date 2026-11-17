//! decode_slice::<SecureBytes> on arbitrary bytes.
//!
//! Same reader, byte-buffer variant: the payload is copied into a SecureVec<u8> that is
//! zeroized on drop, so this also drives the container's construction, growth and drop
//! paths from a document the fuzzer chose.

#![no_main]

use libfuzzer_sys::fuzz_target;
use secure_types::{SecureBytes, decode_slice};

fuzz_target!(|data: &[u8]| {
   let Ok(secret) = decode_slice::<SecureBytes>(data) else {
      return;
   };

   assert!(secret.len() <= data.len());
   // The document is version || varint(len) || bytes, and the reader refuses trailing
   // bytes, so the value it produced is exactly the document's tail.
   secret.unlock_slice(|slice| assert!(data.ends_with(slice)));
});
