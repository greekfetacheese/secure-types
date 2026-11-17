//! `SecureVec<u8>` against a plain `Vec<u8>` model.
//!
//! Unit tests pin the operations they name; this drives them in arbitrary order and checks
//! the container against the model after every one, which is where a length, a capacity or
//! a compaction that is only wrong in some interleaving shows up. It runs on the
//! `no_std` build, whose raw-pointer paths are the ones `use_os` uses.

#![no_main]

use libfuzzer_sys::fuzz_target;
use secure_types::SecureVec;

fuzz_target!(|data: &[u8]| {
   let mut secret: SecureVec<u8> = SecureVec::new().unwrap();
   let mut model: Vec<u8> = Vec::new();

   for pair in data.chunks_exact(2) {
      let op = pair[0] % 6;
      let arg = usize::from(pair[1]);

      match op {
         // Append one element.
         0 => {
            let byte = pair[1];
            secret.push(byte);
            model.push(byte);
         }
         // Discard every element, keeping the allocation.
         1 => {
            secret.clear();
            model.clear();
         }
         // Grow without touching the length.
         2 => {
            let additional = arg % 64;
            secret.reserve(additional);
            assert!(secret.capacity() >= secret.len() + additional);
         }
         // Drain an in-bounds range.
         3 => {
            if !model.is_empty() {
               let start = (arg >> 4) % model.len();
               let end = start + (arg & 0x0F) % (model.len() - start + 1);

               let drained: Vec<u8> = secret.drain(start..end).collect();
               let expected: Vec<u8> = model.drain(start..end).collect();

               assert_eq!(drained, expected);
            }
         }
         // Read the whole value back.
         4 => {
            secret.unlock_slice(|slice| assert_eq!(slice, model.as_slice()));
         }
         // Write through the mutable window.
         _ => {
            let byte = pair[1];

            secret.unlock_slice_mut(|slice| {
               for slot in slice.iter_mut() {
                  *slot = slot.wrapping_add(byte);
               }
            });
            for slot in model.iter_mut() {
               *slot = slot.wrapping_add(byte);
            }
         }
      }

      assert_eq!(secret.len(), model.len());
      assert!(secret.capacity() >= secret.len());
   }

   secret.unlock_slice(|slice| assert_eq!(slice, model.as_slice()));
});
