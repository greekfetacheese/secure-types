//! Crate-level behavior: the OS capability the locking is built on, and the
//! `SecureArray`/`SecureVec` serde-compatibility contract.

// `memfd_secret` is Linux-only, so this test is gated to Linux as well as to OS
// support; non-Linux Unix gets `test_memfd_secret_is_unavailable_off_linux` instead.
#[cfg(all(target_os = "linux", feature = "use_os"))]
#[test]
fn test_supports_memfd_secret() {
   use secure_types::{memsec, supports_memfd_secret};

   let supports = supports_memfd_secret();

   if supports {
      print!("memfd_secret is supported");
      let size = std::mem::size_of::<u8>();
      let ptr = unsafe { memsec::memfd_secret_sized(size) };
      assert!(ptr.is_some());
   } else {
      print!("memfd_secret is not supported");
   }
}

/// `memfd_secret` is Linux-only, so every other Unix reports it as unavailable
/// rather than probing a syscall that does not exist there.
#[cfg(all(unix, not(target_os = "linux"), feature = "use_os"))]
#[test]
fn test_memfd_secret_is_unavailable_off_linux() {
   assert!(!secure_types::supports_memfd_secret());
}

#[cfg(feature = "serde")]
#[test]
fn test_array_and_secure_vec_serde_compatibility() {
   use secure_types::{SecureArray, SecureVec};

   let exposed_array: &mut [u8; 3] = &mut [1, 2, 3];
   let array: SecureArray<u8, 3> = SecureArray::from_slice_mut(exposed_array).unwrap();
   let vec: SecureVec<u8> = array.clone().into();

   let array_json_string = serde_json::to_string(&array).unwrap();
   let array_json_bytes = serde_json::to_vec(&array).unwrap();
   let vec_json_string = serde_json::to_string(&vec).unwrap();
   let vec_json_bytes = serde_json::to_vec(&vec).unwrap();

   assert_eq!(array_json_string, vec_json_string);
   assert_eq!(array_json_bytes, vec_json_bytes);

   let deserialized_array_from_string: SecureArray<u8, 3> =
      serde_json::from_str(&array_json_string).unwrap();

   let deserialized_array_from_bytes: SecureArray<u8, 3> =
      serde_json::from_slice(&array_json_bytes).unwrap();

   let deserialized_vec_from_string: SecureVec<u8> =
      serde_json::from_str(&vec_json_string).unwrap();

   let deserialized_vec_from_bytes: SecureVec<u8> =
      serde_json::from_slice(&vec_json_bytes).unwrap();

   deserialized_array_from_string.unlock(|slice| {
      deserialized_vec_from_string.unlock_slice(|slice2| {
         assert_eq!(slice, slice2);
      });
   });

   deserialized_array_from_bytes.unlock(|slice| {
      deserialized_vec_from_bytes.unlock_slice(|slice2| {
         assert_eq!(slice, slice2);
      });
   });
}
