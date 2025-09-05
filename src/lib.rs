//! # Secure Types
//!
//! This crate provides heap-allocated data structures (`SecureVec`, `SecureArray`, `SecureString`)
//! designed to handle sensitive information in memory with enhanced security.
//!
//! ## Core Security Guarantees
//!
//! The primary goal is to protect secret data (like passwords, private keys, or credentials)
//! from being exposed through common vulnerabilities.
//!
//! 1.  **Zeroization on Drop**: All secure types implement the `Zeroize` trait, ensuring their
//!     memory is securely overwritten with zeros when they are dropped. This prevents stale
//!     data from being recoverable in deallocated memory.
//!
//! 2.  **Memory Locking (`std` only)**: When compiled with the `std` feature (the default),
//!     the crate uses OS-level primitives to lock memory pages, preventing them from being
//!     swapped to disk.
//!     - On Windows: `VirtualLock` and `VirtualProtect`.
//!     - On Unix: `mlock` and `mprotect`.
//!
//! 3.  **Memory Encryption (`std` on Windows only)**: On Windows, memory is also encrypted
//!     in place using `CryptProtectMemory`, providing an additional layer of protection
//!     against memory inspection.
//!
//! 4.  **Scoped Access**: Data is protected by default. To access it, you must use scoped
//!     methods like `.unlocked_scope(|slice| { ... })`, which temporarily makes the data
//!     accessible and automatically re-locks it afterward.
//!
//! ## Usage Example
//!
//! Here's a quick example of how to use `SecureString`:
//!
//! ```rust
//! use secure_types::SecureString;
//!
//! // Create a string from a sensitive literal.
//! // The original data is securely zeroized after being copied.
//! let mut secret = SecureString::from("my_super_secret_password");
//!
//! // The memory is locked and protected here. Direct access is not possible.
//!
//! // Use a scope to safely access the content as a &str.
//! secret.unlock_str(|unlocked_str| {
//!     assert_eq!(unlocked_str, "my_super_secret_password");
//!     println!("The secret is: {}", unlocked_str);
//! });
//!
//! // The memory is automatically locked again when the scope ends.
//!
//! // When `secret` goes out of scope, its memory will be securely zeroized.
//! ```
//!
//! ## Feature Flags
//!
//! - `std` (default): Enables all OS-level security features like memory locking and encryption.
//! - `serde`: Enables serialization and deserialization for `SecureString` and `SecureBytes` via the Serde framework.
//! - `no_std`: Compiles the crate in a `no_std` environment. In this mode, only the **Zeroize on Drop** applys.

#![cfg_attr(feature = "no_std", no_std)]

#[cfg(feature = "no_std")]
extern crate alloc;

pub mod array;
pub mod string;
pub mod vec;

pub use array::SecureArray;
pub use string::SecureString;
pub use vec::{SecureBytes, SecureVec};

use core::ptr::NonNull;
pub use zeroize::Zeroize;

#[cfg(feature = "std")]
pub use memsec;
#[cfg(feature = "std")]
use memsec::Prot;

use thiserror::Error as ThisError;

#[cfg(feature = "std")]
#[derive(ThisError, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum Error {
   #[error("Failed to allocate secure memory")]
   AllocationFailed,
   #[error("Length cannot be zero")]
   LengthCannotBeZero,
   #[error("Allocated Ptr is null")]
   NullAllocation,
   #[error("CryptProtectMemory failed")]
   CryptProtectMemoryFailed,
   #[error("CryptUnprotectMemory failed")]
   CryptUnprotectMemoryFailed,
   #[error("Failed to lock memory")]
   LockFailed,
   #[error("Failed to unlock memory")]
   UnlockFailed,
   #[error("Source length does not match the fixed size of the destination array")]
   LengthMismatch,
}

#[cfg(not(feature = "std"))]
#[derive(Debug)]
pub enum Error {
   AllocationFailed,
   NullAllocation,
}

#[cfg(all(feature = "std", test, windows))]
use windows_sys::Win32::Foundation::GetLastError;
#[cfg(all(feature = "std", windows))]
use windows_sys::Win32::Security::Cryptography::{
   CRYPTPROTECTMEMORY_BLOCK_SIZE, CRYPTPROTECTMEMORY_SAME_PROCESS, CryptProtectMemory,
   CryptUnprotectMemory,
};
#[cfg(all(feature = "std", windows))]
use windows_sys::Win32::System::SystemInformation::GetSystemInfo;

#[cfg(feature = "std")]
/// Returns the page size depending on the OS
pub fn page_size() -> usize {
   #[cfg(unix)]
   {
      unsafe { libc::sysconf(libc::_SC_PAGESIZE) as usize }
   }

   #[cfg(windows)]
   {
      let mut si = core::mem::MaybeUninit::uninit();
      unsafe {
         GetSystemInfo(si.as_mut_ptr());
         (*si.as_ptr()).dwPageSize as usize
      }
   }
}

#[cfg(feature = "std")]
/// Returns the page aligned size of a given size
pub fn page_aligned_size(size: usize) -> usize {
   (size + page_size() - 1) & !(page_size() - 1)
}

#[cfg(feature = "std")]
pub fn mprotect<T>(ptr: NonNull<T>, prot: Prot::Ty) -> bool {
   let success = unsafe { memsec::mprotect(ptr, prot) };
   if !success {
      #[cfg(test)]
      eprintln!("mprotect failed");
   }
   success
}

#[cfg(all(feature = "std", windows))]
pub fn crypt_protect_memory(ptr: *mut u8, aligned_size: usize) -> bool {
   if aligned_size == 0 {
      return true; // Nothing to encrypt
   }

   if aligned_size % (CRYPTPROTECTMEMORY_BLOCK_SIZE as usize) != 0 {
      // not a multiple of CRYPTPROTECTMEMORY_BLOCK_SIZE
      return false;
   }

   if aligned_size > u32::MAX as usize {
      return false;
   }

   let result = unsafe {
      CryptProtectMemory(
         ptr as *mut core::ffi::c_void,
         aligned_size as u32,
         CRYPTPROTECTMEMORY_SAME_PROCESS,
      )
   };

   if result == 0 {
      #[cfg(test)]
      {
         let error_code = unsafe { GetLastError() };
         eprintln!(
            "CryptProtectMemory failed with error code: {}",
            error_code
         );
      }
      false
   } else {
      true
   }
}

#[cfg(all(feature = "std", windows))]
pub fn crypt_unprotect_memory(ptr: *mut u8, size_in_bytes: usize) -> bool {
   if size_in_bytes == 0 {
      return true;
   }

   if size_in_bytes % (CRYPTPROTECTMEMORY_BLOCK_SIZE as usize) != 0 {
      return false;
   }

   if size_in_bytes > u32::MAX as usize {
      return false;
   }

   let result = unsafe {
      CryptUnprotectMemory(
         ptr as *mut core::ffi::c_void,
         size_in_bytes as u32,
         CRYPTPROTECTMEMORY_SAME_PROCESS,
      )
   };

   if result == 0 {
      #[cfg(test)]
      {
         let error_code = unsafe { GetLastError() };
         eprintln!(
            "CryptUnprotectMemory failed with error code: {}",
            error_code
         );
      }
      false
   } else {
      true
   }
}

#[cfg(test)]
mod tests {
   #[cfg(feature = "serde")]
   #[test]
   fn test_array_and_secure_vec_serde_compatibility() {
      use super::*;
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
}
