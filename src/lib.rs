#![doc = include_str!("../readme.md")]
#![cfg_attr(feature = "no_os", no_os)]

#[cfg(feature = "no_os")]
extern crate alloc;

pub mod array;
pub mod string;
pub mod vec;

pub use array::SecureArray;
pub use string::SecureString;
pub use vec::{SecureBytes, SecureVec};

use core::ptr::NonNull;
pub use zeroize::Zeroize;

#[cfg(feature = "use_os")]
pub use memsec;
#[cfg(feature = "use_os")]
use memsec::Prot;
#[cfg(all(feature = "use_os", unix))]
use std::sync::Once;

use thiserror::Error as ThisError;

#[cfg(feature = "use_os")]
#[derive(ThisError, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum Error {
   #[error("Failed to allocate secure memory")]
   AllocationFailed,
   #[error("Length cannot be zero")]
   LengthCannotBeZero,
   #[error("Allocated Ptr is null")]
   NullAllocation,
   #[error("Failed to lock memory")]
   LockFailed,
   #[error("Failed to unlock memory")]
   UnlockFailed,
   #[error("Source length does not match the fixed size of the destination array")]
   LengthMismatch,
}

#[cfg(not(feature = "use_os"))]
#[derive(Debug)]
pub enum Error {
   AlignmentFailed,
   AllocationFailed,
   NullAllocation,
}


#[cfg(all(feature = "use_os", unix))]
static mut SUPPORTS_MEMFD_SECRET: bool = false;
#[cfg(all(feature = "use_os", unix))]
static SUPPORTS_MEMFD_SECRET_INIT: Once = Once::new();


#[cfg(all(feature = "use_os", unix))]
unsafe fn supports_memfd_secret_init() {
   use libc::{SYS_memfd_secret, close, syscall};

   let res = unsafe { syscall(SYS_memfd_secret as _, 0isize) };

   if res >= 0 {
      // memfd_secret is supported
      unsafe { close(res as libc::c_int) };
      unsafe { SUPPORTS_MEMFD_SECRET = true };
   } else {
      /*
      let errno = unsafe { *libc::__errno_location() };
      if errno == ENOSYS {
         // not supported
      } else {
         // Other error treat as unsupported
      }
       */
   }
}

/// Allocate memory
///
/// For `Windows` it always uses [memsec::malloc_sized]
///
/// For `Unix` it uses [memsec::memfd_secret_sized] if `memfd_secret` is supported
///
/// If the allocation fails it fallbacks to [memsec::malloc_sized]
pub(crate) unsafe fn alloc<T>(size: usize) -> Result<NonNull<T>, Error> {
   #[cfg(feature = "use_os")]
   {
      #[cfg(windows)]
      unsafe {
         let allocated_ptr = memsec::malloc_sized(size);
         let non_null = allocated_ptr.ok_or(Error::AllocationFailed)?;
         let ptr = non_null.as_ptr() as *mut T;
         NonNull::new(ptr).ok_or(Error::NullAllocation)
      }

      #[cfg(unix)]
      {
         SUPPORTS_MEMFD_SECRET_INIT.call_once(|| unsafe { supports_memfd_secret_init() });

         let supports_memfd_secret = unsafe { SUPPORTS_MEMFD_SECRET };

         let ptr_opt = if supports_memfd_secret {
            unsafe { memsec::memfd_secret_sized(size) }
         } else {
            None
         };

         if let Some(ptr) = ptr_opt {
            NonNull::new(ptr.as_ptr() as *mut T).ok_or(Error::NullAllocation)
         } else {
            unsafe {
               let allocated_ptr = memsec::malloc_sized(size);
               let non_null = allocated_ptr.ok_or(Error::AllocationFailed)?;
               let ptr = non_null.as_ptr() as *mut T;
               NonNull::new(ptr).ok_or(Error::NullAllocation)
            }
         }
      }
   }

   #[cfg(not(feature = "use_os"))]
   {
      let layout =
         Layout::from_size_align(size, mem::align_of::<T>()).map_err(|_| Error::AlignmentFailed)?;
      let ptr = unsafe { alloc::alloc(layout) as *mut T };
      if ptr.is_null() {
         return Err(Error::NullAllocation);
      }
      ptr
   }
}

#[cfg(feature = "use_os")]
pub(crate) fn free<T>(ptr: NonNull<T>) {
   #[cfg(windows)]
   unsafe {
      memsec::free(ptr);
   }

   #[cfg(unix)]
   {
      let supports_memfd_secret = unsafe { SUPPORTS_MEMFD_SECRET };
      if supports_memfd_secret {
         unsafe { memsec::free_memfd_secret(ptr) };
      } else {
         unsafe { memsec::free(ptr) };
      }
   }
}

#[cfg(feature = "use_os")]
pub(crate) fn mprotect<T>(ptr: NonNull<T>, prot: Prot::Ty) -> bool {
   let success = unsafe { memsec::mprotect(ptr, prot) };
   #[cfg(test)]
   {
      if !success {
         eprintln!("mprotect failed");
      }
   }
   success
}


#[cfg(test)]
mod tests {

   #[cfg(unix)]
   #[test]
   fn test_supports_memfd_secret() {
      use super::*;

      SUPPORTS_MEMFD_SECRET_INIT.call_once(|| unsafe { supports_memfd_secret_init() });

      let supports = unsafe { SUPPORTS_MEMFD_SECRET };

      if supports {
         print!("memfd_secret is supported");
         let size = 1 * size_of::<u8>();
         let ptr = unsafe { memsec::memfd_secret_sized(size) };
         assert!(ptr.is_some());
      } else {
         print!("memfd_secret is not supported");
      }
   }

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
