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
#[cfg(feature = "use_os")]
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

#[cfg(not(feature = "use_os"))]
#[derive(Debug)]
pub enum Error {
   AlignmentFailed,
   AllocationFailed,
   NullAllocation,
}

#[cfg(all(feature = "use_os", test, windows))]
use windows_sys::Win32::Foundation::GetLastError;
#[cfg(all(feature = "use_os", windows))]
use windows_sys::Win32::Security::Cryptography::{
   CRYPTPROTECTMEMORY_BLOCK_SIZE, CRYPTPROTECTMEMORY_SAME_PROCESS, CryptProtectMemory,
   CryptUnprotectMemory,
};
#[cfg(all(feature = "use_os", windows))]
use windows_sys::Win32::System::SystemInformation::GetSystemInfo;

static PAGE_SIZE_INIT: Once = Once::new();
static mut PAGE_SIZE: usize = 0;

#[cfg(all(feature = "use_os", unix))]
static mut SUPPORTS_MEMFD_SECRET: bool = false;
#[cfg(all(feature = "use_os", unix))]
static SUPPORTS_MEMFD_SECRET_INIT: Once = Once::new();

#[cfg(feature = "use_os")]
/// Returns the page size depending on the OS
unsafe fn page_size_init() {
   #[cfg(unix)]
   unsafe {
      PAGE_SIZE = libc::sysconf(libc::_SC_PAGESIZE) as usize;
   }

   #[cfg(windows)]
   {
      let mut si = core::mem::MaybeUninit::uninit();
      unsafe {
         GetSystemInfo(si.as_mut_ptr());
         PAGE_SIZE = (*si.as_ptr()).dwPageSize as usize;
      }
   }
}

#[cfg(feature = "use_os")]
/// Returns the page aligned size of a given size
pub(crate) unsafe fn page_aligned_size(size: usize) -> usize {
   PAGE_SIZE_INIT.call_once(|| unsafe { page_size_init() });
   unsafe { (size + PAGE_SIZE - 1) & !(PAGE_SIZE - 1) }
}

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
/// Size is page aligned if the target is an OS
///
/// For `Windows` it always uses [memsec::malloc_sized]
///
/// For `Unix` it uses [memsec::memfd_secret_sized] if `memfd_secret` is supported
///
/// If the allocation fails it fallbacks to [memsec::malloc_sized]
pub(crate) unsafe fn alloc_aligned<T>(size: usize) -> Result<NonNull<T>, Error> {
   #[cfg(feature = "use_os")]
   {
      #[cfg(windows)]
      unsafe {
         let aligned_size = page_aligned_size(size);
         let allocated_ptr = memsec::malloc_sized(aligned_size);
         let non_null = allocated_ptr.ok_or(Error::AllocationFailed)?;
         let ptr = non_null.as_ptr() as *mut T;
         NonNull::new(ptr).ok_or(Error::NullAllocation)
      }

      #[cfg(unix)]
      {
         SUPPORTS_MEMFD_SECRET_INIT.call_once(|| unsafe { supports_memfd_secret_init() });

         let aligned_size = unsafe { page_aligned_size(size) };
         let supports_memfd_secret = unsafe { SUPPORTS_MEMFD_SECRET };

         let ptr_opt = if supports_memfd_secret {
            unsafe { memsec::memfd_secret_sized(aligned_size) }
         } else {
            None
         };

         if let Some(ptr) = ptr_opt {
            NonNull::new(ptr.as_ptr() as *mut T).ok_or(Error::NullAllocation)
         } else {
            unsafe {
               let allocated_ptr = memsec::malloc_sized(aligned_size);
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

#[cfg(all(feature = "use_os", windows))]
pub(crate) fn crypt_protect_memory(ptr: *mut u8, aligned_size: usize) -> bool {
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

#[cfg(all(feature = "use_os", windows))]
pub(crate) fn crypt_unprotect_memory(ptr: *mut u8, size_in_bytes: usize) -> bool {
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

   #[cfg(unix)]
   #[test]
   fn test_supports_memfd_secret() {
      use super::*;

      SUPPORTS_MEMFD_SECRET_INIT.call_once(|| unsafe { supports_memfd_secret_init() });

      let supports = unsafe { SUPPORTS_MEMFD_SECRET };

      if supports {
         print!("memfd_secret is supported");
         let size = 1 * size_of::<u8>();
         let aligned = unsafe { page_aligned_size(size) };
         let ptr = unsafe { memsec::memfd_secret_sized(aligned) };
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
