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
const ALLOC_TAG_MALLOC: usize = 0xDEAD_BEEF;
#[cfg(all(feature = "use_os", unix))]
const ALLOC_TAG_MEMFD: usize = 0x5EC0_0000;

/// Calculates the offset needed to store a usize header while maintaining
/// the alignment requirements of T.
#[cfg(all(feature = "use_os", unix))]
const fn get_header_offset<T>() -> usize {
   let header_size = core::mem::size_of::<usize>();
   let align = core::mem::align_of::<T>();

   // If T needs stronger alignment than usize, we must pad more.
   // Otherwise, sizeof(usize) is sufficient.
   if align > header_size {
      align
   } else {
      header_size
   }
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
         // Other error
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

         let header_offset = get_header_offset::<T>();

         // Calculate alignment requirement
         let align_req = core::mem::align_of::<usize>().max(core::mem::align_of::<T>());

         // Calculate raw size (Header + Data)
         let raw_size = size
            .checked_add(header_offset)
            .ok_or(Error::AllocationFailed)?;

         // Calculate padded size to satisfy alignment
         let remainder = raw_size % align_req;
         let alloc_size = if remainder == 0 {
            raw_size
         } else {
            raw_size
               .checked_add(align_req - remainder)
               .ok_or(Error::AllocationFailed)?
         };

         let ptr_opt = if supports_memfd_secret {
            unsafe { memsec::memfd_secret_sized(alloc_size) }
         } else {
            None
         };

         if let Some(raw_ptr_nonnull) = ptr_opt {
            let raw_ptr = raw_ptr_nonnull.as_ptr() as *mut u8;

            // Write the MEMFD tag
            unsafe { *(raw_ptr as *mut usize) = ALLOC_TAG_MEMFD };

            let user_ptr = unsafe { raw_ptr.add(header_offset) as *mut T };
            return NonNull::new(user_ptr).ok_or(Error::NullAllocation);
         }

         unsafe {
            let allocated_ptr = memsec::malloc_sized(alloc_size);
            let non_null = allocated_ptr.ok_or(Error::AllocationFailed)?;

            let raw_ptr = non_null.as_ptr() as *mut u8;

            // Write the MALLOC tag
            *(raw_ptr as *mut usize) = ALLOC_TAG_MALLOC;

            let user_ptr = raw_ptr.add(header_offset) as *mut T;
            NonNull::new(user_ptr).ok_or(Error::NullAllocation)
         }
      }
   }

   #[cfg(not(feature = "use_os"))]
   {
      use core::alloc::Layout;
      let layout =
         Layout::from_size_align(size, mem::align_of::<T>()).map_err(|_| Error::AlignmentFailed)?;
      let ptr = unsafe { alloc::alloc(layout) as *mut T };
      if ptr.is_null() {
         return Err(Error::NullAllocation);
      }
      unsafe { NonNull::new_unchecked(ptr) }
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
      let header_offset = get_header_offset::<T>();

      unsafe {
         let user_ptr = ptr.as_ptr() as *mut u8;
         let raw_ptr = user_ptr.sub(header_offset);

         // Reconstruct the NonNull pointer to the START of the allocation (header)
         let non_null_raw = NonNull::new_unchecked(raw_ptr);

         // Read the tag
         let tag = *(raw_ptr as *const usize);

         match tag {
            ALLOC_TAG_MEMFD => {
               memsec::free_memfd_secret(non_null_raw);
            }
            ALLOC_TAG_MALLOC => {
               memsec::free(non_null_raw);
            }
            _ => {
               // SHOULD NOT HAPPEN
               // Tag mismatch: Double free or corruption.
               #[cfg(debug_assertions)]
               panic!(
                  "SecureAllocator: Corrupt header tag found: {:x}",
                  tag
               );
            }
         }
      }
   }
}

#[cfg(feature = "use_os")]
pub(crate) fn mprotect<T>(ptr: NonNull<T>, prot: Prot::Ty) -> bool {
   #[cfg(unix)]
   {
      // We need to protect the whole block, including the header.
      let header_offset = get_header_offset::<T>();
      unsafe {
         let raw_ptr = (ptr.as_ptr() as *mut u8).sub(header_offset);
         let raw_non_null = NonNull::new_unchecked(raw_ptr as *mut T);

         memsec::mprotect(raw_non_null, prot)
      }
   }
   #[cfg(windows)]
   {
      unsafe { memsec::mprotect(ptr, prot) }
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
