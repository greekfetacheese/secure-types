#![doc = include_str!("../readme.md")]
// no_std is implied whenever `use_os` is not active.
// `use_os` is the default feature — see Cargo.toml.
#![cfg_attr(not(feature = "use_os"), no_std)]

#[cfg(not(feature = "use_os"))]
extern crate alloc;

pub mod array;
pub mod string;
pub mod vec;
#[cfg(feature = "use_os")]
pub mod writer;

#[cfg(all(feature = "use_os", feature = "serde_json"))]
pub mod json;

pub use array::SecureArray;
pub use string::SecureString;
pub use vec::{SecureBytes, SecureVec};
#[cfg(feature = "use_os")]
pub use writer::SecureBytesWriter;

#[cfg(all(feature = "use_os", feature = "serde_json"))]
pub use json::{
   JsonError, serialize_json_into_secure_bytes, serialize_json_into_secure_bytes_with_capacity,
   serialize_json_into_secure_string, serialize_json_into_secure_string_with_capacity,
};

use core::ptr::NonNull;
pub use zeroize::Zeroize;

#[cfg(feature = "use_os")]
pub use memsec;
#[cfg(feature = "use_os")]
use memsec::Prot;

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum Error {
   AllocationFailed,
   LengthCannotBeZero,
   SizeCannotBeZero,
   NullAllocation,
   LockFailed,
   UnlockFailed,
   LengthMismatch,
   InvalidUtf8,
   AlignmentFailed,
}

impl core::fmt::Display for Error {
   fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
      match self {
         Self::AllocationFailed => write!(f, "Failed to allocate memory"),
         Self::LengthCannotBeZero => write!(f, "Length cannot be zero"),
         Self::SizeCannotBeZero => write!(f, "Size cannot be zero"),
         Self::NullAllocation => write!(f, "Allocated Ptr is null"),
         Self::LockFailed => write!(f, "Failed to lock memory"),
         Self::UnlockFailed => write!(f, "Failed to unlock memory"),
         Self::LengthMismatch => {
            write!(
               f,
               "Source length does not match the fixed size of the destination array"
            )
         }
         Self::InvalidUtf8 => write!(f, "Bytes are not valid UTF-8"),
         Self::AlignmentFailed => write!(f, "Failed to satisfy allocation alignment"),
      }
   }
}

impl core::error::Error for Error {}

#[cfg(all(feature = "use_os", unix))]
const ALLOC_TAG_MALLOC: usize = 0xDEAD_BEEF;
#[cfg(all(feature = "use_os", unix))]
const ALLOC_TAG_MEMFD: usize = 0x5EC0_0000;

#[cfg(all(feature = "use_os", unix))]
use core::sync::atomic::{AtomicU8, Ordering};

#[cfg(all(feature = "use_os", unix))]
static MEMFD_SECRET_SUPPORT: AtomicU8 = AtomicU8::new(MEMFD_UNKNOWN);
#[cfg(all(feature = "use_os", unix))]
const MEMFD_UNKNOWN: u8 = 0;
#[cfg(all(feature = "use_os", unix))]
const MEMFD_NO: u8 = 1;
#[cfg(all(feature = "use_os", unix))]
const MEMFD_YES: u8 = 2;

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
pub fn supports_memfd_secret() -> bool {
   match MEMFD_SECRET_SUPPORT.load(Ordering::Relaxed) {
      MEMFD_YES => true,
      MEMFD_NO => false,
      _ => {
         let supported = unsafe {
            use libc::{SYS_memfd_secret, close, syscall};
            let res = syscall(SYS_memfd_secret as _, 0isize);
            if res >= 0 {
               close(res as libc::c_int);
               true
            } else {
               false
            }
         };
         MEMFD_SECRET_SUPPORT.store(
            if supported { MEMFD_YES } else { MEMFD_NO },
            Ordering::Relaxed,
         );
         supported
      }
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
      if size == 0 {
         return Err(Error::SizeCannotBeZero);
      }

      #[cfg(windows)]
      unsafe {
         let allocated_ptr = memsec::malloc_sized(size);
         let non_null = allocated_ptr.ok_or(Error::AllocationFailed)?;
         let ptr = non_null.as_ptr() as *mut T;
         NonNull::new(ptr).ok_or(Error::NullAllocation)
      }

      #[cfg(unix)]
      {
         let supports_memfd_secret = supports_memfd_secret();

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

            debug_assert!(
               (raw_ptr as usize).is_multiple_of(core::mem::align_of::<usize>()),
               "allocator returned a pointer not aligned for the usize header tag"
            );

            // Write the MEMFD tag
            unsafe { *(raw_ptr as *mut usize) = ALLOC_TAG_MEMFD };

            let user_ptr = unsafe { raw_ptr.add(header_offset) as *mut T };
            return NonNull::new(user_ptr).ok_or(Error::NullAllocation);
         }

         unsafe {
            let allocated_ptr = memsec::malloc_sized(alloc_size);
            let non_null = allocated_ptr.ok_or(Error::AllocationFailed)?;

            let raw_ptr = non_null.as_ptr() as *mut u8;

            debug_assert!(
               (raw_ptr as usize).is_multiple_of(core::mem::align_of::<usize>()),
               "allocator returned a pointer not aligned for the usize header tag"
            );

            // Write the MALLOC tag
            *(raw_ptr as *mut usize) = ALLOC_TAG_MALLOC;

            let user_ptr = raw_ptr.add(header_offset) as *mut T;
            NonNull::new(user_ptr).ok_or(Error::NullAllocation)
         }
      }
   }

   #[cfg(not(feature = "use_os"))]
   {
      let layout = core::alloc::Layout::from_size_align(size, core::mem::align_of::<T>())
         .map_err(|_| Error::AlignmentFailed)?;
      let ptr = unsafe { alloc::alloc::alloc(layout) as *mut T };
      if ptr.is_null() {
         return Err(Error::NullAllocation);
      }
      unsafe { Ok(NonNull::new_unchecked(ptr)) }
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
               // Tag mismatch: double free or a corrupted header. Freeing through
               // the wrong allocator would be worse, and silently doing nothing
               // leaks the allocation, so fail loudly in every profile — memsec
               // itself aborts on a canary mismatch.
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

   // `memsec` and `supports_memfd_secret` only exist with OS support, so this test
   // is gated like the ones in the other modules.
   #[cfg(all(unix, feature = "use_os"))]
   #[test]
   fn test_supports_memfd_secret() {
      use super::*;

      let supports = supports_memfd_secret();

      if supports {
         print!("memfd_secret is supported");
         let size = size_of::<u8>();
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

/// Minimal [`serde::Deserializer`]s that hand the value to the owned-input visitor
/// methods (`visit_string` / `visit_byte_buf`). `serde_json` never calls those, so
/// without these the "wipe the buffer the format gave us" paths would be untested.
#[cfg(all(test, feature = "serde", feature = "use_os"))]
pub(crate) mod test_support {
   #[cfg(not(feature = "use_os"))]
   use alloc::{string::String, vec::Vec};

   /// Owns a `String` and yields it through `visit_string`.
   pub(crate) struct OwnedString(pub(crate) String);

   /// Owns a `Vec<u8>` and yields it through `visit_byte_buf`.
   pub(crate) struct OwnedBytes(pub(crate) Vec<u8>);

   impl<'de> serde::Deserializer<'de> for OwnedString {
      type Error = serde::de::value::Error;

      fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
      where
         V: serde::de::Visitor<'de>,
      {
         visitor.visit_string(self.0)
      }

      serde::forward_to_deserialize_any! {
         bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
         bytes byte_buf option unit unit_struct newtype_struct seq tuple
         tuple_struct map struct enum identifier ignored_any
      }
   }

   impl<'de> serde::Deserializer<'de> for OwnedBytes {
      type Error = serde::de::value::Error;

      fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
      where
         V: serde::de::Visitor<'de>,
      {
         visitor.visit_byte_buf(self.0)
      }

      serde::forward_to_deserialize_any! {
         bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
         bytes byte_buf option unit unit_struct newtype_struct seq tuple
         tuple_struct map struct enum identifier ignored_any
      }
   }
}
