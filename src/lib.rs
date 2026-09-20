#![doc = include_str!("../readme.md")]
// no_std is implied whenever `use_os` is not active.
// `use_os` is the default feature — see Cargo.toml.
#![cfg_attr(not(feature = "use_os"), no_std)]

#[cfg(not(feature = "use_os"))]
extern crate alloc;

pub mod array;
#[cfg(feature = "codec")]
pub mod codec;
pub mod string;
pub mod vec;
#[cfg(feature = "use_os")]
pub mod writer;

pub use array::SecureArray;
pub use string::SecureString;
pub use vec::{SecureBytes, SecureVec};
#[cfg(feature = "use_os")]
pub use writer::SecureBytesWriter;

#[cfg(feature = "serde")]
pub use vec::SeqElement;

#[cfg(feature = "codec")]
pub use codec::{
   DecodeError, EncodeError, FORMAT_VERSION, decode, decode_slice, encode, encode_into_vec,
   encode_to_vec, encode_to_vec_with_capacity, encode_with_capacity,
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
// `memfd_secret` is a Linux-only allocator, so the tag that selects it — and the
// availability probe that caches whether it exists — are only meaningful there.
#[cfg(all(feature = "use_os", target_os = "linux"))]
const ALLOC_TAG_MEMFD: usize = 0x5EC0_0000;

#[cfg(all(feature = "use_os", target_os = "linux"))]
use core::sync::atomic::{AtomicU8, Ordering};

#[cfg(all(feature = "use_os", target_os = "linux"))]
static MEMFD_SECRET_SUPPORT: AtomicU8 = AtomicU8::new(MEMFD_UNKNOWN);
#[cfg(all(feature = "use_os", target_os = "linux"))]
const MEMFD_UNKNOWN: u8 = 0;
#[cfg(all(feature = "use_os", target_os = "linux"))]
const MEMFD_NO: u8 = 1;
#[cfg(all(feature = "use_os", target_os = "linux"))]
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

/// Reports whether the kernel supports `memfd_secret`-backed allocations.
///
/// `memfd_secret` is Linux-only, so this is always `false` on every other
/// target (including non-Linux Unix like macOS and FreeBSD), where the crate
/// falls back to [`memsec::malloc_sized`].
#[cfg(all(feature = "use_os", unix))]
pub fn supports_memfd_secret() -> bool {
   #[cfg(target_os = "linux")]
   {
      match MEMFD_SECRET_SUPPORT.load(Ordering::Relaxed) {
         MEMFD_YES => true,
         MEMFD_NO => false,
         _ => {
            // SAFETY: probes `memfd_secret` with no flags and no pointers; any
            // returned fd is closed immediately.
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

   #[cfg(not(target_os = "linux"))]
   {
      false
   }
}

/// Allocate memory
///
/// For `Windows` it always uses [memsec::malloc_sized]
///
/// For `Linux` it uses [memsec::memfd_secret_sized] if `memfd_secret` is supported
///
/// For every other `Unix` (macOS, FreeBSD, …) it uses [memsec::malloc_sized]:
/// `memfd_secret` is Linux-only.
///
/// If the allocation fails it fallbacks to [memsec::malloc_sized]
pub(crate) unsafe fn alloc<T>(size: usize) -> Result<NonNull<T>, Error> {
   #[cfg(feature = "use_os")]
   {
      if size == 0 {
         return Err(Error::SizeCannotBeZero);
      }

      #[cfg(windows)]
      // SAFETY: `size != 0` was checked above; `malloc_sized` returns either a
      // valid pointer to `size` bytes or `None`, and the pointer is re-checked.
      unsafe {
         let allocated_ptr = memsec::malloc_sized(size);
         let non_null = allocated_ptr.ok_or(Error::AllocationFailed)?;
         let ptr = non_null.as_ptr() as *mut T;
         NonNull::new(ptr).ok_or(Error::NullAllocation)
      }

      #[cfg(unix)]
      {
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

         // `memfd_secret` is Linux-only; everywhere else the malloc fallback
         // below is the sole allocator, so the probe and the tag are compiled out.
         #[cfg(target_os = "linux")]
         {
            let ptr_opt = if supports_memfd_secret() {
               // SAFETY: `memsec` allocation of the byte count computed above;
               // its result is checked for null before use.
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

               // SAFETY: `raw_ptr` is `memsec`'s user pointer for a live
               // `alloc_size`-byte allocation, aligned for a `usize` (asserted
               // above). The tag goes at offset 0 and the user region starts at
               // `header_offset`, which `alloc_size` reserves — both in bounds.
               unsafe { *(raw_ptr as *mut usize) = ALLOC_TAG_MEMFD };

               // SAFETY: `header_offset <= alloc_size`, so the offset pointer
               // stays inside the allocation.
               let user_ptr = unsafe { raw_ptr.add(header_offset) as *mut T };
               return NonNull::new(user_ptr).ok_or(Error::NullAllocation);
            }
         }

         // SAFETY: as in the memfd branch — `memsec`'s user pointer for an
         // `alloc_size`-byte allocation, aligned for the `usize` tag, with the tag
         // at offset 0 and the user region at `header_offset`.
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
      // `alloc::alloc::alloc` requires a non-zero-size layout, so a zero-sized
      // `T` (a ZST, where `capacity * size_of::<T>() == 0`) must be rejected
      // rather than handed to it. `use_os` refuses the same input.
      if size == 0 {
         return Err(Error::SizeCannotBeZero);
      }

      let layout = core::alloc::Layout::from_size_align(size, core::mem::align_of::<T>())
         .map_err(|_| Error::AlignmentFailed)?;
      // SAFETY: `size != 0` was checked just above, so the `Layout` is valid for
      // `alloc`, which returns either an aligned pointer or null.
      let ptr = unsafe { alloc::alloc::alloc(layout) as *mut T };
      if ptr.is_null() {
         return Err(Error::NullAllocation);
      }
      // SAFETY: the null case returned above, so `ptr` is non-null.
      unsafe { Ok(NonNull::new_unchecked(ptr)) }
   }
}

#[cfg(feature = "use_os")]
pub(crate) fn free<T>(ptr: NonNull<T>) {
   #[cfg(windows)]
   // SAFETY: `ptr` was returned by `memsec::malloc_sized` in `alloc` and is freed
   // exactly once here, so `memsec::free` receives the pointer it handed out.
   unsafe {
      memsec::free(ptr);
   }

   #[cfg(unix)]
   {
      let header_offset = get_header_offset::<T>();

      // SAFETY: `ptr` is this allocation's user pointer, so `ptr - header_offset`
      // is exactly the pointer `memsec` returned; `alloc` wrote the tag there, so
      // reading it back and dispatching to the matching deallocator is sound. The
      // allocation is freed exactly once (this consumes the `NonNull`).
      unsafe {
         let user_ptr = ptr.as_ptr() as *mut u8;
         let raw_ptr = user_ptr.sub(header_offset);

         // Reconstruct the NonNull pointer to the START of the allocation (header)
         let non_null_raw = NonNull::new_unchecked(raw_ptr);

         // Read the tag
         let tag = *(raw_ptr as *const usize);

         match tag {
            #[cfg(target_os = "linux")]
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
      // SAFETY: `ptr - header_offset` is the pointer `memsec` returned (see
      // `alloc`), which is what `memsec::mprotect` expects, and `prot` is a valid
      // `Prot` value. The block stays allocated while `ptr` is live.
      unsafe {
         let raw_ptr = (ptr.as_ptr() as *mut u8).sub(header_offset);
         let raw_non_null = NonNull::new_unchecked(raw_ptr as *mut T);

         memsec::mprotect(raw_non_null, prot)
      }
   }
   #[cfg(windows)]
   {
      // SAFETY: `ptr` is a live `memsec` allocation and `prot` a valid `Prot`.
      unsafe { memsec::mprotect(ptr, prot) }
   }
}
