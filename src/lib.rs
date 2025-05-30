pub mod string;
pub mod vec;

pub use string::SecureString;
pub use vec::{SecureBytes, SecureVec};

use core::ptr::NonNull;
pub use memsec;
use memsec::Prot;
pub use zeroize::Zeroize;

use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum Error {
   #[error("Failed to allocate secure memory")]
   AllocationFailed,
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
}

#[cfg(all(test, windows))]
use windows_sys::Win32::Foundation::GetLastError;
#[cfg(windows)]
use windows_sys::Win32::Security::Cryptography::{
   CRYPTPROTECTMEMORY_BLOCK_SIZE, CRYPTPROTECTMEMORY_SAME_PROCESS, CryptProtectMemory,
   CryptUnprotectMemory,
};
#[cfg(windows)]
use windows_sys::Win32::System::SystemInformation::GetSystemInfo;

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

pub fn mprotect<T>(ptr: NonNull<T>, prot: Prot::Ty) -> bool {
   let success = unsafe { memsec::mprotect(ptr, prot) };
   if !success {
      #[cfg(test)]
      eprintln!("mprotect failed");
   }
   success
}

#[cfg(windows)]
pub fn crypt_protect_memory(ptr: *mut u8, size_in_bytes: usize) -> bool {
   if size_in_bytes == 0 {
      return true; // Nothing to encrypt
   }

   if size_in_bytes % (CRYPTPROTECTMEMORY_BLOCK_SIZE as usize) != 0 {
      // not a multiple of CRYPTPROTECTMEMORY_BLOCK_SIZE
      return false;
   }

   if size_in_bytes > u32::MAX as usize {
      return false;
   }

   let result = unsafe {
      CryptProtectMemory(
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
            "CryptProtectMemory failed with error code: {}",
            error_code
         );
      }
      return false;
   } else {
      true
   }
}

#[cfg(windows)]
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
      return false;
   } else {
      true
   }
}
