pub mod string;
pub mod vec;

pub use string::SecureString;
pub use vec::{SecureBytes, SecureVec};

pub use memsec;
pub use zeroize::Zeroize;

use thiserror::Error as ThisError;

#[derive(ThisError, Debug)]
pub enum Error {
   #[error("Failed to allocate secure memory")]
   AllocationFailed,
   #[error("Allocated Ptr is null")]
   NullAllocation,
   #[error("Failed to lock memory")]
   LockFailed,
   #[error("Failed to unlock memory")]
   UnlockFailed,
}


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
