#[cfg(not(feature = "std"))]
use alloc::{Layout, alloc, dealloc};

use super::{Error, SecureVec};
use core::{marker::PhantomData, mem, ptr::NonNull};
use zeroize::Zeroize;

#[cfg(feature = "std")]
use super::page_aligned_size;
#[cfg(feature = "std")]
use memsec::Prot;

/// A fixed-size array allocated in a secure memory region.
///
/// `SecureArray` provides the same core security guarantees as the other types in this
/// crate, including zeroization on drop and optional memory locking/encryption when
// compiled with the `std` feature.
///
/// It is ideal for secrets of a known, fixed length.
///
/// # Program Termination
///
/// Direct indexing (e.g., `array[0]`) on a locked array will cause the operating system
/// to terminate the process with an access violation error. Always use the provided
/// scope methods (`unlocked_scope`, `unlocked_mut_scope`) for safe access.
///
/// # Examples
///
/// ```
/// use secure_types::SecureArray;
///
/// let key_data = [1u8; 32];
/// let secure_key: SecureArray<u8, 32> = SecureArray::new(key_data).unwrap();
///
/// secure_key.unlocked_scope(|unlocked_slice| {
///     assert_eq!(unlocked_slice.len(), 32);
///     assert_eq!(unlocked_slice[0], 1);
/// });
/// ```
pub struct SecureArray<T, const LENGTH: usize>
where
   T: Zeroize,
{
   ptr: NonNull<T>,
   _marker: PhantomData<T>,
}

unsafe impl<T: Zeroize + Send, const LENGTH: usize> Send for SecureArray<T, LENGTH> {}
unsafe impl<T: Zeroize + Send + Sync, const LENGTH: usize> Sync for SecureArray<T, LENGTH> {}

impl<T, const LENGTH: usize> SecureArray<T, LENGTH>
where
   T: Zeroize,
{
   /// Creates an empty (but allocated) SecureArray.
   /// The memory is allocated but not initialized, and it's the caller's responsibility to fill it.
   pub fn empty() -> Result<Self, Error> {
      let size = LENGTH * mem::size_of::<T>();
      if size == 0 {
         // Cannot create a zero-sized secure array
         return Err(Error::AllocationFailed);
      }

      #[cfg(feature = "std")]
      let new_ptr = {
         let aligned_size = page_aligned_size(size);
         let allocated_ptr = unsafe { memsec::malloc_sized(aligned_size) };
         allocated_ptr.ok_or(Error::AllocationFailed)?.as_ptr() as *mut T
      };

      #[cfg(not(feature = "std"))]
      let new_ptr = {
         let layout = Layout::from_size_align(size, mem::align_of::<T>())
            .map_err(|_| Error::AllocationFailed)?;
         let ptr = unsafe { alloc::alloc(layout) as *mut T };
         if ptr.is_null() {
            return Err(Error::AllocationFailed);
         }
         ptr
      };

      let non_null = NonNull::new(new_ptr).ok_or(Error::NullAllocation)?;

      let secure_array = SecureArray {
         ptr: non_null,
         _marker: PhantomData,
      };

      let (encrypted, locked) = secure_array.lock_memory();

      #[cfg(feature = "std")]
      if !locked {
         return Err(Error::LockFailed);
      }

      #[cfg(feature = "std")]
      if !encrypted {
         return Err(Error::CryptProtectMemoryFailed);
      }

      Ok(secure_array)
   }

   /// Creates a new SecureArray from a given array.
   pub fn new(mut content: [T; LENGTH]) -> Result<Self, Error> {
      let secure_array = Self::empty()?;

      secure_array.unlock_memory();

      unsafe {
         // Copy the data from the source array into the secure memory region
         core::ptr::copy_nonoverlapping(
            content.as_ptr(),
            secure_array.ptr.as_ptr(),
            LENGTH,
         );
      }

      content.zeroize();

      let (encrypted, locked) = secure_array.lock_memory();

      #[cfg(feature = "std")]
      if !locked {
         return Err(Error::LockFailed);
      }

      #[cfg(feature = "std")]
      if !encrypted {
         return Err(Error::CryptProtectMemoryFailed);
      }

      Ok(secure_array)
   }

   pub fn len(&self) -> usize {
      LENGTH
   }

   pub fn as_ptr(&self) -> *const T {
      self.ptr.as_ptr()
   }

   pub fn as_mut_ptr(&mut self) -> *mut u8 {
      self.ptr.as_ptr() as *mut u8
   }

   #[allow(dead_code)]
   fn aligned_size(&self) -> usize {
      let size = self.len() * mem::size_of::<T>();
      #[cfg(feature = "std")]
      {
         page_aligned_size(size)
      }
      #[cfg(not(feature = "std"))]
      {
         size // No page alignment in no_std
      }
   }

   #[cfg(all(feature = "std", windows))]
   fn encypt_memory(&self) -> bool {
      let ptr = self.as_ptr() as *mut u8;
      super::crypt_protect_memory(ptr, self.aligned_size())
   }

   #[cfg(all(feature = "std", windows))]
   fn decrypt_memory(&self) -> bool {
      let ptr = self.as_ptr() as *mut u8;
      super::crypt_unprotect_memory(ptr, self.aligned_size())
   }

   pub(crate) fn lock_memory(&self) -> (bool, bool) {
      #[cfg(feature = "std")]
      {
         #[cfg(windows)]
         {
            let encrypt_ok = self.encypt_memory();
            let mprotect_ok = super::mprotect(self.ptr, Prot::NoAccess);
            (encrypt_ok, mprotect_ok)
         }
         #[cfg(unix)]
         {
            let mprotect_ok = super::mprotect(self.ptr, Prot::NoAccess);
            (true, mprotect_ok)
         }
      }
      #[cfg(not(feature = "std"))]
      {
         (true, true) // No-op: always "succeeds"
      }
   }

   pub(crate) fn unlock_memory(&self) -> (bool, bool) {
      #[cfg(feature = "std")]
      {
         #[cfg(windows)]
         {
            let mprotect_ok = super::mprotect(self.ptr, Prot::ReadWrite);
            if !mprotect_ok {
               return (false, false);
            }
            let decrypt_ok = self.decrypt_memory();
            (decrypt_ok, mprotect_ok)
         }
         #[cfg(unix)]
         {
            let mprotect_ok = super::mprotect(self.ptr, Prot::ReadWrite);
            (true, mprotect_ok)
         }
      }

      #[cfg(not(feature = "std"))]
      {
         (true, true) // No-op: always "succeeds"
      }
   }

   /// Provides scoped, immutable access to the array's data as a slice.
   pub fn unlocked_scope<F, R>(&self, f: F) -> R
   where
      F: FnOnce(&[T]) -> R,
   {
      self.unlock_memory();
      let slice = unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), LENGTH) };
      let result = f(slice);
      self.lock_memory();
      result
   }

   /// Provides scoped, mutable access to the array's data as a mutable slice.
   pub fn unlocked_mut_scope<F, R>(&mut self, f: F) -> R
   where
      F: FnOnce(&mut [T]) -> R,
   {
      self.unlock_memory();
      let slice = unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), LENGTH) };
      let result = f(slice);
      self.lock_memory();
      result
   }

   /// Securely erases the contents of the array by zeroizing the memory.
   pub fn erase(&mut self) {
      self.unlocked_mut_scope(|slice| {
         for element in slice.iter_mut() {
            element.zeroize();
         }
      });
   }
}

impl<T: Zeroize, const LENGTH: usize> core::ops::Index<usize> for SecureArray<T, LENGTH> {
   type Output = T;
   fn index(&self, index: usize) -> &Self::Output {
      assert!(index < self.len(), "Index out of bounds");
      unsafe {
         let ptr = self.ptr.as_ptr().add(index);
         let reference = &*ptr;
         reference
      }
   }
}

impl<T: Zeroize, const LENGTH: usize> core::ops::IndexMut<usize> for SecureArray<T, LENGTH> {
   fn index_mut(&mut self, index: usize) -> &mut Self::Output {
      assert!(index < self.len(), "Index out of bounds");
      unsafe {
         let ptr = self.ptr.as_ptr().add(index);
         let reference = &mut *ptr;
         reference
      }
   }
}

impl<T: Zeroize, const LENGTH: usize> Drop for SecureArray<T, LENGTH> {
   fn drop(&mut self) {
      self.erase();
      self.unlock_memory();

      let size = LENGTH * mem::size_of::<T>();
      if size == 0 {
         return;
      }

      unsafe {
         #[cfg(feature = "std")]
         {
            memsec::free(self.ptr);
         }
         #[cfg(not(feature = "std"))]
         {
            // Recreate the layout to deallocate correctly
            let layout = Layout::from_size_align_unchecked(size, mem::align_of::<T>());
            dealloc(self.ptr.as_ptr() as *mut u8, layout);
         }
      }
   }
}

impl<T: Clone + Zeroize, const LENGTH: usize> Clone for SecureArray<T, LENGTH> {
   fn clone(&self) -> Self {
      let mut new_array = Self::empty().unwrap();
      self.unlocked_scope(|src_slice| {
         new_array.unlocked_mut_scope(|dest_slice| {
            dest_slice.clone_from_slice(src_slice);
         });
      });
      new_array
   }
}

impl<const LENGTH: usize> TryFrom<SecureVec<u8>> for SecureArray<u8, LENGTH> {
   type Error = Error;

   /// Tries to convert a `SecureVec<u8>` into a `SecureArray<u8, LENGTH>`.
   ///
   /// This operation will only succeed if `vec.len() == LENGTH`.
   /// The original `SecureVec` is consumed.
   fn try_from(vec: SecureVec<u8>) -> Result<Self, Self::Error> {
      if vec.len() != LENGTH {
         return Err(Error::LengthMismatch);
      }

      let mut new_array = Self::empty()?;

      vec.slice_scope(|vec_slice| {
         new_array.unlocked_mut_scope(|array_slice| {
            array_slice.copy_from_slice(vec_slice);
         });
      });

      Ok(new_array)
   }
}

impl<T, const LENGTH: usize> TryFrom<[T; LENGTH]> for SecureArray<T, LENGTH>
where
   T: Zeroize,
{
   type Error = Error;
   fn try_from(s: [T; LENGTH]) -> Result<Self, Error> {
      Self::new(s)
   }
}

#[cfg(feature = "serde")]
impl<const LENGTH: usize> serde::Serialize for SecureArray<u8, LENGTH> {
   fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
   where
      S: serde::Serializer,
   {
      self.unlocked_scope(|slice| serializer.collect_seq(slice.iter()))
   }
}

#[cfg(feature = "serde")]
impl<'de, const LENGTH: usize> serde::Deserialize<'de> for SecureArray<u8, LENGTH> {
   fn deserialize<D>(deserializer: D) -> Result<SecureArray<u8, LENGTH>, D::Error>
   where
      D: serde::Deserializer<'de>,
   {
      struct SecureArrayVisitor<const L: usize>;

      impl<'de, const L: usize> serde::de::Visitor<'de> for SecureArrayVisitor<L> {
         type Value = SecureArray<u8, L>;

         fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            write!(formatter, "a byte array of length {}", L)
         }

         fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
         where
            A: serde::de::SeqAccess<'de>,
         {
            let mut data: SecureVec<u8> =
               SecureVec::new_with_capacity(L).map_err(serde::de::Error::custom)?;
            while let Some(byte) = seq.next_element()? {
               data.push(byte);
            }

            // Check that the deserialized data has the exact length required.
            if data.len() != L {
               return Err(serde::de::Error::invalid_length(
                  data.len(),
                  &self,
               ));
            }

            SecureArray::try_from(data).map_err(serde::de::Error::custom)
         }
      }

      deserializer.deserialize_bytes(SecureArrayVisitor::<LENGTH>)
   }
}

#[cfg(all(test, feature = "std"))]
mod tests {
   use super::*;
   use std::process::{Command, Stdio};
   use std::sync::{Arc, Mutex};

   #[test]
   fn test_creation() {
      let array: SecureArray<u8, 3> = SecureArray::new([1, 2, 3]).unwrap();
      assert_eq!(array.len(), 3);
      array.unlocked_scope(|slice| {
         assert_eq!(slice, &[1, 2, 3]);
      });
   }

   #[test]
   fn test_from_secure_vec() {
      let vec: SecureVec<u8> = SecureVec::from_slice(&[1, 2, 3]).unwrap();
      let array: SecureArray<u8, 3> = vec.try_into().unwrap();
      assert_eq!(array.len(), 3);
      array.unlocked_scope(|slice| {
         assert_eq!(slice, &[1, 2, 3]);
      });
   }

   #[test]
   fn test_erase() {
      let mut array: SecureArray<u8, 3> = SecureArray::new([1, 2, 3]).unwrap();
      array.erase();
      array.unlocked_scope(|slice| {
         assert_eq!(slice, &[0u8; 3]);
      });
   }

   #[test]
   fn lock_unlock() {
      let array = [1, 2, 3];
      let secure: SecureArray<u8, 3> = SecureArray::new(array).unwrap();
      let size = secure.aligned_size();
      assert_eq!(size > 0, true);

      let (decrypted, unlocked) = secure.unlock_memory();
      assert!(decrypted);
      assert!(unlocked);

      let (encrypted, locked) = secure.lock_memory();
      assert!(encrypted);
      assert!(locked);

      let secure: SecureArray<u8, 3> = SecureArray::empty().unwrap();
      let size = secure.aligned_size();
      assert_eq!(size > 0, true);

      let (decrypted, unlocked) = secure.unlock_memory();
      assert!(decrypted);
      assert!(unlocked);

      let (encrypted, locked) = secure.lock_memory();
      assert!(encrypted);
      assert!(locked);
   }

   #[test]
   fn test_clone() {
      let mut array1: SecureArray<u8, 3> = SecureArray::empty().unwrap();
      array1.unlocked_mut_scope(|slice| {
         slice[0] = 1;
         slice[1] = 2;
         slice[2] = 3;
      });

      let array2 = array1.clone();

      array2.unlocked_scope(|slice| {
         assert_eq!(slice, &[1, 2, 3]);
      });

      array1.unlocked_scope(|slice| {
         assert_eq!(slice, &[1, 2, 3]);
      });
   }

   #[test]
   fn test_thread_safety() {
      let array = SecureArray::new([1, 2, 3]).unwrap();
      let arc_array = Arc::new(Mutex::new(array));
      let mut handles = Vec::new();

      for _ in 0..5u8 {
         let array_clone = Arc::clone(&arc_array);
         let handle = std::thread::spawn(move || {
            let mut guard = array_clone.lock().unwrap();
            guard.unlocked_mut_scope(|slice| {
               slice[0] += 1;
            });
         });
         handles.push(handle);
      }

      for handle in handles {
         handle.join().unwrap();
      }

      let final_array = arc_array.lock().unwrap();
      final_array.unlocked_scope(|slice| {
         assert_eq!(slice[0], 6);
      });
   }

   #[test]
   fn test_index_should_fail_when_locked() {
      let arg = "CRASH_TEST_ARRAY_LOCKED";

      if std::env::args().any(|a| a == arg) {
         let array: SecureArray<u8, 3> = SecureArray::new([1, 2, 3]).unwrap();
         let _value = core::hint::black_box(array[0]);

         std::process::exit(1);
      }

      let child = Command::new(std::env::current_exe().unwrap())
         .arg("array::tests::test_index_should_fail_when_locked")
         .arg(arg)
         .arg("--nocapture")
         .stdout(Stdio::piped())
         .stderr(Stdio::piped())
         .spawn()
         .expect("Failed to spawn child process");

      let output = child.wait_with_output().expect("Failed to wait on child");
      let status = output.status;

      assert!(
         !status.success(),
         "Process exited successfully with code {:?}, but it should have crashed.",
         status.code()
      );

      #[cfg(unix)]
      {
         use std::os::unix::process::ExitStatusExt;
         let signal = status
            .signal()
            .expect("Process was not terminated by a signal on Unix.");
         assert!(
            signal == libc::SIGSEGV || signal == libc::SIGBUS,
            "Process terminated with unexpected signal: {}",
            signal
         );
         println!(
            "Test passed: Process correctly terminated with signal {}.",
            signal
         );
      }

      #[cfg(windows)]
      {
         const STATUS_ACCESS_VIOLATION: i32 = 0xC0000005_u32 as i32;
         assert_eq!(
            status.code(),
            Some(STATUS_ACCESS_VIOLATION),
            "Process exited with unexpected code: {:x?}. Expected STATUS_ACCESS_VIOLATION.",
            status.code()
         );
         eprintln!("Test passed: Process correctly terminated with STATUS_ACCESS_VIOLATION.");
      }
   }

   #[test]
   fn test_mutable_access_in_scope() {
      let mut array: SecureArray<u8, 3> = SecureArray::new([1, 2, 3]).unwrap();

      array.unlocked_mut_scope(|slice| {
         slice[1] = 100;
      });

      array.unlocked_scope(|slice| {
         assert_eq!(slice, &[1, 100, 3]);
      });
   }

   #[cfg(feature = "serde")]
   #[test]
   fn test_serde() {
      let array: SecureArray<u8, 3> = SecureArray::new([1, 2, 3]).unwrap();
      let json_string = serde_json::to_string(&array).expect("Serialization failed");
      let json_bytes = serde_json::to_vec(&array).expect("Serialization failed");

      let deserialized_string: SecureArray<u8, 3> =
         serde_json::from_str(&json_string).expect("Deserialization failed");

      let deserialized_bytes: SecureArray<u8, 3> =
         serde_json::from_slice(&json_bytes).expect("Deserialization failed");

      deserialized_string.unlocked_scope(|slice| {
         assert_eq!(slice, &[1, 2, 3]);
      });

      deserialized_bytes.unlocked_scope(|slice| {
         assert_eq!(slice, &[1, 2, 3]);
      });
   }
}
