#[cfg(not(feature = "use_os"))]
use alloc::{Layout, alloc, dealloc};

use super::{Error, SecureVec};
use core::{marker::PhantomData, mem, ptr::NonNull};
use zeroize::Zeroize;

#[cfg(feature = "use_os")]
use super::{alloc, free};
#[cfg(feature = "use_os")]
use memsec::Prot;

/// A fixed-size array allocated in a secure memory region.
///
/// ## Security Model
///
/// When compiled with the `use_os` feature (the default), it provides several layers of protection:
/// - **Zeroization on Drop**: The memory is zeroized when the array is dropped.
/// - **Memory Locking**: The underlying memory pages are locked using `mlock` & `madvise` for (Unix) or
///   `VirtualLock` & `VirtualProtect` for (Windows) to prevent the OS from memory-dump/swap to disk or other processes accessing the memory.
///
/// In a `no_std` environment, it falls back to providing only the **zeroization-on-drop** guarantee.
///
/// # Program Termination
///
/// Direct indexing (e.g., `array[0]`) on a locked array will cause the operating system
/// to terminate the process with an access violation error. Always use the provided
/// scope methods (`unlock`, `unlock_mut`) for safe access.
///
/// # Notes
///
/// If you return a new allocated `[T; LENGTH]` from one of the unlock methods you are responsible for zeroizing the memory.
///
/// # Example
///
/// ```
/// use secure_types::{SecureArray, Zeroize};
///
/// let exposed_key: &mut [u8; 32] = &mut [1u8; 32];
/// let secure_key: SecureArray<u8, 32> = SecureArray::from_slice_mut(exposed_key).unwrap();
///
/// secure_key.unlock(|unlocked_slice| {
///     assert_eq!(unlocked_slice.len(), 32);
///     assert_eq!(unlocked_slice[0], 1);
/// });
///
/// // Not recommended but if you allocate a new [u8; LENGTH] make sure to zeroize it
/// let mut exposed = secure_key.unlock(|unlocked_slice| {
///     [unlocked_slice[0], unlocked_slice[1], unlocked_slice[2]]
/// });
///
/// // Do what you need to to do with the new array
/// // When you are done with it, zeroize it
/// exposed.zeroize();
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
   ///
   /// The memory is allocated but not initialized, and it's the caller's responsibility to fill it.
   pub fn empty() -> Result<Self, Error> {
      let size = LENGTH * mem::size_of::<T>();
      if size == 0 {
         // Cannot create a zero-sized secure array
         return Err(Error::LengthCannotBeZero);
      }

      let ptr = unsafe { alloc::<T>(size)? };

      let secure_array = SecureArray {
         ptr,
         _marker: PhantomData,
      };

      let locked = secure_array.lock_memory();

      #[cfg(feature = "use_os")]
      if !locked {
         return Err(Error::LockFailed);
      }

      Ok(secure_array)
   }

   /// Creates a new SecureArray from a `&mut [T; LENGTH]`.
   ///
   /// The passed slice is zeroized afterwards
   pub fn from_slice_mut(content: &mut [T; LENGTH]) -> Result<Self, Error> {
      let secure_array = Self::empty()?;

      let unlocked = secure_array.unlock_memory();

      if !unlocked {
         return Err(Error::UnlockFailed);
      }

      unsafe {
         // Copy the data from the source array into the secure memory region
         core::ptr::copy_nonoverlapping(
            content.as_ptr(),
            secure_array.ptr.as_ptr(),
            LENGTH,
         );
      }

      content.zeroize();

      let locked = secure_array.lock_memory();

      #[cfg(feature = "use_os")]
      if !locked {
         return Err(Error::LockFailed);
      }

      Ok(secure_array)
   }

   /// Creates a new SecureArray from a `&[T; LENGTH]`.
   ///
   /// The array is not zeroized, you are responsible for zeroizing it
   pub fn from_slice(content: &[T; LENGTH]) -> Result<Self, Error> {
      let secure_array = Self::empty()?;

      let unlocked = secure_array.unlock_memory();

      if !unlocked {
         return Err(Error::UnlockFailed);
      }

      unsafe {
         // Copy the data from the source array into the secure memory region
         core::ptr::copy_nonoverlapping(
            content.as_ptr(),
            secure_array.ptr.as_ptr(),
            LENGTH,
         );
      }

      let locked = secure_array.lock_memory();

      #[cfg(feature = "use_os")]
      if !locked {
         return Err(Error::LockFailed);
      }

      Ok(secure_array)
   }

   pub fn len(&self) -> usize {
      LENGTH
   }

   pub fn is_empty(&self) -> bool {
      self.len() == 0
   }

   pub(crate) fn lock_memory(&self) -> bool {
      #[cfg(feature = "use_os")]
      {
         #[cfg(windows)]
         {
            super::mprotect(self.ptr, Prot::NoAccess)
         }
         #[cfg(unix)]
         {
            super::mprotect(self.ptr, Prot::NoAccess)
         }
      }
      #[cfg(not(feature = "use_os"))]
      {
         true // No-op: always "succeeds"
      }
   }

   pub(crate) fn unlock_memory(&self) -> bool {
      #[cfg(feature = "use_os")]
      {
         #[cfg(windows)]
         {
            super::mprotect(self.ptr, Prot::ReadWrite)
         }
         #[cfg(unix)]
         {
            super::mprotect(self.ptr, Prot::ReadWrite)
         }
      }

      #[cfg(not(feature = "use_os"))]
      {
         true // No-op: always "succeeds"
      }
   }

   /// Immutable access to the array's data as a `&[T]`
   pub fn unlock<F, R>(&self, f: F) -> R
   where
      F: FnOnce(&[T]) -> R,
   {
      self.unlock_memory();
      let slice = unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), LENGTH) };
      let result = f(slice);
      self.lock_memory();
      result
   }

   /// Mutable access to the array's data as a `&mut [T]`
   pub fn unlock_mut<F, R>(&mut self, f: F) -> R
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
      self.unlock_mut(|slice| {
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
         &*ptr
      }
   }
}

impl<T: Zeroize, const LENGTH: usize> core::ops::IndexMut<usize> for SecureArray<T, LENGTH> {
   fn index_mut(&mut self, index: usize) -> &mut Self::Output {
      assert!(index < self.len(), "Index out of bounds");
      unsafe {
         let ptr = self.ptr.as_ptr().add(index);
         &mut *ptr
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

      #[cfg(feature = "use_os")]
      free(self.ptr);

      #[cfg(not(feature = "use_os"))]
      {
         let layout = Layout::from_size_align_unchecked(size, mem::align_of::<T>());
         dealloc(self.ptr.as_ptr() as *mut u8, layout);
      }
   }
}

impl<T: Clone + Zeroize, const LENGTH: usize> Clone for SecureArray<T, LENGTH> {
   fn clone(&self) -> Self {
      let mut new_array = Self::empty().unwrap();
      self.unlock(|src_slice| {
         new_array.unlock_mut(|dest_slice| {
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
   ///
   /// The `SecureVec` is consumed.
   fn try_from(vec: SecureVec<u8>) -> Result<Self, Self::Error> {
      if vec.len() != LENGTH {
         return Err(Error::LengthMismatch);
      }

      let mut new_array = Self::empty()?;

      vec.unlock_slice(|vec_slice| {
         new_array.unlock_mut(|array_slice| {
            array_slice.copy_from_slice(vec_slice);
         });
      });

      Ok(new_array)
   }
}

#[cfg(feature = "serde")]
impl<const LENGTH: usize> serde::Serialize for SecureArray<u8, LENGTH> {
   fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
   where
      S: serde::Serializer,
   {
      self.unlock(|slice| serializer.collect_seq(slice.iter()))
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

#[cfg(all(test, feature = "use_os"))]
mod tests {
   use super::*;
   use std::process::{Command, Stdio};
   use std::sync::{Arc, Mutex};

   #[test]
   fn test_creation() {
      let exposed_mut = &mut [1, 2, 3];
      let array: SecureArray<u8, 3> = SecureArray::from_slice_mut(exposed_mut).unwrap();
      assert_eq!(array.len(), 3);

      array.unlock(|slice| {
         assert_eq!(slice, &[1, 2, 3]);
      });

      assert_eq!(exposed_mut, &[0u8; 3]);

      let exposed = &[1, 2, 3];
      let array: SecureArray<u8, 3> = SecureArray::from_slice(exposed).unwrap();
      assert_eq!(array.len(), 3);

      array.unlock(|slice| {
         assert_eq!(slice, &[1, 2, 3]);
      });

      assert_eq!(exposed, &[1, 2, 3]);
   }

   #[test]
   fn test_from_secure_vec() {
      let vec: SecureVec<u8> = SecureVec::from_slice(&[1, 2, 3]).unwrap();
      let array: SecureArray<u8, 3> = vec.try_into().unwrap();
      assert_eq!(array.len(), 3);
      array.unlock(|slice| {
         assert_eq!(slice, &[1, 2, 3]);
      });
   }

   #[test]
   fn test_erase() {
      let exposed: &mut [u8; 3] = &mut [1, 2, 3];
      let mut array: SecureArray<u8, 3> = SecureArray::from_slice_mut(exposed).unwrap();
      array.erase();
      array.unlock(|slice| {
         assert_eq!(slice, &[0u8; 3]);
      });
   }

   #[test]
   #[should_panic]
   fn test_length_cannot_be_zero() {
      let secure_vec = SecureVec::new().unwrap();
      let _secure_array: SecureArray<u8, 0> = SecureArray::try_from(secure_vec).unwrap();
   }

   #[test]
   fn lock_unlock() {
      let exposed: &mut [u8; 3] = &mut [1, 2, 3];
      let secure: SecureArray<u8, 3> = SecureArray::from_slice_mut(exposed).unwrap();

      let unlocked = secure.unlock_memory();
      assert!(unlocked);

      let locked = secure.lock_memory();
      assert!(locked);
   }

   #[test]
   fn test_clone() {
      let mut array1: SecureArray<u8, 3> = SecureArray::empty().unwrap();
      array1.unlock_mut(|slice| {
         slice[0] = 1;
         slice[1] = 2;
         slice[2] = 3;
      });

      let array2 = array1.clone();

      array2.unlock(|slice| {
         assert_eq!(slice, &[1, 2, 3]);
      });

      array1.unlock(|slice| {
         assert_eq!(slice, &[1, 2, 3]);
      });
   }

   #[test]
   fn test_thread_safety() {
      let exposed: &mut [u8; 3] = &mut [1, 2, 3];
      let array: SecureArray<u8, 3> = SecureArray::from_slice_mut(exposed).unwrap();
      let arc_array = Arc::new(Mutex::new(array));
      let mut handles = Vec::new();

      for _ in 0..5u8 {
         let array_clone = Arc::clone(&arc_array);
         let handle = std::thread::spawn(move || {
            let mut guard = array_clone.lock().unwrap();
            guard.unlock_mut(|slice| {
               slice[0] += 1;
            });
         });
         handles.push(handle);
      }

      for handle in handles {
         handle.join().unwrap();
      }

      let final_array = arc_array.lock().unwrap();
      final_array.unlock(|slice| {
         assert_eq!(slice[0], 6);
         assert_eq!(slice[1], 2);
         assert_eq!(slice[2], 3);
      });
   }

   #[test]
   fn test_index_should_fail_when_locked() {
      let arg = "CRASH_TEST_ARRAY_LOCKED";

      if std::env::args().any(|a| a == arg) {
         let exposed: &mut [u8; 3] = &mut [1, 2, 3];
         let array: SecureArray<u8, 3> = SecureArray::from_slice_mut(exposed).unwrap();
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
   fn test_unlock_mut() {
      let exposed: &mut [u8; 3] = &mut [1, 2, 3];
      let mut array: SecureArray<u8, 3> = SecureArray::from_slice_mut(exposed).unwrap();

      array.unlock_mut(|slice| {
         slice[1] = 100;
      });

      array.unlock(|slice| {
         assert_eq!(slice, &[1, 100, 3]);
      });
   }

   #[cfg(feature = "serde")]
   #[test]
   fn test_serde() {
      let exposed: &mut [u8; 3] = &mut [1, 2, 3];
      let array: SecureArray<u8, 3> = SecureArray::from_slice_mut(exposed).unwrap();
      let json_string = serde_json::to_string(&array).expect("Serialization failed");
      let json_bytes = serde_json::to_vec(&array).expect("Serialization failed");

      let deserialized_string: SecureArray<u8, 3> =
         serde_json::from_str(&json_string).expect("Deserialization failed");

      let deserialized_bytes: SecureArray<u8, 3> =
         serde_json::from_slice(&json_bytes).expect("Deserialization failed");

      deserialized_string.unlock(|slice| {
         assert_eq!(slice, &[1, 2, 3]);
      });

      deserialized_bytes.unlock(|slice| {
         assert_eq!(slice, &[1, 2, 3]);
      });
   }
}
