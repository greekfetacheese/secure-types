// No_std: we only need `Layout` for computing allocation sizes.
// We call `alloc::alloc::dealloc` via fully-qualified path to avoid
// shadowing the crate-level `alloc::<T>()` helper.
#[cfg(not(feature = "use_os"))]
use alloc::alloc::Layout;

use super::{Error, SecureVec, alloc};
use core::{marker::PhantomData, mem, ptr::NonNull};
use zeroize::Zeroize;

#[cfg(feature = "use_os")]
use super::free;
#[cfg(feature = "use_os")]
use memsec::Prot;

/// Unlocks the array's memory on construction and re-locks it on drop —
/// including when the drop happens because the fn closure panicked.
struct UnlockGuard<'a, T: Zeroize, const LENGTH: usize> {
   array: &'a SecureArray<T, LENGTH>,
}

impl<'a, T: Zeroize, const LENGTH: usize> UnlockGuard<'a, T, LENGTH> {
   fn new(array: &'a SecureArray<T, LENGTH>) -> Self {
      let ok = array.unlock_memory();
      debug_assert!(ok, "UnlockGuard::new: unlock_memory failed");
      UnlockGuard { array }
   }
}

impl<'a, T: Zeroize, const LENGTH: usize> Drop for UnlockGuard<'a, T, LENGTH> {
   fn drop(&mut self) {
      let ok = self.array.lock_memory();
      debug_assert!(ok, "UnlockGuard::drop: lock_memory failed");
   }
}

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
/// # Security Note
///
/// We intentionally do **not** implement `Index` or `IndexMut`.
/// `array[0]` is a compile error.
///
/// Always use `.unlock()` / `.unlock_mut()` (or the slice variants) to access data.
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

      let _locked = secure_array.lock_memory();

      #[cfg(feature = "use_os")]
      if !_locked {
         return Err(Error::LockFailed);
      }

      Ok(secure_array)
   }

   /// Creates a new SecureArray from a `&mut [T; LENGTH]`.
   ///
   /// The passed slice is zeroized afterwards
   pub fn from_slice_mut(content: &mut [T; LENGTH]) -> Result<Self, Error>
   where
      T: Clone,
   {
      let secure_array = match Self::empty() {
         Ok(secure_array) => secure_array,
         Err(e) => {
            content.zeroize();
            return Err(e);
         }
      };

      let unlocked = secure_array.unlock_memory();

      if !unlocked {
         content.zeroize();
         return Err(Error::UnlockFailed);
      }

      unsafe {
         let dst = secure_array.ptr.as_ptr();
         for (i, item) in content.iter().enumerate() {
            core::ptr::write(dst.add(i), item.clone());
         }
      }

      content.zeroize();

      let _locked = secure_array.lock_memory();

      #[cfg(feature = "use_os")]
      if !_locked {
         return Err(Error::LockFailed);
      }

      Ok(secure_array)
   }

   /// Creates a new SecureArray from a `&[T; LENGTH]`.
   ///
   /// The array is not zeroized, you are responsible for zeroizing it
   pub fn from_slice(content: &[T; LENGTH]) -> Result<Self, Error>
   where
      T: Clone,
   {
      let secure_array = Self::empty()?;

      let unlocked = secure_array.unlock_memory();

      if !unlocked {
         return Err(Error::UnlockFailed);
      }

      unsafe {
         let dst = secure_array.ptr.as_ptr();
         for (i, item) in content.iter().enumerate() {
            core::ptr::write(dst.add(i), item.clone());
         }
      }

      let _locked = secure_array.lock_memory();

      #[cfg(feature = "use_os")]
      if !_locked {
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

   /// Returns the pointer to the locked memory region
   ///
   /// # DANGER
   ///
   /// This is a low-level API, which should be used only for
   /// testing purposes. If you need to access the locked memory
   /// region, use [`unlock`](Self::unlock) or [`unlock_mut`](Self::unlock_mut).
   #[cfg(feature = "expose-ptr")]
   #[deprecated(
      since = "0.3.0",
      note = "This method is intended only for testing/crash reproduction. Use unlock() or unlock_mut() instead."
   )]
   pub fn ptr(&self) -> NonNull<T> {
      self.ptr
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
      let _guard = UnlockGuard::new(self);
      let slice = unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), LENGTH) };
      let result = f(slice);
      result
   }

   /// Mutable access to the array's data as a `&mut [T]`
   pub fn unlock_mut<F, R>(&mut self, f: F) -> R
   where
      F: FnOnce(&mut [T]) -> R,
   {
      let _guard = UnlockGuard::new(self);
      let slice = unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), LENGTH) };
      let result = f(slice);
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

   /// Same as `SecureVec::init_from_clone`, for the fixed-size buffer.
   /// `src.len()` must equal `LENGTH`.
   pub(crate) fn init_from_clone(&mut self, src: &[T])
   where
      T: Clone,
   {
      debug_assert_eq!(src.len(), LENGTH);

      let ok = self.unlock_memory();
      debug_assert!(
         ok,
         "SecureArray::init_from_clone: unlock_memory failed"
      );

      unsafe {
         let dst = self.ptr.as_ptr();
         for (i, item) in src.iter().enumerate() {
            core::ptr::write(dst.add(i), item.clone());
         }
      }
      let ok = self.lock_memory();
      debug_assert!(
         ok,
         "SecureArray::init_from_clone: lock_memory failed"
      );
   }
}

impl<T: Zeroize, const LENGTH: usize> Drop for SecureArray<T, LENGTH> {
   fn drop(&mut self) {
      let ok = self.unlock_memory();
      debug_assert!(ok, "SecureArray::drop: unlock_memory failed");

      let slice = unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), LENGTH) };
      for element in slice.iter_mut() {
         element.zeroize();
      }

      let size = LENGTH * mem::size_of::<T>();
      if size == 0 {
         return;
      }

      #[cfg(feature = "use_os")]
      free(self.ptr);

      #[cfg(not(feature = "use_os"))]
      unsafe {
         let layout = Layout::from_size_align_unchecked(size, mem::align_of::<T>());
         alloc::alloc::dealloc(self.ptr.as_ptr() as *mut u8, layout);
      }
   }
}

impl<T: Clone + Zeroize, const LENGTH: usize> Clone for SecureArray<T, LENGTH> {
   fn clone(&self) -> Self {
      let mut new_array = Self::empty().unwrap();
      self.unlock(|src_slice| {
         new_array.init_from_clone(src_slice);
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
         new_array.init_from_clone(vec_slice);
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
         // Deliberately dereference the locked pointer to test that
         // the security model works as expected.
         let _value = unsafe { core::hint::black_box(*array.ptr.as_ptr()) };

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

   use std::fmt::Debug;
   use zeroize::Zeroize;

   // === Test helpers for variety of types (bigger than u8, complex) ===
   #[derive(Clone, Debug, PartialEq)]
   struct SmallStruct {
      a: u8,
      b: u16,
   }
   impl Zeroize for SmallStruct {
      fn zeroize(&mut self) {
         self.a.zeroize();
         self.b.zeroize();
      }
   }

   #[derive(Clone, Debug, PartialEq)]
   struct LargeStruct {
      data: [u64; 4],
      flag: bool,
   }
   impl Zeroize for LargeStruct {
      fn zeroize(&mut self) {
         self.data.zeroize();
         self.flag.zeroize();
      }
   }

   #[derive(Clone, Debug, PartialEq)]
   #[repr(align(64))]
   struct AlignedStruct {
      value: u64,
   }
   impl Zeroize for AlignedStruct {
      fn zeroize(&mut self) {
         self.value.zeroize();
      }
   }

   #[derive(Clone, Debug, PartialEq)]
   struct Person {
      name: String,
      age: u32,
      notes: String,
   }
   impl Person {
      fn new(name: impl Into<String>, age: u32, notes: impl Into<String>) -> Self {
         Self {
            name: name.into(),
            age,
            notes: notes.into(),
         }
      }
   }
   impl Zeroize for Person {
      fn zeroize(&mut self) {
         self.name.zeroize();
         self.age.zeroize();
         self.notes.zeroize();
      }
   }
   fn create_test_person(id: usize) -> Person {
      Person::new(
         format!("Person{}", id),
         (id % 100) as u32,
         format!("Notes #{}", id),
      )
   }

   fn test_array_generic_basics<T: Zeroize + Clone + PartialEq + Debug, const N: usize>(
      initial: &[T; N],
   ) {
      let secure: SecureArray<T, N> = SecureArray::from_slice(initial).unwrap();
      assert_eq!(secure.len(), N);
      secure.unlock(|slice| {
         assert_eq!(slice, initial);
      });
      let cloned = secure.clone();
      cloned.unlock(|slice| {
         assert_eq!(slice, initial);
      });
      let mut er = SecureArray::from_slice(initial).unwrap();
      er.erase();
      er.unlock(|slice| {
         assert_eq!(slice.len(), N);
      });
   }

   #[test]
   fn test_array_u8_variety() {
      let data: [u8; 3] = [1, 2, 3];
      test_array_generic_basics(&data);
   }

   #[test]
   fn test_array_u64() {
      let data: [u64; 2] = [100u64, 200];
      test_array_generic_basics(&data);
   }

   #[test]
   fn test_array_byte_array() {
      let data: [[u8; 16]; 2] = [[1u8; 16], [2u8; 16]];
      test_array_generic_basics(&data);
   }

   #[test]
   fn test_array_small_struct() {
      let data: [SmallStruct; 2] = [SmallStruct { a: 1, b: 2 }, SmallStruct { a: 3, b: 4 }];
      test_array_generic_basics(&data);
   }

   #[test]
   fn test_array_large_struct() {
      let data = [
         LargeStruct {
            data: [1, 2, 3, 4],
            flag: true,
         },
         LargeStruct {
            data: [5, 6, 7, 8],
            flag: false,
         },
      ];
      test_array_generic_basics(&data);
   }

   #[test]
   fn test_array_person() {
      let data = [create_test_person(42), create_test_person(43)];
      test_array_generic_basics(&data);
   }

   #[test]
   fn test_array_aligned() {
      let data = [
         AlignedStruct { value: 0xDEAD_BEEF },
         AlignedStruct { value: 0xCAFE_BABE },
      ];
      test_array_generic_basics(&data);
   }
}
