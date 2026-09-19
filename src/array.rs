// No_std: we only need `Layout` for computing allocation sizes.
// We call `alloc::alloc::dealloc` via fully-qualified path to avoid
// shadowing the crate-level `alloc::<T>()` helper.
#[cfg(not(feature = "use_os"))]
use alloc::alloc::Layout;
#[cfg(not(feature = "use_os"))]
use alloc::vec::Vec;

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
      // Failing to re-lock means the protection is silently gone while the value is
      // still alive, so this is a hard error in every profile.
      assert!(ok, "UnlockGuard::drop: lock_memory failed");
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
/// # Thread Safety
///
/// `SecureArray` is `Send` (it can be moved to another thread) but not `Sync`.
/// `unlock` / `unlock_mut` change the allocation's page protection, so two threads
/// unlocking the same instance would race (one can relock while the other still
/// holds a live slice). Share it as `Arc<Mutex<SecureArray<...>>>`.
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
   /// Number of elements that have been initialized (written) so far.
   ///
   /// A freshly allocated array starts at `0` and the allocator's poison bytes
   /// remain in the slots that follow. `drop` and `erase` only zeroize this many
   /// elements, so they never interpret uninitialized memory as a `T`.
   initialized: usize,
   _marker: PhantomData<T>,
}

unsafe impl<T: Zeroize + Send, const LENGTH: usize> Send for SecureArray<T, LENGTH> {}

impl<T, const LENGTH: usize> SecureArray<T, LENGTH>
where
   T: Zeroize,
{
   /// Creates an empty (but allocated) SecureArray.
   ///
   /// The memory is allocated but not initialized, and it's the caller's responsibility to fill it.
   ///
   /// Only elements that are actually written are tracked as initialized: `drop`
   /// and `erase` zeroize just those, so dropping an array that was never filled is
   /// sound. The remaining slots still hold the allocator's poison bytes and must
   /// never be read as a `T`. Initialize the whole array (for example through
   /// [`unlock_mut`](Self::unlock_mut)) before accessing it.
   pub fn empty() -> Result<Self, Error> {
      let size = LENGTH * mem::size_of::<T>();
      if size == 0 {
         // Cannot create a zero-sized secure array
         return Err(Error::LengthCannotBeZero);
      }

      let ptr = unsafe { alloc::<T>(size)? };

      let secure_array = SecureArray {
         ptr,
         initialized: 0,
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
      let mut secure_array = match Self::empty() {
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
      secure_array.initialized = LENGTH;

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
      let mut secure_array = Self::empty()?;

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
      secure_array.initialized = LENGTH;

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
      f(slice)
   }

   /// Mutable access to the array's data as a `&mut [T]`
   ///
   /// Exposing the whole array as a `&mut [T]` treats every slot as initialized
   /// storage, so a later `drop` / `erase` zeroizes all `LENGTH` elements.
   pub fn unlock_mut<F, R>(&mut self, f: F) -> R
   where
      F: FnOnce(&mut [T]) -> R,
   {
      self.initialized = LENGTH;

      let _guard = UnlockGuard::new(self);
      let slice = unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), LENGTH) };
      f(slice)
   }

   /// Securely erases the contents of the array by zeroizing the initialized elements.
   pub fn erase(&mut self) {
      let ok = self.unlock_memory();
      debug_assert!(ok, "SecureArray::erase: unlock_memory failed");

      unsafe {
         // Only the initialized elements are zeroized: the slots after them are
         // uninitialized and must not be interpreted as a `T`.
         let slice = core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.initialized);
         for element in slice.iter_mut() {
            element.zeroize();
         }
      }

      let ok = self.lock_memory();
      assert!(ok, "SecureArray::erase: lock_memory failed");
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
      // Commit only after every write succeeded, so a panic from `T::clone`
      // leaves the array with just the elements that were actually written.
      self.initialized = src.len();
      let ok = self.lock_memory();
      assert!(
         ok,
         "SecureArray::init_from_clone: lock_memory failed"
      );
   }
}

impl<T: Zeroize, const LENGTH: usize> Drop for SecureArray<T, LENGTH> {
   fn drop(&mut self) {
      let ok = self.unlock_memory();
      debug_assert!(ok, "SecureArray::drop: unlock_memory failed");

      // Only the initialized elements are zeroized. A partially-initialized
      // array (a panic during `from_slice*` / `init_from_clone`, or an `empty()`
      // array that was never filled) still holds the allocator's poison bytes in
      // the remaining slots, and interpreting those as a `T` would dereference
      // garbage.
      let slice = unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.initialized) };
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

impl<T: Clone + Zeroize, const LENGTH: usize> TryFrom<SecureVec<T>> for SecureArray<T, LENGTH> {
   type Error = Error;

   /// Tries to convert a `SecureVec<T>` into a `SecureArray<T, LENGTH>`.
   ///
   /// This operation will only succeed if `vec.len() == LENGTH`.
   /// `LENGTH` is a compile-time constant on the destination type, it cannot
   /// be taken from the vector's runtime length.
   ///
   /// The `SecureVec` is consumed.
   fn try_from(vec: SecureVec<T>) -> Result<Self, Self::Error> {
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

impl<T: Clone + Zeroize, const LENGTH: usize> TryFrom<Vec<T>> for SecureArray<T, LENGTH> {
   type Error = Error;

   /// Tries to convert a `Vec<T>` into a `SecureArray<T, LENGTH>`.
   ///
   /// This operation will only succeed if `vec.len() == LENGTH`.
   /// `LENGTH` is a compile-time constant on the destination type, it cannot
   /// be taken from the vector's runtime length.
   ///
   /// The `Vec` is consumed and zeroized.
   fn try_from(mut vec: Vec<T>) -> Result<Self, Self::Error> {
      if vec.len() != LENGTH {
         vec.zeroize();
         return Err(Error::LengthMismatch);
      }

      let mut new_array = match Self::empty() {
         Ok(new_array) => new_array,
         Err(e) => {
            vec.zeroize();
            return Err(e);
         }
      };

      new_array.init_from_clone(&vec);
      vec.zeroize();

      Ok(new_array)
   }
}

/// Serializes as a byte buffer, matching the `deserialize_bytes` request of the
/// `Deserialize` impl below. Formats that support byte buffers get the contents in one
/// piece rather than element by element; `serde_json` renders either form as an array of
/// numbers, so its output is unchanged.
#[cfg(feature = "serde")]
impl<const LENGTH: usize> serde::Serialize for SecureArray<u8, LENGTH> {
   fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
   where
      S: serde::Serializer,
   {
      self.unlock(|slice| serializer.serialize_bytes(slice))
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
            // Pre-sized to the exact length, and rejected as soon as it overflows, so a
            // malformed (over-long) input cannot grow the locked buffer.
            let mut data: SecureVec<u8> =
               SecureVec::new_with_capacity(L).map_err(serde::de::Error::custom)?;

            while let Some(byte) = seq.next_element::<u8>()? {
               if data.len() == L {
                  return Err(serde::de::Error::invalid_length(
                     data.len() + 1,
                     &self,
                  ));
               }

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

         /// `deserialize_bytes` also accepts a raw byte buffer, so a format can hand the
         /// array over directly instead of as a sequence of `u8`s.
         fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
         where
            E: serde::de::Error,
         {
            let bytes: &[u8; L] = v
               .try_into()
               .map_err(|_| serde::de::Error::invalid_length(v.len(), &self))?;

            SecureArray::from_slice(bytes).map_err(serde::de::Error::custom)
         }

         /// Mirrors `SecureString`'s `visit_string`: wipe the owned buffer the format
         /// handed over, instead of letting it drop with the plaintext inside.
         fn visit_byte_buf<E>(self, mut v: Vec<u8>) -> Result<Self::Value, E>
         where
            E: serde::de::Error,
         {
            let array = self.visit_bytes(&v)?;
            v.zeroize();
            Ok(array)
         }
      }

      deserializer.deserialize_bytes(SecureArrayVisitor::<LENGTH>)
   }
}

/// Serializes a `SecureArray<T, LENGTH>` of [`SeqElement`](crate::vec::SeqElement)s as a
/// tuple of `T` values, matching serde's own `[T; N]` convention.
///
/// `SecureArray<u8, LENGTH>` takes the byte-buffer impl above instead; the bound here is
/// what keeps the two disjoint.
#[cfg(feature = "serde")]
impl<const LENGTH: usize, T> serde::Serialize for SecureArray<T, LENGTH>
where
   T: crate::vec::SeqElement + serde::Serialize,
{
   fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
   where
      S: serde::Serializer,
   {
      use serde::ser::SerializeTuple;

      let mut tuple = serializer.serialize_tuple(LENGTH)?;

      let elements: Result<(), S::Error> = self.unlock(|slice| {
         for item in slice {
            tuple.serialize_element(item)?;
         }

         Ok(())
      });
      elements?;

      tuple.end()
   }
}

/// Deserializes a `SecureArray<T, LENGTH>` of [`SeqElement`](crate::vec::SeqElement)s from a
/// tuple of `T` values.
#[cfg(feature = "serde")]
impl<'de, const LENGTH: usize, T> serde::Deserialize<'de> for SecureArray<T, LENGTH>
where
   T: crate::vec::SeqElement + Clone + serde::Deserialize<'de>,
{
   fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
   where
      D: serde::Deserializer<'de>,
   {
      struct SecureArraySeqVisitor<const L: usize, T>(::core::marker::PhantomData<T>);

      impl<'de, const L: usize, T> serde::de::Visitor<'de> for SecureArraySeqVisitor<L, T>
      where
         T: crate::vec::SeqElement + Clone + serde::Deserialize<'de>,
      {
         type Value = SecureArray<T, L>;

         fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            write!(formatter, "a secure array of length {}", L)
         }

         fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
         where
            A: serde::de::SeqAccess<'de>,
         {
            // Pre-sized to the exact length, and rejected as soon as it overflows, so a
            // malformed (over-long) input cannot grow the locked buffer.
            let mut data: SecureVec<T> =
               SecureVec::new_with_capacity(L).map_err(serde::de::Error::custom)?;

            while let Some(element) = seq.next_element::<T>()? {
               if data.len() == L {
                  return Err(serde::de::Error::invalid_length(
                     data.len() + 1,
                     &self,
                  ));
               }

               data.push(element);
            }

            if data.len() != L {
               return Err(serde::de::Error::invalid_length(
                  data.len(),
                  &self,
               ));
            }

            SecureArray::try_from(data).map_err(serde::de::Error::custom)
         }
      }

      deserializer.deserialize_tuple(
         LENGTH,
         SecureArraySeqVisitor::<LENGTH, T>(::core::marker::PhantomData),
      )
   }
}

#[cfg(all(test, feature = "use_os"))]
mod tests {
   use super::*;
   use std::process::{Command, Stdio};

   #[test]
   fn lock_unlock() {
      let exposed: &mut [u8; 3] = &mut [1, 2, 3];
      let secure: SecureArray<u8, 3> = SecureArray::from_slice_mut(exposed).unwrap();

      let unlocked = secure.unlock_memory();
      assert!(unlocked);

      let locked = secure.lock_memory();
      assert!(locked);
   }

   /// Pins the invariant that only written elements are considered initialized.
   #[test]
   fn test_initialized_count_tracking() {
      let mut array: SecureArray<u8, 3> = SecureArray::empty().unwrap();
      assert_eq!(array.initialized, 0);

      array.unlock_mut(|slice| {
         slice[0] = 1;
         slice[1] = 2;
         slice[2] = 3;
      });
      assert_eq!(array.initialized, 3);

      let from_slice: SecureArray<u8, 3> = SecureArray::from_slice(&[1, 2, 3]).unwrap();
      assert_eq!(from_slice.initialized, 3);
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
}
