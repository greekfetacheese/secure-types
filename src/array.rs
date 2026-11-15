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
use secure_alloc::Prot;

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
/// - **Zeroization on Drop**: The memory is zeroized and every element is dropped when the array
///   is dropped.
/// - **Memory Locking**: the allocation is `mprotect`ed `PROT_NONE` outside an `unlock*` scope,
///   which stops accidental reads — including from this process — but is not a defence against
///   `ptrace` or a debugger. On the malloc path it is also `mlock`ed (Windows: `VirtualLock`)
///   and, where the OS supports it, excluded from core dumps (`MADV_DONTDUMP` on Linux,
///   `MADV_NOCORE` on FreeBSD/DragonFly). Linux uses `memfd_secret` when the kernel supports it;
///   that backing is neither `mlock`ed nor marked `MADV_DONTDUMP`.
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
   /// The memory is allocated but not initialized, and it's the caller's
   /// responsibility to fill it with [`from_fn`](Self::from_fn).
   ///
   /// Only elements that are actually written are tracked as initialized: `drop`
   /// and `erase` zeroize just those, so dropping an array that was never filled is
   /// sound. The remaining slots still hold the allocator's poison bytes and must
   /// never be read as a `T`. [`unlock_mut`](Self::unlock_mut) refuses an array
   /// that is not fully initialized, so build the array with
   /// [`from_fn`](Self::from_fn) instead of filling it through `unlock_mut`.
   pub fn empty() -> Result<Self, Error> {
      let size = LENGTH
         .checked_mul(mem::size_of::<T>())
         .ok_or(Error::AllocationFailed)?;
      if size == 0 {
         // Cannot create a zero-sized secure array
         return Err(Error::LengthCannotBeZero);
      }

      // SAFETY: `alloc` is `unsafe` only as a raw-allocation marker — it has no
      // preconditions beyond rejecting a zero `size`, and returns a pointer
      // aligned for `T`.
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

      {
         let _guard = UnlockGuard::new(&secure_array);

         // SAFETY: the fresh allocation holds `LENGTH` uninitialised slots and
         // the guard unprotects it. `content` has exactly `LENGTH` elements, so
         // every `dst.add(i)` is in bounds, and `ptr::write` never reads the
         // uninitialised destination. `initialized` is committed only after the
         // loop, so a panic here still leaves the array sound.
         unsafe {
            let dst = secure_array.ptr.as_ptr();
            for (i, item) in content.iter().enumerate() {
               core::ptr::write(dst.add(i), item.clone());
            }
         }
      }
      secure_array.initialized = LENGTH;

      content.zeroize();

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

      {
         let _guard = UnlockGuard::new(&secure_array);

         // SAFETY: as in `from_slice_mut` — `LENGTH` uninitialised slots in a
         // fresh allocation, `content` has exactly `LENGTH` elements, `ptr::write`
         // never reads the destination, and `initialized` is committed afterwards.
         unsafe {
            let dst = secure_array.ptr.as_ptr();
            for (i, item) in content.iter().enumerate() {
               core::ptr::write(dst.add(i), item.clone());
            }
         }
      }
      secure_array.initialized = LENGTH;

      Ok(secure_array)
   }

   /// Builds a fully-initialized array, using `f` as the source of each element.
   ///
   /// `f(i)` produces the value of slot `i`, and every value is written straight
   /// into the secure allocation — it never touches the stack. If `f` panics, the
   /// slots written so far are zeroized and dropped before the memory is re-locked,
   /// so a failed build leaves no partial value behind. This is the supported way
   /// to build an array without a source slice: it replaces filling an
   /// [`empty`](Self::empty) array through [`unlock_mut`](Self::unlock_mut),
   /// which refuses an array that is not fully initialized.
   pub fn from_fn<F>(mut f: F) -> Result<Self, Error>
   where
      F: FnMut(usize) -> T,
   {
      let mut array = Self::empty()?;

      {
         let _unlock = UnlockGuard::new(&array);

         // Zeroizes and drops the prefix written so far if `f` panics. Declared
         // after `_unlock`, so it is dropped first, while the memory is still
         // unlocked.
         struct InitGuard<T: Zeroize> {
            ptr: *mut T,
            written: usize,
         }

         impl<T: Zeroize> Drop for InitGuard<T> {
            fn drop(&mut self) {
               // SAFETY: `written` counts exactly the slots `from_fn` filled with
               // `ptr::write`, and this guard is dropped before the enclosing
               // `UnlockGuard` re-locks the region.
               unsafe {
                  for i in 0..self.written {
                     let slot = self.ptr.add(i);
                     (*slot).zeroize();
                     core::ptr::drop_in_place(slot);
                  }
               }
            }
         }

         let mut guard = InitGuard::<T> {
            ptr: array.ptr.as_ptr(),
            written: 0,
         };

         for i in 0..LENGTH {
            let value = f(i);
            // SAFETY: `i < LENGTH`, so `dst.add(i)` is in bounds of the live
            // allocation, the guard unprotects it, and `ptr::write` never reads
            // the uninitialized destination.
            unsafe {
               core::ptr::write(array.ptr.as_ptr().add(i), value);
            }
            guard.written = i + 1;
         }

         core::mem::forget(guard);
      }

      array.initialized = LENGTH;

      Ok(array)
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
   ///
   /// The slice covers exactly the elements that have been initialized: `LENGTH`
   /// for any array built through a constructor or `unlock_mut`, and empty for
   /// an [`empty`](Self::empty) array that was never filled (see its contract).
   pub fn unlock<F, R>(&self, f: F) -> R
   where
      F: FnOnce(&[T]) -> R,
   {
      let _guard = UnlockGuard::new(self);
      // SAFETY: the guard unprotects the live allocation. Only the `initialized`
      // written slots are exposed, so no uninitialised memory is read as a `T`.
      let slice = unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.initialized) };
      f(slice)
   }

   /// Mutable access to the array's data as a `&mut [T]`
   ///
   /// The array must be fully initialized first; this refuses a partially
   /// initialized one rather than exposing slots that still hold poison bytes.
   ///
   /// # Panics
   ///
   /// Panics if any slot was never written. An [`empty`](Self::empty) array that
   /// was not filled, or one left partial by a panic during construction, still
   /// holds the allocator's poison bytes in those slots. Exposing them as
   /// `&mut [T]` would make `drop` and [`erase`](Self::erase) zeroize those bytes
   /// as a `T`, which is undefined behaviour. Build the array with
   /// [`from_slice`](Self::from_slice), [`from_slice_mut`](Self::from_slice_mut),
   /// [`from_fn`](Self::from_fn), `Clone` or `TryFrom` instead.
   pub fn unlock_mut<F, R>(&mut self, f: F) -> R
   where
      F: FnOnce(&mut [T]) -> R,
   {
      assert_eq!(
         self.initialized, LENGTH,
         "SecureArray::unlock_mut: {} of {LENGTH} slots are initialized; build the array with from_slice, from_slice_mut, from_fn, Clone or TryFrom",
         self.initialized,
      );

      let _guard = UnlockGuard::new(self);
      // SAFETY: the assertion above proves every slot holds a written `T`, so the
      // whole allocation is initialized storage, and the guard unprotects it.
      let slice = unsafe { core::slice::from_raw_parts_mut(self.ptr.as_ptr(), LENGTH) };
      f(slice)
   }

   /// Securely erases the contents of the array by zeroizing the initialized elements.
   pub fn erase(&mut self) {
      let _guard = UnlockGuard::new(self);

      // SAFETY: the guard unprotects the live allocation; only the `initialized`
      // written slots are exposed as `&mut [T]`, so uninitialised memory is never
      // interpreted as a `T`.
      unsafe {
         let slice = core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.initialized);
         for element in slice.iter_mut() {
            element.zeroize();
         }
      }
   }

   /// Same as `SecureVec::init_from_clone`, for the fixed-size buffer.
   ///
   /// `src.len()` must not exceed `LENGTH`: the slots it fills become the
   /// initialized prefix, so a short `src` — a clone of an `empty` or partially
   /// filled array — leaves the remaining slots untouched and uninitialized.
   pub(crate) fn init_from_clone(&mut self, src: &[T])
   where
      T: Clone,
   {
      debug_assert!(
         src.len() <= LENGTH,
         "init_from_clone: more elements than the array can hold"
      );

      {
         let _guard = UnlockGuard::new(self);

         // SAFETY: `src.len() == LENGTH` is the caller's contract, so every
         // `dst.add(i)` is in bounds of this fixed-size allocation, the guard
         // unprotects it, and `ptr::write` never reads the unwritten destination.
         unsafe {
            let dst = self.ptr.as_ptr();
            for (i, item) in src.iter().enumerate() {
               core::ptr::write(dst.add(i), item.clone());
            }
         }
      }
      // Commit only after every write succeeded, so a panic from `T::clone`
      // leaves the array with just the elements that were actually written.
      self.initialized = src.len();
   }
}

impl<T: Zeroize, const LENGTH: usize> Drop for SecureArray<T, LENGTH> {
   fn drop(&mut self) {
      let ok = self.unlock_memory();
      debug_assert!(ok, "SecureArray::drop: unlock_memory failed");

      // Only the initialized elements are zeroized and dropped. A
      // partially-initialized array (a panic during `from_slice*` /
      // `init_from_clone`, or an `empty()` array that was never filled) still
      // holds the allocator's poison bytes in the remaining slots, and
      // interpreting those as a `T` would dereference garbage. Zeroizing wipes
      // what an element owns; the drop releases that allocation.
      // SAFETY: the memory was unprotected above; the raw loop covers only the
      // `initialized` written slots, and each is zeroized then dropped once.
      unsafe {
         let ptr = self.ptr.as_ptr();
         for i in 0..self.initialized {
            let slot = ptr.add(i);
            (*slot).zeroize();
            core::ptr::drop_in_place(slot);
         }
      }

      let size = LENGTH.checked_mul(mem::size_of::<T>()).unwrap_or(0);
      if size == 0 {
         return;
      }

      #[cfg(feature = "use_os")]
      free(self.ptr);

      #[cfg(not(feature = "use_os"))]
      // SAFETY: `size` is the full allocation size (`LENGTH * size_of::<T>()`),
      // the region was unprotected above and is still owned here, and the
      // `Layout` below matches the one `alloc` used.
      unsafe {
         let bytes = core::slice::from_raw_parts_mut(self.ptr.as_ptr() as *mut u8, size);
         bytes.zeroize();

         let layout = Layout::from_size_align_unchecked(size, mem::align_of::<T>());
         alloc::alloc::dealloc(self.ptr.as_ptr() as *mut u8, layout);
      }
   }
}

impl<T: Clone + Zeroize, const LENGTH: usize> Clone for SecureArray<T, LENGTH> {
   /// The clone carries the source's initialization state: an
   /// [`empty`](Self::empty) array clones to an empty one, not to a fully
   /// populated array of poison bytes.
   ///
   /// # Panics
   ///
   /// Panics if the clone's secure allocation cannot be made or locked.
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
            let array = self.visit_bytes(&v);
            v.zeroize();
            array
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
   use std::sync::atomic::{AtomicUsize, Ordering};

   #[test]
   fn lock_unlock() {
      let exposed: &mut [u8; 3] = &mut [1, 2, 3];
      let secure: SecureArray<u8, 3> = SecureArray::from_slice_mut(exposed).unwrap();

      let unlocked = secure.unlock_memory();
      assert!(unlocked);

      let locked = secure.lock_memory();
      assert!(locked);
   }

   /// Pins the invariant that only written elements are considered initialized:
   /// a fresh `empty` array starts at zero, and a built one covers every slot.
   #[test]
   fn test_initialized_count_tracking() {
      let empty: SecureArray<u8, 3> = SecureArray::empty().unwrap();
      assert_eq!(empty.initialized, 0);

      let array: SecureArray<u8, 3> = SecureArray::from_fn(|i| i as u8 + 1).unwrap();
      assert_eq!(array.initialized, 3);

      let from_slice: SecureArray<u8, 3> = SecureArray::from_slice(&[1, 2, 3]).unwrap();
      assert_eq!(from_slice.initialized, 3);
   }

   /// An array that was never filled still holds the allocator's poison bytes in
   /// its slots, so `unlock_mut` must refuse it instead of exposing them as a
   /// `&mut [T]` that `drop` would zeroize as a `T`.
   #[test]
   #[should_panic(expected = "slots are initialized")]
   fn test_unlock_mut_requires_a_fully_initialized_array() {
      let mut array = SecureArray::<u8, 2>::empty().unwrap();
      array.unlock_mut(|_| {});
   }

   #[test]
   fn test_from_fn_fills_every_slot() {
      let array: SecureArray<u8, 4> = SecureArray::from_fn(|i| i as u8).unwrap();

      array.unlock(|slice| {
         assert_eq!(slice, &[0, 1, 2, 3]);
      });
   }

   #[test]
   fn test_from_fn_rejects_zero_sized_array() {
      let result: Result<SecureArray<u8, 0>, Error> = SecureArray::from_fn(|_| 0);

      assert!(matches!(result, Err(Error::LengthCannotBeZero)));
   }

   /// A `T` whose zeroization and drop are observable, so the panic path is
   /// asserted through the counters rather than from inside `Drop` (an assert
   /// there would abort the process instead of failing the test).
   ///
   /// It carries one byte of payload because `SecureArray` rejects a zero-sized
   /// allocation, and because the prefix that is cleaned up must hold real values.
   struct Tracked(u8);

   static ZEROIZED: AtomicUsize = AtomicUsize::new(0);

   static DROPPED: AtomicUsize = AtomicUsize::new(0);

   impl Zeroize for Tracked {
      fn zeroize(&mut self) {
         self.0.zeroize();
         ZEROIZED.fetch_add(1, Ordering::SeqCst);
      }
   }

   impl Drop for Tracked {
      fn drop(&mut self) {
         DROPPED.fetch_add(1, Ordering::SeqCst);
      }
   }

   /// A panic in the closure zeroizes and drops exactly the prefix that was
   /// already written, and nothing else.
   #[test]
   fn test_from_fn_panic_zeroizes_written_prefix() {
      ZEROIZED.store(0, Ordering::SeqCst);
      DROPPED.store(0, Ordering::SeqCst);

      let result = std::panic::catch_unwind(|| {
         SecureArray::<Tracked, 3>::from_fn(|i| {
            if i == 1 {
               panic!("x");
            }

            Tracked(1)
         })
      });

      assert!(result.is_err());
      assert_eq!(ZEROIZED.load(Ordering::SeqCst), 1);
      assert_eq!(DROPPED.load(Ordering::SeqCst), 1);
   }

   /// Owns a drop half of the lifecycle with counters of its own, so the drop-path
   /// test does not race the panic-path test above.
   struct DropTracked(u8);

   static DROP_COUNT: AtomicUsize = AtomicUsize::new(0);

   impl Zeroize for DropTracked {
      fn zeroize(&mut self) {
         self.0.zeroize();
      }
   }

   impl Drop for DropTracked {
      fn drop(&mut self) {
         DROP_COUNT.fetch_add(1, Ordering::SeqCst);
      }
   }

   /// An initialized element must be zeroized *and dropped* when the array goes
   /// away: zeroizing alone wipes its bytes but leaks the allocation it owns.
   #[test]
   fn test_drop_zeroizes_and_drops_initialized_elements() {
      DROP_COUNT.store(0, Ordering::SeqCst);

      {
         let array: SecureArray<DropTracked, 3> =
            SecureArray::from_fn(|i| DropTracked(i as u8)).unwrap();
         drop(array);
      }

      assert_eq!(DROP_COUNT.load(Ordering::SeqCst), 3);
   }

   #[test]
   fn test_index_should_fail_when_locked() {
      let arg = "CRASH_TEST_ARRAY_LOCKED";

      if std::env::args().any(|a| a == arg) {
         let exposed: &mut [u8; 3] = &mut [1, 2, 3];
         let array: SecureArray<u8, 3> = SecureArray::from_slice_mut(exposed).unwrap();
         // SAFETY (test-only): this deliberately dereferences a locked,
         // `PROT_NONE` page to prove the access faults — the child process is
         // expected to die with SIGSEGV, so the read never completes.
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
