// No_std: we only need `Layout` for computing allocation sizes.
// We call `alloc::alloc::dealloc` via fully-qualified path to avoid
// shadowing the crate-level `alloc::<T>()` helper.
#[cfg(not(feature = "use_os"))]
use alloc::alloc::Layout;

#[cfg(feature = "use_os")]
use std::vec::Vec;

// In a `no_std` build `Vec` is only needed by the serde visitor below.
#[cfg(all(feature = "serde", not(feature = "use_os")))]
use alloc::vec::Vec;

use super::{Error, SecureArray, alloc};
use core::{
   marker::PhantomData,
   mem,
   ops::{Bound, RangeBounds},
   ptr::{self, NonNull},
};
use zeroize::{DefaultIsZeroes, Zeroize};

#[cfg(feature = "use_os")]
use super::free;
#[cfg(feature = "use_os")]
use memsec::Prot;

pub type SecureBytes = SecureVec<u8>;

/// Unlocks the vector's memory on construction and re-locks it on drop —
/// including when the drop happens because the fn closure panicked.
pub(crate) struct UnlockGuard<'a, T: Zeroize> {
   vec: &'a SecureVec<T>,
}

impl<'a, T: Zeroize> UnlockGuard<'a, T> {
   pub(crate) fn new(vec: &'a SecureVec<T>) -> Self {
      let ok = vec.unlock_memory();
      debug_assert!(ok, "UnlockGuard::new: unlock_memory failed");

      UnlockGuard { vec }
   }
}

impl<'a, T: Zeroize> Drop for UnlockGuard<'a, T> {
   fn drop(&mut self) {
      let ok = self.vec.lock_memory();
      // Failing to re-lock means the protection is silently gone while the value is
      // still alive, so this is a hard error in every profile.
      assert!(ok, "UnlockGuard::drop: lock_memory failed");
   }
}

/// A securely allocated, growable vector, just like `std::vec::Vec`.
///
/// ## Security Model
///
/// When compiled with the `use_os` feature (the default), it provides several layers of protection:
/// - **Zeroization on Drop**: The memory is zeroized when the vector is dropped.
/// - **Memory Locking**: The underlying memory pages are locked using `mlock` & `madvise` for (Unix) or
///   `VirtualLock` & `VirtualProtect` for (Windows) to prevent the OS from memory-dump/swap to disk or other processes accessing the memory.
///
/// In a `no_std` environment, it falls back to providing only the **zeroization-on-drop** guarantee.
///
/// ## Security Note on Direct Access
///
/// We intentionally do **not** implement `Index` / `IndexMut`.
/// Using `secure_vec[0]` is a compile error.
///
/// This is by design: direct indexing would allow bypassing the explicit
/// unlock mechanism. Always use `unlock_slice()` / `unlock_slice_mut()` (or
/// the `unlock*` family of methods) to access the contents.
///
/// # Thread Safety
///
/// `SecureVec` is `Send` (it can be moved to another thread) but not `Sync`.
/// `unlock*` changes the allocation's page protection, so two threads unlocking
/// the same instance would race (one can relock while the other still holds a
/// live slice). Share it as `Arc<Mutex<SecureVec<T>>>`.
///
/// # Notes
///
/// If you return a new allocated `Vec` from one of the unlock methods you are responsible for zeroizing the memory.
///
/// # Example
///
/// Using `SecureBytes` (a type alias for `SecureVec<u8>`) to handle a secret key.
///
/// ```
/// use secure_types::{SecureBytes, Zeroize};
///
/// // Create a new, empty secure vector.
/// let mut secret_key = SecureBytes::new().unwrap();
///
/// // Push some sensitive data into it.
/// secret_key.push(0xAB);
/// secret_key.push(0xCD);
/// secret_key.push(0xEF);
///
/// // The memory is locked here.
///
/// // Use a scope to safely access the contents as a slice.
/// secret_key.unlock_slice(|unlocked_slice| {
///     assert_eq!(unlocked_slice, &[0xAB, 0xCD, 0xEF]);
/// });
///
/// // Not recommended but if you allocate a new Vec make sure to zeroize it
/// let mut exposed = secret_key.unlock_slice(|unlocked_slice| {
///     Vec::from(unlocked_slice)
/// });
///
/// // Do what you need to to do with the new vector
/// // When you are done with it, zeroize it
/// exposed.zeroize();
///
/// // The memory is automatically locked again when the scope ends.
///
/// // When `secret_key` is dropped, its memory is securely zeroized.
/// ```
pub struct SecureVec<T>
where
   T: Zeroize,
{
   ptr: NonNull<T>,
   pub(crate) len: usize,
   pub(crate) capacity: usize,
   _marker: PhantomData<T>,
}

unsafe impl<T: Zeroize + Send> Send for SecureVec<T> {}

impl<T: Zeroize> SecureVec<T> {
   /// Create a new `SecureVec` with a capacity of 1
   pub fn new() -> Result<Self, Error> {
      let capacity = 1;
      let size = capacity * mem::size_of::<T>();
      let ptr = unsafe { alloc::<T>(size)? };

      let secure = SecureVec {
         ptr,
         len: 0,
         capacity,
         _marker: PhantomData,
      };

      let _locked = secure.lock_memory();

      #[cfg(feature = "use_os")]
      if !_locked {
         return Err(Error::LockFailed);
      }

      Ok(secure)
   }

   /// Create a new `SecureVec` with the given capacity
   pub fn new_with_capacity(mut capacity: usize) -> Result<Self, Error> {
      if capacity == 0 {
         capacity = 1;
      }

      capacity
         .checked_mul(size_of::<T>())
         .ok_or(Error::AllocationFailed)?;

      let size = capacity * mem::size_of::<T>();
      let ptr = unsafe { alloc::<T>(size)? };

      let secure = SecureVec {
         ptr,
         len: 0,
         capacity,
         _marker: PhantomData,
      };

      let _locked = secure.lock_memory();

      #[cfg(feature = "use_os")]
      if !_locked {
         return Err(Error::LockFailed);
      }

      Ok(secure)
   }

   #[cfg(feature = "use_os")]
   /// Create a new `SecureVec` from a `Vec`
   ///
   /// The `Vec` is zeroized afterwards
   pub fn from_vec(mut vec: Vec<T>) -> Result<Self, Error> {
      if vec.capacity() == 0 {
         vec.reserve(1);
      }

      let capacity = vec.capacity();
      let len = vec.len();

      let size = match capacity.checked_mul(size_of::<T>()) {
         Some(s) => s,
         None => {
            vec.zeroize();
            return Err(Error::AllocationFailed);
         }
      };

      let ptr = match unsafe { alloc::<T>(size) } {
         Ok(ptr) => ptr,
         Err(_) => {
            vec.zeroize();
            return Err(Error::AllocationFailed);
         }
      };

      // Move data from the old vec into the secure allocation using ptr::read / ptr::write
      // This correctly transfers ownership for non-Copy types (e.g. structs containing String).
      // We then zero the *bytes* of the source buffer (after moving values out) to avoid
      // leaving sensitive data, and prevent double-drop by clearing the vec length.
      unsafe {
         let src = vec.as_ptr();
         let dst = ptr.as_ptr();
         for i in 0..len {
            let value = core::ptr::read(src.add(i));
            core::ptr::write(dst.add(i), value);
         }
      }

      // Prevent the Vec from dropping the now-moved-from elements (would be UB)
      // and securely erase whatever representation bytes remain in its buffer.
      //
      // We use set_len(0) + zeroize on a &mut [u8] view of the allocation
      // (instead of calling vec.zeroize()) because the Ts have been moved out
      // via ptr::read. The normal Vec::zeroize impl would zeroize+drop the
      // moved-from elements, which is UB (and often SIGABRT for a non-copy type).
      let old_byte_size = capacity * mem::size_of::<T>();
      unsafe {
         vec.set_len(0);
      }
      if old_byte_size > 0 {
         // SAFETY: after set_len(0) the allocation bytes are still valid,
         // we own them exclusively, and no Ts will be dropped by the Vec.
         let bytes =
            unsafe { core::slice::from_raw_parts_mut(vec.as_mut_ptr() as *mut u8, old_byte_size) };
         bytes.zeroize();
      }

      let secure = SecureVec {
         ptr,
         len,
         capacity,
         _marker: PhantomData,
      };

      let locked = secure.lock_memory();

      if !locked {
         return Err(Error::LockFailed);
      }

      Ok(secure)
   }

   /// Create a new `SecureVec` from a mutable slice.
   ///
   /// The slice is zeroized afterwards
   pub fn from_slice_mut(slice: &mut [T]) -> Result<Self, Error>
   where
      T: Clone + DefaultIsZeroes,
   {
      let mut secure_vec = match SecureVec::new_with_capacity(slice.len()) {
         Ok(secure_vec) => secure_vec,
         Err(e) => {
            slice.zeroize();
            return Err(e);
         }
      };

      secure_vec.init_from_clone(slice);
      slice.zeroize();

      Ok(secure_vec)
   }

   /// Create a new `SecureVec` from a slice.
   ///
   /// The slice is not zeroized, you are responsible for zeroizing it
   pub fn from_slice(slice: &[T]) -> Result<Self, Error>
   where
      T: Clone,
   {
      let mut secure_vec = SecureVec::new_with_capacity(slice.len())?;
      secure_vec.init_from_clone(slice);
      Ok(secure_vec)
   }

   pub fn len(&self) -> usize {
      self.len
   }

   /// The number of elements the locked allocation can hold before it grows.
   ///
   /// The allocation is re-`mprotect`ed on every growth, so this is also the number of
   /// elements that can be pushed before another unlock/lock cycle.
   pub fn capacity(&self) -> usize {
      self.capacity
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
   /// region, use one of the unlock methods.
   #[cfg(feature = "expose-ptr")]
   #[deprecated(
      since = "0.3.0",
      note = "This method is intended only for testing/crash reproduction. Use one of the unlock methods instead."
   )]
   pub fn ptr(&self) -> NonNull<T> {
      self.ptr
   }

   /// Returns the total number of bytes currently allocated for this vector.
   #[cfg(not(feature = "use_os"))]
   pub(crate) fn allocated_byte_size(&self) -> usize {
      self.capacity * mem::size_of::<T>()
   }

   pub(crate) fn as_mut_ptr(&mut self) -> *mut u8 {
      self.ptr.as_ptr() as *mut u8
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

   /// Immutable access to the `SecureVec`
   pub fn unlock<F, R>(&self, f: F) -> R
   where
      F: FnOnce(&SecureVec<T>) -> R,
   {
      let _guard = UnlockGuard::new(self);
      f(self)
   }

   /// Immutable access to the `SecureVec` as `&[T]`
   pub fn unlock_slice<F, R>(&self, f: F) -> R
   where
      F: FnOnce(&[T]) -> R,
   {
      let _guard = UnlockGuard::new(self);
      let slice = unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) };
      f(slice)
   }

   /// Mutable access to the `SecureVec` as `&mut [T]`
   pub fn unlock_slice_mut<F, R>(&mut self, f: F) -> R
   where
      F: FnOnce(&mut [T]) -> R,
   {
      unsafe {
         let _guard = UnlockGuard::new(self);
         let slice = core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len);
         f(slice)
      }
   }

   /// Immutable access to the `SecureVec` as `Iter<T>`
   pub fn unlock_iter<F, R>(&self, f: F) -> R
   where
      F: FnOnce(core::slice::Iter<T>) -> R,
   {
      unsafe {
         let _guard = UnlockGuard::new(self);
         let slice = core::slice::from_raw_parts(self.ptr.as_ptr(), self.len);
         let iter = slice.iter();
         f(iter)
      }
   }

   /// Mutable access to the `SecureVec` as `IterMut<T>`
   pub fn unlock_iter_mut<F, R>(&mut self, f: F) -> R
   where
      F: FnOnce(core::slice::IterMut<T>) -> R,
   {
      unsafe {
         let _guard = UnlockGuard::new(self);
         let slice = core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len);
         let iter = slice.iter_mut();
         f(iter)
      }
   }

   /// Erase the underlying data and clears the vector
   ///
   /// The memory is locked again and the capacity is preserved for reuse
   pub fn erase(&mut self) {
      unsafe {
         let ok = self.unlock_memory();
         debug_assert!(ok, "SecureVec::erase: unlock_memory failed");

         // Only zero the initialized elements. Zeroizing capacity would try to
         // zeroize uninitialized memory as T, which for Drop types (eg. String)
         // is UB and causes SIGSEGV/SIGABRT.
         let slice = core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len);
         for elem in slice.iter_mut() {
            elem.zeroize();
         }

         self.clear();

         let ok = self.lock_memory();
         assert!(ok, "SecureVec::erase: lock_memory failed");
      }
   }

   /// Clear the vector
   ///
   /// This just sets the vector's len to zero it does not erase the underlying data
   pub fn clear(&mut self) {
      self.len = 0;
   }

   pub fn push(&mut self, value: T) {
      self.reserve(1);

      let ok = self.unlock_memory();
      debug_assert!(ok, "SecureVec::push: unlock_memory failed");

      unsafe {
         // Write the new value at the end of the vector.
         core::ptr::write(self.ptr.as_ptr().add(self.len), value);

         self.len += 1;
      }

      let ok = self.lock_memory();
      assert!(ok, "SecureVec::push: lock_memory failed");
   }

   /// Appends every element of `src` using a single unlock/lock cycle.
   ///
   /// A loop of [`push`](Self::push) costs an `mprotect` pair per element, so bulk
   /// copies (the serde writer feeding this vector, and the binary codec's encoder)
   /// need this instead. The length is committed only after every write succeeded,
   /// so a panic from `T::clone` leaves the vector at its previous length.
   ///
   /// Gated on `use_os` or `codec`: those are the two features that call it, and
   /// compiling it for neither would only produce a `dead_code` warning.
   #[cfg(any(feature = "use_os", feature = "codec"))]
   pub(crate) fn extend_from_slice(&mut self, src: &[T])
   where
      T: Clone,
   {
      if src.is_empty() {
         return;
      }

      self.reserve(src.len());

      let write_at = self.len;
      let dst = self.ptr.as_ptr();

      {
         let _guard = UnlockGuard::new(self);

         unsafe {
            for (i, item) in src.iter().enumerate() {
               core::ptr::write(dst.add(write_at + i), item.clone());
            }
         }
      }

      self.len = write_at + src.len();
   }

   /// Ensures that the vector has enough capacity for at least `additional` more elements.
   ///
   /// If more capacity is needed, it will reallocate. This may cause the buffer location to change.
   ///
   /// # Panics
   ///
   /// Panics if the new capacity overflows `usize` or if the allocation fails.
   pub fn reserve(&mut self, additional: usize) {
      let required_capacity = match self.len.checked_add(additional) {
         Some(required_capacity) => required_capacity,
         None => panic!(
            "secure-types: SecureVec::reserve overflow: len ({}) + additional ({}) exceeds usize",
            self.len, additional
         ),
      };

      if required_capacity <= self.capacity {
         return;
      }

      // Use an amortized growth strategy to avoid reallocating on every push.
      // If doubling would overflow, fall back to the exact requirement and let
      // the allocation below report the failure.
      let new_capacity = self
         .capacity
         .max(1)
         .checked_mul(2)
         .unwrap_or(required_capacity)
         .max(required_capacity);

      let new_size = match new_capacity.checked_mul(mem::size_of::<T>()) {
         Some(new_size) => new_size,
         None => panic!(
            "secure-types: SecureVec::reserve overflow: capacity ({}) * size_of::<T>() ({}) exceeds usize",
            new_capacity,
            mem::size_of::<T>()
         ),
      };

      // Safe to panic here because the memory is locked
      let new_ptr = unsafe {
         alloc::<T>(new_size).unwrap_or_else(|_| {
            panic!(
               "secure-types: failed to allocate {} bytes of locked memory \
          (possibly RLIMIT_MEMLOCK exhausted); SecureVec left unchanged",
               new_size
            )
         })
      };

      // Copy data to new pointer
      unsafe {
         let ok = self.unlock_memory();
         debug_assert!(ok, "SecureVec::reserve: unlock_memory failed");

         // Move (not copy) elements to new buffer to support non-Copy T correctly.
         // Using read+write transfers ownership of e.g. Strings.
         let len = self.len();
         for i in 0..len {
            let val = core::ptr::read(self.ptr.as_ptr().add(i));
            core::ptr::write(new_ptr.as_ptr().add(i), val);
         }

         // Erase old buffer bytes (after move-out)
         if self.capacity > 0 {
            let old_bytes = self.capacity * mem::size_of::<T>();
            let bytes = core::slice::from_raw_parts_mut(self.ptr.as_ptr() as *mut u8, old_bytes);
            bytes.zeroize();
         }

         #[cfg(feature = "use_os")]
         free(self.ptr);

         #[cfg(not(feature = "use_os"))]
         {
            let old_size = self.capacity * mem::size_of::<T>();
            let old_layout = Layout::from_size_align_unchecked(old_size, mem::align_of::<T>());
            alloc::alloc::dealloc(self.ptr.as_ptr() as *mut u8, old_layout);
         }
      }

      // Update pointer and capacity, then re-lock the new memory region
      self.ptr = new_ptr;
      self.capacity = new_capacity;
      let ok = self.lock_memory();
      assert!(ok, "SecureVec::reserve: lock_memory failed");
   }

   /// Creates a draining iterator that removes the specified range from the vector
   /// and yields the removed items.
   ///
   /// Note: the memory is only unlocked while an item is read and while the iterator
   /// is dropped, so it is left locked once the iterator is gone even if the
   /// iterator is leaked with `mem::forget`.
   ///
   /// # Panics
   /// Panics if the starting point is greater than the end point or if the end point
   /// is greater than the length of the vector.
   pub fn drain<R>(&mut self, range: R) -> Drain<'_, T>
   where
      R: RangeBounds<usize>,
   {
      let original_len = self.len;

      let (drain_start_idx, drain_end_idx) = resolve_range_indices(range, original_len);

      let tail_len = original_len - drain_end_idx;

      self.len = drain_start_idx;

      Drain {
         vec_ref: self,
         drain_start_index: drain_start_idx,
         current_drain_iter_index: drain_start_idx,
         drain_end_index: drain_end_idx,
         original_vec_len: original_len,
         tail_len,
         _marker: PhantomData,
      }
   }

   /// Initializes a freshly-allocated (uninitialized) buffer by cloning `src`
   /// into it. Uses `ptr::write` so the uninitialized destination slots are
   /// never read, never dropped, and no `&mut [T]` is ever formed over them.
   ///
   /// `len` is set only after every write succeeds, so a panic from
   /// `T::clone` leaves the vector at its previous length (0 for a fresh one).
   pub(crate) fn init_from_clone(&mut self, src: &[T])
   where
      T: Clone,
   {
      debug_assert!(src.len() <= self.capacity);

      let ok = self.unlock_memory();
      debug_assert!(
         ok,
         "SecureVec::init_from_clone: unlock_memory failed"
      );

      unsafe {
         let dst = self.ptr.as_ptr();
         for (i, item) in src.iter().enumerate() {
            core::ptr::write(dst.add(i), item.clone());
         }
      }

      self.len = src.len();
      let ok = self.lock_memory();
      assert!(
         ok,
         "SecureVec::init_from_clone: lock_memory failed"
      );
   }
}

impl SecureVec<u8> {
   /// Overwrites `src` at `offset` without changing the length or the capacity.
   ///
   /// Used by the binary codec to back-fill the `u32` length placeholder that
   /// precedes a struct field's framed body, once that body has been written.
   /// The frame is what lets a reader skip a field it does not know about, which
   /// is what makes adding a field a compatible change.
   ///
   /// Unlike the `unlock*` family this returns nothing: it exposes no slice, so
   /// the borrowed window is not left up to the caller.
   ///
   /// # Panics
   ///
   /// Panics if `offset + src.len()` exceeds the current length, or if the
   /// memory cannot be re-locked afterwards. A patch never grows the vector —
   /// use [`extend_from_slice`](Self::extend_from_slice) for that.
   #[cfg(feature = "codec")]
   pub(crate) fn patch_at(&mut self, offset: usize, src: &[u8]) {
      let end = offset
         .checked_add(src.len())
         .expect("SecureVec::patch_at: offset overflow");
      assert!(
         end <= self.len,
         "SecureVec::patch_at: range {offset}..{end} exceeds length {}",
         self.len
      );

      let ok = self.unlock_memory();
      debug_assert!(ok, "SecureVec::patch_at: unlock_memory failed");

      // SAFETY: `end <= self.len`, so `offset..end` lies inside the initialized
      // region of the allocation. `src` is a distinct live slice that cannot
      // overlap it, so the copy is non-overlapping. The length is untouched, so
      // no element is created, duplicated, or dropped here.
      unsafe {
         core::ptr::copy_nonoverlapping(
            src.as_ptr(),
            self.ptr.as_ptr().add(offset),
            src.len(),
         );
      }

      let ok = self.lock_memory();
      assert!(ok, "SecureVec::patch_at: lock_memory failed");
   }
}

impl<T: Clone + Zeroize> Clone for SecureVec<T> {
   fn clone(&self) -> Self {
      let mut new_vec = SecureVec::new_with_capacity(self.capacity).unwrap();
      self.unlock_slice(|src_slice| {
         new_vec.init_from_clone(src_slice);
      });
      new_vec
   }
}

impl<T: Clone + Zeroize, const LENGTH: usize> From<SecureArray<T, LENGTH>> for SecureVec<T> {
   fn from(array: SecureArray<T, LENGTH>) -> Self {
      let mut new_vec = SecureVec::new_with_capacity(LENGTH)
         .expect("Failed to allocate SecureVec during conversion");
      array.unlock(|array_slice| {
         new_vec.init_from_clone(array_slice);
      });
      new_vec
   }
}

impl<T: Zeroize> Drop for SecureVec<T> {
   fn drop(&mut self) {
      unsafe {
         let ok = self.unlock_memory();
         debug_assert!(ok, "SecureVec::drop: unlock_memory failed");

         // Only zero the initialized elements. Zeroizing capacity would try to
         // zeroize uninitialized memory as T, which for Drop types (eg. String)
         // is UB and causes SIGSEGV/SIGABRT.
         let slice = core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len);
         for elem in slice.iter_mut() {
            elem.zeroize();
         }
      }

      #[cfg(feature = "use_os")]
      free(self.ptr);

      #[cfg(not(feature = "use_os"))]
      unsafe {
         // `T::zeroize()` above only covers the initialized elements. Wipe the
         // bytes of the whole allocation as well, so anything a `clear()` left
         // behind (and the spare capacity) is gone before the allocator gets the
         // memory back. Without `use_os` there is no `memsec::free` doing it.
         let byte_size = self.allocated_byte_size();
         let bytes = core::slice::from_raw_parts_mut(self.ptr.as_ptr() as *mut u8, byte_size);
         bytes.zeroize();

         let layout = Layout::from_size_align_unchecked(byte_size, mem::align_of::<T>());
         alloc::alloc::dealloc(self.ptr.as_ptr() as *mut u8, layout);
      }
   }
}

// Note: We intentionally do **not** implement Index / IndexMut.
// Direct indexing (`vec[0]`) would bypass the unlock mechanism and
// access locked memory, causing a segfault. This is by design.
// Always use unlock_slice() / unlock_slice_mut().

/// Upper bound on how much memory a `Deserialize` impl will reserve up front from a
/// format-supplied `size_hint`.
///
/// The hint is advisory and comes from the format, so trusting a huge one would mean
/// locking that much memory before a single element has been read. The vector still grows
/// to whatever the real length turns out to be, so a low cap costs nothing but
/// reallocation.
#[cfg(feature = "serde")]
const MAX_PREALLOCATION_FROM_SIZE_HINT: usize = 4096;

/// Serializes as a byte buffer, matching the `deserialize_bytes` request of the
/// `Deserialize` impl below. Formats that support byte buffers get the contents in one
/// piece rather than element by element; `serde_json` renders either form as an array of
/// numbers, so its output is unchanged.
#[cfg(feature = "serde")]
impl serde::Serialize for SecureVec<u8> {
   fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
   where
      S: serde::Serializer,
   {
      self.unlock_slice(|slice| serializer.serialize_bytes(slice))
   }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SecureVec<u8> {
   fn deserialize<D>(deserializer: D) -> Result<SecureVec<u8>, D::Error>
   where
      D: serde::Deserializer<'de>,
   {
      struct SecureVecVisitor;
      impl<'de> serde::de::Visitor<'de> for SecureVecVisitor {
         type Value = SecureVec<u8>;

         fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            write!(formatter, "a sequence or a byte buffer")
         }

         fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
         where
            A: serde::de::SeqAccess<'de>,
         {
            // Reserve what the format advertises, so the locked buffer is not grown
            // (re-allocated and re-`mprotect`ed) once per element — but cap it. The hint
            // comes from the format, and a huge one would otherwise have us lock that
            // much memory before reading a single byte.
            let capacity = seq
               .size_hint()
               .unwrap_or(0)
               .min(MAX_PREALLOCATION_FROM_SIZE_HINT);
            let mut vec =
               SecureVec::new_with_capacity(capacity).map_err(serde::de::Error::custom)?;

            while let Some(byte) = seq.next_element::<u8>()? {
               vec.push(byte);
            }

            Ok(vec)
         }

         /// A format that hands over raw bytes instead of a sequence of `u8`s gets a
         /// single bulk copy straight into locked memory.
         fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
         where
            E: serde::de::Error,
         {
            SecureVec::from_slice(v).map_err(serde::de::Error::custom)
         }

         /// Mirrors `SecureString`'s `visit_string`: wipe the owned buffer the format
         /// handed over, instead of letting it drop with the plaintext inside.
         fn visit_byte_buf<E>(self, mut v: Vec<u8>) -> Result<Self::Value, E>
         where
            E: serde::de::Error,
         {
            let vec = self.visit_bytes(&v)?;
            v.zeroize();
            Ok(vec)
         }
      }

      deserializer.deserialize_bytes(SecureVecVisitor)
   }
}

/// Elements that a [`SecureVec`] or [`SecureArray`] encodes as a *sequence of values*
/// rather than as one byte buffer.
///
/// [`u8`] is deliberately absent. A `u8` container is a byte string, so it encodes as a
/// single bulk buffer — the compact form, and one unlock/lock cycle instead of one per
/// element. A blanket impl that covered `u8` too would overlap with the byte-buffer impls
/// above, and Rust has no specialization, so each element type opts in here instead.
///
/// Implemented for the core scalar types. Implement it for your own type to make
/// `SecureVec<T>` and `SecureArray<T, N>` serializable. It is a safe trait: implementing it
/// only selects an encoding.
#[cfg(feature = "serde")]
pub trait SeqElement: Zeroize {}

#[cfg(feature = "serde")]
impl SeqElement for bool {}

#[cfg(feature = "serde")]
impl SeqElement for char {}

#[cfg(feature = "serde")]
impl SeqElement for f32 {}

#[cfg(feature = "serde")]
impl SeqElement for f64 {}

#[cfg(feature = "serde")]
impl SeqElement for i8 {}

#[cfg(feature = "serde")]
impl SeqElement for i16 {}

#[cfg(feature = "serde")]
impl SeqElement for i32 {}

#[cfg(feature = "serde")]
impl SeqElement for i64 {}

#[cfg(feature = "serde")]
impl SeqElement for i128 {}

#[cfg(feature = "serde")]
impl SeqElement for u16 {}

#[cfg(feature = "serde")]
impl SeqElement for u32 {}

#[cfg(feature = "serde")]
impl SeqElement for u64 {}

#[cfg(feature = "serde")]
impl SeqElement for u128 {}

/// Serializes a `SecureVec<T>` of [`SeqElement`]s as a sequence of `T` values.
///
/// `SecureVec<u8>` takes the byte-buffer impl above instead; the bound here is what keeps
/// the two disjoint.
#[cfg(feature = "serde")]
impl<T> serde::Serialize for SecureVec<T>
where
   T: SeqElement + serde::Serialize,
{
   fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
   where
      S: serde::Serializer,
   {
      use serde::ser::SerializeSeq;

      let mut seq = serializer.serialize_seq(Some(self.len()))?;

      // One unlock for the whole run. Element writes are per element, which for these
      // types is unavoidable: the container cannot hand a `&[T]` to a format that asked
      // for a sequence.
      let elements: Result<(), S::Error> = self.unlock_slice(|slice| {
         for item in slice {
            seq.serialize_element(item)?;
         }

         Ok(())
      });
      elements?;

      seq.end()
   }
}

/// Deserializes a `SecureVec<T>` of [`SeqElement`]s from a sequence of `T` values.
#[cfg(feature = "serde")]
impl<'de, T> serde::Deserialize<'de> for SecureVec<T>
where
   T: SeqElement + serde::Deserialize<'de>,
{
   fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
   where
      D: serde::Deserializer<'de>,
   {
      struct SecureSeqVisitor<T>(PhantomData<T>);

      impl<'de, T> serde::de::Visitor<'de> for SecureSeqVisitor<T>
      where
         T: SeqElement + serde::Deserialize<'de>,
      {
         type Value = SecureVec<T>;

         fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
            write!(formatter, "a sequence of secure elements")
         }

         fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
         where
            A: serde::de::SeqAccess<'de>,
         {
            // The same capped reservation as the byte-buffer visitor: the hint comes from
            // the format and is only advisory.
            let capacity = seq
               .size_hint()
               .unwrap_or(0)
               .min(MAX_PREALLOCATION_FROM_SIZE_HINT);
            let mut vec =
               SecureVec::new_with_capacity(capacity).map_err(serde::de::Error::custom)?;

            while let Some(item) = seq.next_element::<T>()? {
               vec.push(item);
            }

            Ok(vec)
         }
      }

      deserializer.deserialize_seq(SecureSeqVisitor::<T>(PhantomData))
   }
}

/// A draining iterator for `SecureVec<T>`.
///
/// This struct is created by the `drain` method on `SecureVec`.
///
/// # Notes
///
/// The memory is unlocked only while an item is read and while `Drop` compacts the
/// vector, so a leaked iterator (`mem::forget`) leaves the vector locked rather than
/// exposed. Leaking it still skips the drops of the elements left in the drained
/// range and leaves the length at the drain start.
pub struct Drain<'a, T: Zeroize + 'a> {
   vec_ref: &'a mut SecureVec<T>,
   drain_start_index: usize,
   current_drain_iter_index: usize,
   drain_end_index: usize,

   original_vec_len: usize, // Original length of vec_ref before drain
   tail_len: usize,         // Number of elements after the drain range in the original vec

   _marker: PhantomData<&'a T>,
}

impl<'a, T: Zeroize> Iterator for Drain<'a, T> {
   type Item = T;

   fn next(&mut self) -> Option<T> {
      if self.current_drain_iter_index >= self.drain_end_index {
         return None;
      }

      // Raw pointer taken before the guard borrows the vector: raw pointers do not
      // keep the borrow alive, and the guard must stay alive while we read through it.
      let base = self.vec_ref.ptr.as_ptr();

      // Unlock for this single read only, so the memory is locked again as soon as
      // this returns — and stays locked if the iterator is forgotten.
      let _guard = UnlockGuard::new(&*self.vec_ref);

      let item = unsafe { ptr::read(base.add(self.current_drain_iter_index)) };
      self.current_drain_iter_index += 1;

      Some(item)
   }

   fn size_hint(&self) -> (usize, Option<usize>) {
      let remaining = self.drain_end_index - self.current_drain_iter_index;
      (remaining, Some(remaining))
   }
}

impl<'a, T: Zeroize> ExactSizeIterator for Drain<'a, T> {}

impl<'a, T: Zeroize> Drain<'a, T> {
   /// Unlocks the vector, compacts it, and re-locks it again.
   ///
   /// Returns the vector's new length. The `UnlockGuard` re-locks the memory even
   /// if the compaction panics, so a leaked or panicking iterator never leaves the
   /// vector exposed.
   fn compact(&self) -> usize {
      // Raw pointer taken before the guard borrows the vector: raw pointers do not
      // keep the borrow alive, and the guard must stay alive while we compact.
      let base = self.vec_ref.ptr.as_ptr();

      let _guard = UnlockGuard::new(&*self.vec_ref);

      unsafe {
         if mem::needs_drop::<T>() {
            let mut current_ptr = base.add(self.current_drain_iter_index);
            let end_ptr = base.add(self.drain_end_index);
            while current_ptr < end_ptr {
               ptr::drop_in_place(current_ptr);
               current_ptr = current_ptr.add(1);
            }
         }

         let hole_dst_ptr = base.add(self.drain_start_index);
         let tail_src_ptr = base.add(self.drain_end_index);

         if self.tail_len > 0 {
            ptr::copy(tail_src_ptr, hole_dst_ptr, self.tail_len);
         }

         // The new length of the vector.
         let new_len = self.drain_start_index + self.tail_len;

         // Process the memory region that is no longer part of the active vector's content.
         // This region is from `vec_ref.ptr + new_len` up to `vec_ref.ptr + original_vec_len`.
         // It contains:
         //    a) Original data of the latter part of the drained slice (if not overwritten by tail).
         //       These were dropped in step 1 if T:Drop.
         //    b) Original data of the tail items (which have now been copied).
         //       These need to be dropped if T:Drop, as ptr::copy doesn't drop the source.
         // After any necessary drops, this entire region must be zeroized.

         let mut current_cleanup_ptr = base.add(new_len);
         let end_cleanup_ptr = base.add(self.original_vec_len);

         // Determine the start of the original tail's memory region
         let original_tail_start_ptr_val = tail_src_ptr as usize;

         while current_cleanup_ptr < end_cleanup_ptr {
            if mem::needs_drop::<T>() {
               let current_ptr_val = current_cleanup_ptr as usize;
               let original_tail_end_ptr_val =
                  original_tail_start_ptr_val + self.tail_len * mem::size_of::<T>();

               if current_ptr_val >= original_tail_start_ptr_val
                  && current_ptr_val < original_tail_end_ptr_val
               {
                  // This element was part of the original tail. ptr::copy moved its value.
                  // The original instance here needs to be dropped.
                  ptr::drop_in_place(current_cleanup_ptr);
               }
               // Else, it was part of the drained range (not covered by tail move).
               // If it needed dropping, it was handled in step 1.
            }

            // Zeroize the memory of this element.
            (*current_cleanup_ptr).zeroize();
            current_cleanup_ptr = current_cleanup_ptr.add(1);
         }

         new_len
      }
   }
}

impl<'a, T: Zeroize> Drop for Drain<'a, T> {
   fn drop(&mut self) {
      let new_len = self.compact();

      // `compact` re-locked the memory before returning.
      self.vec_ref.len = new_len;
   }
}

// Helper function to resolve RangeBounds to (start, end) indices
fn resolve_range_indices<R: RangeBounds<usize>>(range: R, len: usize) -> (usize, usize) {
   let start_bound = range.start_bound();
   let end_bound = range.end_bound();

   let start = match start_bound {
      Bound::Included(&s) => s,
      Bound::Excluded(&s) => s
         .checked_add(1)
         .unwrap_or_else(|| panic!("attempted to start drain at Excluded(usize::MAX)")),
      Bound::Unbounded => 0,
   };

   let end = match end_bound {
      Bound::Included(&e) => e
         .checked_add(1)
         .unwrap_or_else(|| panic!("attempted to end drain at Included(usize::MAX)")),
      Bound::Excluded(&e) => e,
      Bound::Unbounded => len,
   };

   if start > end {
      panic!(
         "drain range start ({}) must be less than or equal to end ({})",
         start, end
      );
   }
   if end > len {
      panic!(
         "drain range end ({}) out of bounds for slice of length {}",
         end, len
      );
   }

   (start, end)
}

#[cfg(all(test, feature = "use_os"))]
mod tests {
   use super::*;
   use std::process::{Command, Stdio};

   #[test]
   fn lock_unlock_works() {
      let secure: SecureVec<u8> = SecureVec::new().unwrap();

      let unlocked = secure.unlock_memory();
      assert!(unlocked);

      let locked = secure.lock_memory();
      assert!(locked);
   }

   #[cfg(feature = "codec")]
   #[test]
   fn test_patch_at_overwrites_in_place() {
      let mut secure = SecureBytes::from_slice(b"abcdefgh").unwrap();

      secure.patch_at(2, b"XY");

      secure.unlock_slice(|bytes| {
         assert_eq!(bytes, b"abXYefgh");
         assert_eq!(bytes.len(), 8);
      });
   }

   #[cfg(feature = "codec")]
   #[test]
   fn test_patch_at_last_bytes_and_whole_buffer() {
      let mut secure = SecureBytes::from_slice(b"abcdefgh").unwrap();

      secure.patch_at(6, b"XY");
      secure.unlock_slice(|bytes| assert_eq!(bytes, b"abcdefXY"));

      secure.patch_at(0, b"12345678");
      secure.unlock_slice(|bytes| assert_eq!(bytes, b"12345678"));
   }

   #[cfg(feature = "codec")]
   #[test]
   fn test_patch_at_empty_source_is_a_noop() {
      let mut secure = SecureBytes::from_slice(b"abc").unwrap();

      // A zero-length patch is valid inside the buffer and at its very end.
      secure.patch_at(0, b"");
      secure.patch_at(3, b"");

      secure.unlock_slice(|bytes| assert_eq!(bytes, b"abc"));
   }

   #[cfg(feature = "codec")]
   #[test]
   fn test_patch_at_leaves_length_and_capacity_alone() {
      let mut secure = SecureBytes::new_with_capacity(16).unwrap();
      secure.extend_from_slice(b"abc");
      let capacity_before = secure.unlock(|vec| vec.capacity);

      secure.patch_at(0, b"ZY");

      secure.unlock(|vec| {
         assert_eq!(vec.len, 3);
         assert_eq!(vec.capacity, capacity_before);
      });
      secure.unlock_slice(|bytes| assert_eq!(bytes, b"ZYc"));
   }

   #[cfg(feature = "codec")]
   #[test]
   fn test_patch_at_survives_reallocation() {
      // Growth moves the buffer to a new locked allocation; the patch must land
      // in the live one rather than a stale pointer.
      let mut secure = SecureBytes::new().unwrap();
      secure.extend_from_slice(b"first");
      secure.reserve(4096);
      secure.extend_from_slice(b"second");

      secure.patch_at(0, b"FIRST");

      secure.unlock_slice(|bytes| assert_eq!(bytes, b"FIRSTsecond"));
   }

   #[cfg(feature = "codec")]
   #[test]
   #[should_panic(expected = "exceeds length")]
   fn test_patch_at_straddling_the_end_panics() {
      let mut secure = SecureBytes::from_slice(b"abc").unwrap();

      secure.patch_at(2, b"XY");
   }

   #[cfg(feature = "codec")]
   #[test]
   #[should_panic(expected = "exceeds length")]
   fn test_patch_at_past_the_end_panics() {
      let mut secure = SecureBytes::from_slice(b"abc").unwrap();

      secure.patch_at(4, b"");
   }

   #[test]
   fn test_forgotten_drain_keeps_memory_locked() {
      let arg = "CRASH_TEST_DRAIN_FORGET_LOCKED";

      if std::env::args().any(|a| a == arg) {
         let vec: Vec<u8> = vec![1, 2, 3, 4, 5];
         let mut secure = SecureVec::from_vec(vec).unwrap();
         let drain = secure.drain(..3);
         core::mem::forget(drain);

         // A leaked `Drain` must not leave the vector exposed: this read is
         // expected to fault because the memory is still locked.
         let _value = unsafe { core::hint::black_box(*secure.ptr.as_ptr()) };

         std::process::exit(1);
      }

      let child = Command::new(std::env::current_exe().unwrap())
         .arg("vec::tests::test_forgotten_drain_keeps_memory_locked")
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
            "Process exited with unexpected code: {:x?}.",
            status.code()
         );
      }
   }

   #[test]
   fn test_index_should_fail_when_locked() {
      let arg = "CRASH_TEST_SECUREVEC_LOCKED";

      if std::env::args().any(|a| a == arg) {
         let vec: Vec<u8> = vec![1, 2, 3];
         let secure = SecureVec::from_vec(vec).unwrap();
         // Deliberately dereference the locked pointer to test that
         // the security model (mlock + no normal access) works as expected.
         let _value = unsafe { core::hint::black_box(*secure.ptr.as_ptr()) };

         std::process::exit(1);
      }

      let child = Command::new(std::env::current_exe().unwrap())
         .arg("vec::tests::test_index_should_fail_when_locked")
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
