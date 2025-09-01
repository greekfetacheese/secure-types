#[cfg(not(feature = "std"))]
use alloc::{Layout, alloc, dealloc};

#[cfg(feature = "std")]
use std::vec::Vec;

use super::{Error, SecureArray};
use core::{
   marker::PhantomData,
   mem,
   ops::{Bound, RangeBounds},
   ptr::{self, NonNull},
};
use zeroize::{DefaultIsZeroes, Zeroize};

#[cfg(feature = "std")]
use super::page_aligned_size;
#[cfg(feature = "std")]
use memsec::Prot;

pub type SecureBytes = SecureVec<u8>;

/// A securely allocated, growable vector, analogous to `std::vec::Vec`.
///
/// `SecureVec<T>` is designed to hold a sequence of sensitive data elements. It serves as the
/// foundational secure collection in this crate.
///
/// ## Security Model
///
/// When compiled with the `std` feature (the default), it provides several layers of protection:
/// - **Zeroization on Drop**: The memory region is securely zeroized when the vector is dropped.
/// - **Memory Locking**: The underlying memory pages are locked using `mlock` (Unix) or
///   `VirtualLock` (Windows) to prevent the OS from swapping them to disk.
/// - **Memory Encryption**: On Windows, the memory is also encrypted using `CryptProtectMemory`.
///
/// In a `no_std` environment, it falls back to providing only the **zeroization-on-drop** guarantee.
///
/// ## Program Termination
///
/// Direct indexing (e.g., `vec[0]`) on a locked vector will cause the operating system
/// to terminate the process with an access violation error.
///
/// Always use the provided scope methods (`slice_scope`, `slice_mut_scope`) for safe access.
///
/// # Examples
///
/// Using `SecureBytes` (a type alias for `SecureVec<u8>`) to handle a secret key.
///
/// ```
/// use secure_types::SecureBytes;
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
///     println!("Secret Key: {:?}", unlocked_slice);
/// });
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
unsafe impl<T: Zeroize + Send + Sync> Sync for SecureVec<T> {}

impl<T: Zeroize> SecureVec<T> {
   pub fn new() -> Result<Self, Error> {
      // Give at least a capacity of 1 so encryption/decryption can be done.
      let capacity = 1;
      let size = capacity * mem::size_of::<T>();

      #[cfg(feature = "std")]
      let ptr = unsafe {
         let aligned_size = page_aligned_size(size);
         let allocated_ptr = memsec::malloc_sized(aligned_size);
         let ptr = allocated_ptr.ok_or(Error::AllocationFailed)?;
         ptr.as_ptr() as *mut T
      };

      #[cfg(not(feature = "std"))]
      let ptr = {
         let layout = Layout::from_size_align(size, mem::align_of::<T>())
            .map_err(|_| Error::AllocationFailed)?;
         let ptr = unsafe { alloc::alloc(layout) as *mut T };
         if ptr.is_null() {
            return Err(Error::AllocationFailed);
         }
         ptr
      };

      let non_null = NonNull::new(ptr).ok_or(Error::NullAllocation)?;
      let secure = SecureVec {
         ptr: non_null,
         len: 0,
         capacity,
         _marker: PhantomData,
      };

      let (encrypted, locked) = secure.lock_memory();

      #[cfg(feature = "std")]
      if !locked {
         return Err(Error::LockFailed);
      }

      #[cfg(feature = "std")]
      if !encrypted {
         return Err(Error::CryptProtectMemoryFailed);
      }

      Ok(secure)
   }

   pub fn new_with_capacity(mut capacity: usize) -> Result<Self, Error> {
      if capacity == 0 {
         capacity = 1;
      }

      let size = capacity * mem::size_of::<T>();

      #[cfg(feature = "std")]
      let ptr = unsafe {
         let aligned_size = page_aligned_size(size);
         let allocated_ptr = memsec::malloc_sized(aligned_size);
         let ptr = allocated_ptr.ok_or(Error::AllocationFailed)?;
         ptr.as_ptr() as *mut T
      };

      #[cfg(not(feature = "std"))]
      let ptr = {
         let layout = Layout::from_size_align(size, mem::align_of::<T>())
            .map_err(|_| Error::AllocationFailed)?;
         let ptr = unsafe { alloc::alloc(layout) as *mut T };
         if ptr.is_null() {
            return Err(Error::AllocationFailed);
         }
         ptr
      };

      let non_null = NonNull::new(ptr).ok_or(Error::NullAllocation)?;

      let secure = SecureVec {
         ptr: non_null,
         len: 0,
         capacity,
         _marker: PhantomData,
      };

      let (encrypted, locked) = secure.lock_memory();

      #[cfg(feature = "std")]
      if !locked {
         return Err(Error::LockFailed);
      }

      #[cfg(feature = "std")]
      if !encrypted {
         return Err(Error::CryptProtectMemoryFailed);
      }

      Ok(secure)
   }

   #[cfg(feature = "std")]
   pub fn from_vec(mut vec: Vec<T>) -> Result<Self, Error> {
      if vec.capacity() == 0 {
         vec.reserve(1);
      }

      let capacity = vec.capacity();
      let len = vec.len();

      // Allocate memory
      let size = capacity * mem::size_of::<T>();

      let ptr = unsafe {
         let aligned_size = page_aligned_size(size);
         let allocated_ptr = memsec::malloc_sized(aligned_size);
         if allocated_ptr.is_none() {
            vec.zeroize();
            return Err(Error::AllocationFailed);
         } else {
            allocated_ptr.unwrap().as_ptr() as *mut T
         }
      };

      // Copy data from the old pointer to the new one
      unsafe {
         core::ptr::copy_nonoverlapping(vec.as_ptr(), ptr, len);
      }

      // Zeroize and drop the original Vec
      vec.zeroize();
      drop(vec);

      let non_null = NonNull::new(ptr).ok_or(Error::NullAllocation)?;

      let secure = SecureVec {
         ptr: non_null,
         len,
         capacity,
         _marker: PhantomData,
      };

      let (encrypted, locked) = secure.lock_memory();

      if !locked {
         return Err(Error::LockFailed);
      }

      if !encrypted {
         return Err(Error::CryptProtectMemoryFailed);
      }

      Ok(secure)
   }

   /// Create a new `SecureVec` from a mutable slice.
   /// The slice is zeroized afterwards
   pub fn from_slice_mut(slice: &mut [T]) -> Result<Self, Error>
   where
      T: Clone + DefaultIsZeroes,
   {
      let mut secure_vec = SecureVec::new_with_capacity(slice.len())?;
      secure_vec.len = slice.len();
      secure_vec.unlock_slice_mut(|dest_slice| {
         dest_slice.clone_from_slice(slice);
      });
      slice.zeroize();
      Ok(secure_vec)
   }

   /// Create a new `SecureVec` from a slice.
   /// The slice is not zeroized, you are responsible for zeroizing it
   pub fn from_slice(slice: &[T]) -> Result<Self, Error>
   where
      T: Clone,
   {
      let mut secure_vec = SecureVec::new_with_capacity(slice.len())?;
      secure_vec.len = slice.len();
      secure_vec.unlock_slice_mut(|dest_slice| {
         dest_slice.clone_from_slice(slice);
      });
      Ok(secure_vec)
   }

   pub fn len(&self) -> usize {
      self.len
   }

   pub fn as_ptr(&self) -> *const T {
      self.ptr.as_ptr()
   }

   pub fn as_mut_ptr(&mut self) -> *mut u8 {
      self.ptr.as_ptr() as *mut u8
   }

   #[allow(dead_code)]
   fn aligned_size(&self) -> usize {
      let size = self.capacity * mem::size_of::<T>();
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

   /// Lock the memory region
   ///
   /// On Windows also calls `CryptProtectMemory` to encrypt the memory
   ///
   /// On Unix it just calls `mprotect` to lock the memory
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

   /// Unlock the memory region
   ///
   /// On Windows also calls `CryptUnprotectMemory` to decrypt the memory
   ///
   /// On Unix it just calls `mprotect` to unlock the memory
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

   /// Immutable access to the `SecureVec`
   pub fn unlock<F, R>(&self, f: F) -> R
   where
      F: FnOnce(&SecureVec<T>) -> R,
   {
      self.unlock_memory();
      let result = f(self);
      self.lock_memory();
      result
   }

   /// Immutable access to the `SecureVec` as `&[T]`
   pub fn unlock_slice<F, R>(&self, f: F) -> R
   where
      F: FnOnce(&[T]) -> R,
   {
      unsafe {
         self.unlock_memory();
         let slice = core::slice::from_raw_parts(self.ptr.as_ptr(), self.len);
         let result = f(slice);
         self.lock_memory();
         result
      }
   }

   /// Mutable access to the `SecureVec` as `&mut [T]`
   pub fn unlock_slice_mut<F, R>(&mut self, f: F) -> R
   where
      F: FnOnce(&mut [T]) -> R,
   {
      unsafe {
         self.unlock_memory();
         let slice = core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len);
         let result = f(slice);
         self.lock_memory();
         result
      }
   }

   /// Immutable access to the `SecureVec` as `Iter<T>`
   ///
   /// ## Use with caution
   ///
   /// You can actually return a new allocated `Vec` from this function
   ///
   /// If you do that you are responsible for zeroizing its contents
   pub fn unlock_iter<F, R>(&self, f: F) -> R
   where
      F: FnOnce(core::slice::Iter<T>) -> R,
   {
      unsafe {
         self.unlock_memory();
         let slice = core::slice::from_raw_parts(self.ptr.as_ptr(), self.len);
         let iter = slice.iter();
         let result = f(iter);
         self.lock_memory();
         result
      }
   }

   /// Mutable access to the `SecureVec` as `IterMut<T>`
   ///
   /// ## Use with caution
   ///
   /// You can actually return a new allocated `Vec` from this function
   ///
   /// If you do that you are responsible for zeroizing its contents
   pub fn unlock_iter_mut<F, R>(&mut self, f: F) -> R
   where
      F: FnOnce(core::slice::IterMut<T>) -> R,
   {
      unsafe {
         self.unlock_memory();
         let slice = core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len);
         let iter = slice.iter_mut();
         let result = f(iter);
         self.lock_memory();
         result
      }
   }

   /// Erase the underlying data and clears the vector
   ///
   /// The memory is locked again and the capacity is preserved for reuse
   pub fn erase(&mut self) {
      unsafe {
         self.unlock_memory();
         let slice = core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len);
         for elem in slice.iter_mut() {
            elem.zeroize();
         }
         self.clear();
         self.lock_memory();
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

      self.unlock_memory();

      unsafe {
         // Write the new value at the end of the vector.
         core::ptr::write(self.ptr.as_ptr().add(self.len), value);

         self.len += 1;
      }

      self.lock_memory();
   }

   /// Ensures that the vector has enough capacity for at least `additional` more elements.
   ///
   /// If more capacity is needed, it will reallocate. This may cause the buffer location to change.
   ///
   /// # Panics
   ///
   /// Panics if the new capacity overflows `usize` or if the allocation fails.
   pub fn reserve(&mut self, additional: usize) {
      if self.len() + additional <= self.capacity {
         return;
      }

      // Use an amortized growth strategy to avoid reallocating on every push
      let required_capacity = self.len() + additional;
      let new_capacity = (self.capacity.max(1) * 2).max(required_capacity);

      let new_items_byte_size = new_capacity * mem::size_of::<T>();

      // Allocate new memory
      #[cfg(feature = "std")]
      let new_ptr = unsafe {
         let aligned_allocation_size = page_aligned_size(new_items_byte_size);
         memsec::malloc_sized(aligned_allocation_size)
            .expect("Failed to allocate memory for SecureVec reserve")
            .as_ptr() as *mut T
      };

      #[cfg(not(feature = "std"))]
      let new_ptr = {
         let layout = Layout::from_size_align(new_items_byte_size, mem::align_of::<T>())
            .expect("Failed to create layout for SecureVec reserve");
         let ptr = unsafe { alloc::alloc(layout) as *mut T };
         if ptr.is_null() {
            panic!("Memory allocation failed for SecureVec reserve");
         }
         ptr
      };

      // Copy data to new pointer, then erase and free old memory
      unsafe {
         self.unlock_memory();
         core::ptr::copy_nonoverlapping(self.ptr.as_ptr(), new_ptr, self.len());

         // Erase and free the old memory
         if self.capacity > 0 {
            let slice = core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len);
            for elem in slice.iter_mut() {
               elem.zeroize();
            }
         }
         #[cfg(feature = "std")]
         memsec::free(self.ptr);

         #[cfg(not(feature = "std"))]
         {
            let old_size = self.capacity * mem::size_of::<T>();
            let old_layout = Layout::from_size_align_unchecked(old_size, mem::align_of::<T>());
            dealloc(self.ptr.as_ptr() as *mut u8, old_layout);
         }
      }

      // Update pointer and capacity, then re-lock the new memory region
      self.ptr = NonNull::new(new_ptr).expect("New pointer was null");
      self.capacity = new_capacity;
      self.lock_memory();
   }

   /// Creates a draining iterator that removes the specified range from the vector
   /// and yields the removed items.
   ///
   /// Note: The vector is unlocked during the lifetime of the `Drain` iterator.
   /// The memory is relocked when the `Drain` iterator is dropped.
   ///
   /// # Panics
   /// Panics if the starting point is greater than the end point or if the end point
   /// is greater than the length of the vector.
   pub fn drain<R>(&mut self, range: R) -> Drain<'_, T>
   where
      R: RangeBounds<usize>,
   {
      self.unlock_memory();

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
}

impl<T: Clone + Zeroize> Clone for SecureVec<T> {
   fn clone(&self) -> Self {
      let mut new_vec = SecureVec::new_with_capacity(self.capacity).unwrap();
      new_vec.len = self.len;

      self.unlock_slice(|src_slice| {
         new_vec.unlock_slice_mut(|dest_slice| {
            dest_slice.clone_from_slice(src_slice);
         });
      });

      new_vec
   }
}

impl<const LENGTH: usize> From<SecureArray<u8, LENGTH>> for SecureVec<u8> {
   fn from(array: SecureArray<u8, LENGTH>) -> Self {
      let mut new_vec = SecureVec::new_with_capacity(LENGTH)
         .expect("Failed to allocate SecureVec during conversion");
      new_vec.len = array.len();

      array.unlock(|array_slice| {
         new_vec.unlock_slice_mut(|vec_slice| {
            vec_slice.copy_from_slice(array_slice);
         });
      });

      new_vec
   }
}

impl<T: Zeroize> Drop for SecureVec<T> {
   fn drop(&mut self) {
      self.erase();
      self.unlock_memory();
      unsafe {
         #[cfg(feature = "std")]
         memsec::free(self.ptr);

         #[cfg(not(feature = "std"))]
         {
            // Recreate the layout to deallocate correctly
            let layout =
               Layout::from_size_align_unchecked(self.allocated_byte_size(), mem::align_of::<T>());
            dealloc(self.ptr.as_ptr() as *mut u8, layout);
         }
      }
   }
}

impl<T: Zeroize> core::ops::Index<usize> for SecureVec<T> {
   type Output = T;

   fn index(&self, index: usize) -> &Self::Output {
      assert!(index < self.len, "Index out of bounds");
      unsafe {
         let ptr = self.ptr.as_ptr().add(index);
         let reference = &*ptr;
         reference
      }
   }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SecureVec<u8> {
   fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
   where
      S: serde::Serializer,
   {
      self.unlock_slice(|slice| serializer.collect_seq(slice.iter()))
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
            write!(formatter, "a sequence of bytes")
         }
         fn visit_seq<A>(
            self,
            mut seq: A,
         ) -> Result<<Self as serde::de::Visitor<'de>>::Value, A::Error>
         where
            A: serde::de::SeqAccess<'de>,
         {
            let mut vec = Vec::new();
            while let Some(byte) = seq.next_element::<u8>()? {
               vec.push(byte);
            }
            SecureVec::from_vec(vec).map_err(serde::de::Error::custom)
         }
      }
      deserializer.deserialize_seq(SecureVecVisitor)
   }
}

/// A draining iterator for `SecureVec<T>`.
///
/// This struct is created by the `drain` method on `SecureVec`.
///
/// # Safety
/// The returned `Drain` iterator must not be forgotten (via `mem::forget`).
/// Forgetting the iterator sets the len of `SecureVec` to 0 and the memory will remain unlocked
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
      if self.current_drain_iter_index < self.drain_end_index {
         // SecureVec is already unlocked by the `drain` method.
         unsafe {
            let item_ptr = self.vec_ref.ptr.as_ptr().add(self.current_drain_iter_index);
            let item = ptr::read(item_ptr);
            self.current_drain_iter_index += 1;
            Some(item)
         }
      } else {
         None
      }
   }

   fn size_hint(&self) -> (usize, Option<usize>) {
      let remaining = self.drain_end_index - self.current_drain_iter_index;
      (remaining, Some(remaining))
   }
}

impl<'a, T: Zeroize> ExactSizeIterator for Drain<'a, T> {}

impl<'a, T: Zeroize> Drop for Drain<'a, T> {
   fn drop(&mut self) {
      unsafe {
         // The vec_ref's memory is currently unlocked.
         if mem::needs_drop::<T>() {
            let mut current_ptr =
               self.vec_ref.ptr.as_ptr().add(self.current_drain_iter_index) as *mut T;
            let end_ptr = self.vec_ref.ptr.as_ptr().add(self.drain_end_index) as *mut T;
            while current_ptr < end_ptr {
               ptr::drop_in_place(current_ptr);
               current_ptr = current_ptr.add(1);
            }
         }

         let hole_dst_ptr = self.vec_ref.ptr.as_ptr().add(self.drain_start_index) as *mut T;
         let tail_src_ptr = self.vec_ref.ptr.as_ptr().add(self.drain_end_index) as *mut T;

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

         let mut current_cleanup_ptr = self.vec_ref.ptr.as_ptr().add(new_len) as *mut T;
         let end_cleanup_ptr = self.vec_ref.ptr.as_ptr().add(self.original_vec_len) as *mut T;

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

         // Update the SecureVec's length.
         self.vec_ref.len = new_len;

         // Relock the SecureVec's memory.
         self.vec_ref.lock_memory();
      }
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

#[cfg(all(test, feature = "std"))]
mod tests {
   use super::*;
   use std::process::{Command, Stdio};
   use std::sync::{Arc, Mutex};

   #[test]
   fn test_from_methods() {
      let vec: Vec<u8> = vec![1, 2, 3];
      let secure_vec = SecureVec::from_vec(vec).unwrap();

      secure_vec.unlock_slice(|slice| {
         assert_eq!(slice, &[1, 2, 3]);
      });

      let mut slice = [3u8, 5];
      let secure_slice = SecureVec::from_slice_mut(&mut slice).unwrap();
      assert_eq!(slice, [0, 0]);

      secure_slice.unlock_slice(|slice| {
         assert_eq!(slice, &[3, 5]);
      });

      let slice = [3u8, 5];
      let secure_slice = SecureVec::from_slice(&slice).unwrap();

      secure_slice.unlock_slice(|slice| {
         assert_eq!(slice, &[3, 5]);
      });
   }

   #[test]
   fn test_from_secure_array() {
      let array: SecureArray<u8, 3> = SecureArray::new([1, 2, 3]).unwrap();
      let vec: SecureVec<u8> = array.into();
      assert_eq!(vec.len(), 3);
      vec.unlock_slice(|slice| {
         assert_eq!(slice, &[1, 2, 3]);
      });
   }

   #[test]
   fn lock_unlock() {
      let secure: SecureVec<u8> = SecureVec::new().unwrap();
      let size = secure.aligned_size();
      assert_eq!(size > 0, true);

      let (decrypted, unlocked) = secure.unlock_memory();
      assert!(decrypted);
      assert!(unlocked);

      let (encrypted, locked) = secure.lock_memory();
      assert!(encrypted);
      assert!(locked);

      let secure: SecureVec<u8> = SecureVec::from_vec(vec![]).unwrap();
      let size = secure.aligned_size();
      assert_eq!(size > 0, true);

      let (decrypted, unlocked) = secure.unlock_memory();
      assert!(decrypted);
      assert!(unlocked);

      let (encrypted, locked) = secure.lock_memory();
      assert!(encrypted);
      assert!(locked);

      let secure: SecureVec<u8> = SecureVec::new_with_capacity(0).unwrap();
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
   fn test_thread_safety() {
      let vec: Vec<u8> = vec![];
      let secure = SecureVec::from_vec(vec).unwrap();
      let secure = Arc::new(Mutex::new(secure));

      let mut handles = Vec::new();
      for i in 0..5u8 {
         let secure_clone = secure.clone();
         let handle = std::thread::spawn(move || {
            let mut secure = secure_clone.lock().unwrap();
            secure.push(i);
         });
         handles.push(handle);
      }

      for handle in handles {
         handle.join().unwrap();
      }

      let sec = secure.lock().unwrap();
      sec.unlock_slice(|slice| {
         assert_eq!(slice.len(), 5);
      });
   }

   #[test]
   fn test_clone() {
      let vec: Vec<u8> = vec![1, 2, 3];
      let secure1 = SecureVec::from_vec(vec).unwrap();
      let secure2 = secure1.clone();

      secure1.unlock_slice(|slice| {
         secure2.unlock_slice(|slice2| {
            assert_eq!(slice, slice2);
         });
      });
   }

   #[test]
   fn test_do_not_call_forget_on_drain() {
      let vec: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
      let mut secure = SecureVec::from_vec(vec).unwrap();
      let drain = secure.drain(..3);
      core::mem::forget(drain);
      // we can still use secure vec but its state is unreachable
      secure.unlock_slice(|secure| {
         assert_eq!(secure.len(), 0);
      });
   }

   #[test]
   fn test_drain() {
      let vec: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
      let mut secure = SecureVec::from_vec(vec).unwrap();
      let mut drain = secure.drain(..3);
      assert_eq!(drain.next(), Some(1));
      assert_eq!(drain.next(), Some(2));
      assert_eq!(drain.next(), Some(3));
      assert_eq!(drain.next(), None);
      drop(drain);
      secure.unlock_slice(|secure| {
         assert_eq!(secure.len(), 7);
         assert_eq!(secure, &[4, 5, 6, 7, 8, 9, 10]);
      });
   }

   #[cfg(feature = "serde")]
   #[test]
   fn test_secure_vec_serde() {
      let vec: Vec<u8> = vec![1, 2, 3];
      let secure = SecureVec::from_vec(vec).unwrap();
      let json = serde_json::to_vec(&secure).expect("Serialization failed");
      let deserialized: SecureVec<u8> =
         serde_json::from_slice(&json).expect("Deserialization failed");
      deserialized.unlock_slice(|slice| {
         assert_eq!(slice, &[1, 2, 3]);
      });
   }

   #[test]
   fn test_erase() {
      let vec: Vec<u8> = vec![1, 2, 3];
      let mut secure = SecureVec::from_vec(vec).unwrap();
      secure.erase();
      secure.unlock(|secure| {
         assert_eq!(secure.len, 0);
         assert_eq!(secure.capacity, 3);
      });

      secure.push(1);
      secure.push(2);
      secure.push(3);
      secure.unlock(|secure| {
         assert_eq!(secure[0], 1);
         assert_eq!(secure[1], 2);
         assert_eq!(secure[2], 3);
         assert_eq!(secure.len, 3);
         assert_eq!(secure.capacity, 3);
      });
   }

   #[test]
   fn test_push() {
      let vec: Vec<u8> = Vec::new();
      let mut secure = SecureVec::from_vec(vec).unwrap();
      for i in 0..30 {
         secure.push(i);
      }
   }

   #[test]
   fn test_reserve() {
      let mut secure: SecureVec<u8> = SecureVec::new().unwrap();
      secure.reserve(10);
      assert_eq!(secure.capacity, 10);
   }

   #[test]
   fn test_reserve_doubling() {
      let mut secure: SecureVec<u8> = SecureVec::new().unwrap();
      secure.reserve(10);

      for i in 0..9 {
         secure.push(i);
      }

      secure.push(9);
      assert_eq!(secure.capacity, 10);
      assert_eq!(secure.len(), 10);

      secure.push(10);
      assert_eq!(secure.capacity, 20);
      assert_eq!(secure.len(), 11);
   }

   #[test]
   fn test_index() {
      let vec: Vec<u8> = vec![1, 2, 3];
      let secure = SecureVec::from_vec(vec).unwrap();
      secure.unlock(|secure| {
         assert_eq!(secure[0], 1);
         assert_eq!(secure[1], 2);
         assert_eq!(secure[2], 3);
      });
   }

   #[test]
   fn test_slice_scoped() {
      let vec: Vec<u8> = vec![1, 2, 3];
      let secure = SecureVec::from_vec(vec).unwrap();
      secure.unlock_slice(|slice| {
         assert_eq!(slice, &[1, 2, 3]);
      });
   }

   #[test]
   fn test_slice_mut_scoped() {
      let vec: Vec<u8> = vec![1, 2, 3];
      let mut secure = SecureVec::from_vec(vec).unwrap();

      secure.unlock_slice_mut(|slice| {
         slice[0] = 4;
         assert_eq!(slice, &mut [4, 2, 3]);
      });

      secure.unlock_slice(|slice| {
         assert_eq!(slice, &[4, 2, 3]);
      });
   }

   #[test]
   fn test_iter_scoped() {
      let vec: Vec<u8> = vec![1, 2, 3];
      let secure = SecureVec::from_vec(vec).unwrap();
      let sum: u8 = secure.unlock_iter(|iter| iter.map(|&x| x).sum());

      assert_eq!(sum, 6);

      let secure: SecureVec<u8> = SecureVec::new_with_capacity(3).unwrap();
      let sum: u8 = secure.unlock_iter(|iter| iter.map(|&x| x).sum());

      assert_eq!(sum, 0);
   }

   #[test]
   fn test_iter_mut_scoped() {
      let vec: Vec<u8> = vec![1, 2, 3];
      let mut secure = SecureVec::from_vec(vec).unwrap();
      secure.unlock_iter_mut(|iter| {
         for elem in iter {
            *elem += 1;
         }
      });

      secure.unlock_slice(|slice| {
         assert_eq!(slice, &[2, 3, 4]);
      });
   }

   #[test]
   fn test_index_should_fail_when_locked() {
      let arg = "CRASH_TEST_SECUREVEC_LOCKED";

      if std::env::args().any(|a| a == arg) {
         let vec: Vec<u8> = vec![1, 2, 3];
         let secure = SecureVec::from_vec(vec).unwrap();
         let _value = core::hint::black_box(secure[0]);

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
