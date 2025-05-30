use super::{Error, page_size};
use core::{
   marker::PhantomData,
   mem,
   ops::{Bound, RangeBounds},
   ptr::{self, NonNull},
};
use memsec::Prot;
use zeroize::Zeroize;

pub type SecureBytes = SecureVec<u8>;

/// A vector that allocates memory in a secure manner
///
/// It does that by calling `VirtualLock` & `VirtualProtect` on Windows and `mlock` & `mprotect` on Unix.
/// 
/// On `Windows` it also calls `CryptProtectMemory` & `CryptUnprotectMemory` to encrypt/decrypt the memory
///
/// The data is protected from:
///
/// - Disk swaps (eg. due to insufficient RAM)
/// - Reads/writes by other processes
/// - Core dumps
///
/// This type is safe to clone, any clone will have its own secure allocation.
///
/// On `Drop`, the data is securely zeroed out.
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
      let aligned_size = (size + page_size() - 1) & !(page_size() - 1);
      let ptr = unsafe {
         let allocated_ptr = memsec::malloc_sized(aligned_size);
         let ptr = allocated_ptr.ok_or(Error::AllocationFailed)?;
         ptr.as_ptr() as *mut T
      };

      let non_null = NonNull::new(ptr).ok_or(Error::NullAllocation)?;
      let secure = SecureVec {
         ptr: non_null,
         len: 0,
         capacity,
         _marker: std::marker::PhantomData,
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

   pub fn with_capacity(mut capacity: usize) -> Result<Self, Error> {
      if capacity == 0 {
         capacity = 1;
      }

      let size = capacity * mem::size_of::<T>();
      let aligned_size = (size + page_size() - 1) & !(page_size() - 1); // Round up to page size

      let ptr = unsafe {
         let allocated_ptr = memsec::malloc_sized(aligned_size);
         let ptr = allocated_ptr.ok_or(Error::AllocationFailed)?;
         ptr.as_ptr() as *mut T
      };

      let non_null = NonNull::new(ptr).ok_or(Error::NullAllocation)?;

      let secure = SecureVec {
         ptr: non_null,
         len: 0,
         capacity,
         _marker: std::marker::PhantomData,
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

   pub fn from_vec(mut vec: Vec<T>) -> Result<Self, Error> {
      if vec.capacity() == 0 {
         vec.reserve(1);
      }

      let capacity = vec.capacity();
      let len = vec.len();

      // Allocate secure memory
      let size = capacity * mem::size_of::<T>();
      let aligned_size = (size + page_size() - 1) & !(page_size() - 1);

      let ptr = unsafe {
         let allocated_ptr = memsec::malloc_sized(aligned_size);
         if allocated_ptr.is_none() {
            vec.zeroize();
            return Err(Error::AllocationFailed);
         } else {
            allocated_ptr.unwrap().as_ptr() as *mut T
         }
      };

      // Copy data from Vec to secure memory
      unsafe {
         std::ptr::copy_nonoverlapping(vec.as_ptr(), ptr, len);
      }

      // Zeroize and drop the original Vec
      vec.zeroize();
      drop(vec);

      let non_null = NonNull::new(ptr).ok_or(Error::NullAllocation)?;

      let secure = SecureVec {
         ptr: non_null,
         len,
         capacity,
         _marker: std::marker::PhantomData,
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

   pub fn len(&self) -> usize {
      self.len
   }

   pub fn as_ptr(&self) -> *const T {
      self.ptr.as_ptr()
   }

   pub fn as_mut_ptr(&mut self) -> *mut u8 {
      self.ptr.as_ptr() as *mut u8
   }

   fn allocated_byte_size(&self) -> usize {
      (self.capacity * mem::size_of::<T>() + page_size() - 1) & !(page_size() - 1)
   }

   #[cfg(windows)]
   fn encypt_memory(&self) -> bool {
      let ptr = self.as_ptr() as *mut u8;
      super::crypt_protect_memory(ptr, self.allocated_byte_size())
   }

   #[cfg(windows)]
   fn decrypt_memory(&self) -> bool {
      let ptr = self.as_ptr() as *mut u8;
      super::crypt_unprotect_memory(ptr, self.allocated_byte_size())
   }

   /// Lock the memory region
   ///
   /// On Windows also calls `CryptProtectMemory` to encrypt the memory
   ///
   /// On Unix it just calls `mprotect` to lock the memory
   pub(crate) fn lock_memory(&self) -> (bool, bool) {
      #[cfg(windows)]
      {
         let encrypt_ok = self.encypt_memory();
         let mprotect_ok = unsafe { memsec::mprotect(self.ptr, Prot::NoAccess) };
         (encrypt_ok, mprotect_ok)
      }

      #[cfg(unix)]
      {
         let mprotect_ok = unsafe { memsec::mprotect(self.ptr, Prot::NoAccess) };
         (true, mprotect_ok)
      }
   }

   /// Unlock the memory region
   ///
   /// On Windows also calls `CryptUnprotectMemory` to decrypt the memory
   ///
   /// On Unix it just calls `mprotect` to unlock the memory
   pub(crate) fn unlock_memory(&self) -> (bool, bool) {
      #[cfg(windows)]
      {
         let mprotect_ok = unsafe { memsec::mprotect(self.ptr, Prot::ReadWrite) };

         if !mprotect_ok {
            return (false, false);
         }

         let decrypt_ok = self.decrypt_memory();
         (decrypt_ok, mprotect_ok)
      }

      #[cfg(unix)]
      {
         let mprotect_ok = unsafe { memsec::mprotect(self.ptr, Prot::ReadWrite) };
         (true, mprotect_ok)
      }
   }

   /// Immutable access to the `SecureVec`
   pub fn unlock_scope<F, R>(&self, f: F) -> R
   where
      F: FnOnce(&SecureVec<T>) -> R,
   {
      self.unlock_memory();
      let result = f(self);
      self.lock_memory();
      result
   }

   /// Immutable access to the `SecureVec` as `&[T]`
   pub fn slice_scope<F, R>(&self, f: F) -> R
   where
      F: FnOnce(&[T]) -> R,
   {
      unsafe {
         self.unlock_memory();
         let slice = std::slice::from_raw_parts(self.ptr.as_ptr(), self.len);
         let result = f(slice);
         self.lock_memory();
         result
      }
   }

   /// Mutable access to the `SecureVec` as `&mut [T]`
   pub fn slice_mut_scope<F, R>(&mut self, f: F) -> R
   where
      F: FnOnce(&mut [T]) -> R,
   {
      unsafe {
         self.unlock_memory();
         let slice = std::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len);
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
   pub fn iter_scope<F, R>(&self, f: F) -> R
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
   pub fn iter_mut_scope<F, R>(&mut self, f: F) -> R
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
   /// This just sets the vector's len to zero it does not erase the elements
   pub fn clear(&mut self) {
      self.len = 0;
   }

   pub fn push(&mut self, value: T) {
      if self.len >= self.capacity {
         // Reallocate
         let new_capacity = if self.capacity == 0 {
            1
         } else {
            self.capacity + 1
         };

         let new_size = new_capacity * mem::size_of::<T>();

         // Allocate new secure memory
         let new_ptr = unsafe {
            memsec::malloc_sized(new_size)
               .expect("Failed to allocate secure memory")
               .as_ptr() as *mut T
         };

         // Copy data to new ptr, erase and free old memory
         unsafe {
            self.unlock_memory();
            core::ptr::copy_nonoverlapping(self.ptr.as_ptr(), new_ptr, self.len);
            if self.capacity > 0 {
               let slice = core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len);
               for elem in slice.iter_mut() {
                  elem.zeroize();
               }
            }
            memsec::free(self.ptr);
         }

         // Update pointer and capacity
         self.ptr = NonNull::new(new_ptr).expect("Failed to create NonNull");
         self.capacity = new_capacity;

         // write and lock
         unsafe {
            std::ptr::write(self.ptr.as_ptr().add(self.len), value);
            self.len += 1;
            self.lock_memory();
         }
      } else {
         // Unlock, write, and relock
         unsafe {
            self.unlock_memory();
            std::ptr::write(self.ptr.as_ptr().add(self.len), value);
            self.len += 1;
            self.lock_memory();
         }
      }
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
      let mut new_vec: SecureVec<T> = SecureVec::with_capacity(self.capacity).unwrap();

      new_vec.unlock_memory();
      self.unlock_memory();

      unsafe {
         for i in 0..self.len {
            let value = (*self.ptr.as_ptr().add(i)).clone();
            core::ptr::write(new_vec.ptr.as_ptr().add(i), value);
         }
      }

      new_vec.len = self.len;
      self.lock_memory();
      new_vec.lock_memory();
      new_vec
   }
}

impl<T: Zeroize> Drop for SecureVec<T> {
   fn drop(&mut self) {
      self.erase();
      self.unlock_memory();
      unsafe {
         memsec::free(self.ptr);
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
      let res = self.slice_scope(|slice| serializer.collect_seq(slice.iter()));
      res
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
///
/// The `Drain` iterator relies on being dropped to correctly handle memory
/// (moving tail elements, zeroizing drained portions, and relocking memory).
/// If `mem::forget` is called on `Drain`, the `SecureVec` will have its length
/// zeroed, but the memory for the drained elements and tail might not be
/// properly zeroized or relocked, potentially leading to data exposure if
/// `memsec::free` doesn't zeroize.
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

#[cfg(test)]
mod tests {
   use super::*;
   use std::sync::{Arc, Mutex};

   #[test]
   fn test_creation() {
      let vec: Vec<u8> = vec![1, 2, 3];
      let _ = SecureVec::from_vec(vec);
      let _: SecureVec<u8> = SecureVec::new().unwrap();
      let _: SecureVec<u8> = SecureVec::with_capacity(3).unwrap();
   }

   #[test]
   fn lock_unlock() {
      let secure: SecureVec<u8> = SecureVec::new().unwrap();
      let size = secure.allocated_byte_size();
      assert_eq!(size > 0, true);

      let (decrypted, unlocked) = secure.unlock_memory();
      assert!(decrypted);
      assert!(unlocked);

      let (encrypted, locked) = secure.lock_memory();
      assert!(encrypted);
      assert!(locked);

      let secure: SecureVec<u8> = SecureVec::from_vec(vec![]).unwrap();
      let size = secure.allocated_byte_size();
      assert_eq!(size > 0, true);

      let (decrypted, unlocked) = secure.unlock_memory();
      assert!(decrypted);
      assert!(unlocked);

      let (encrypted, locked) = secure.lock_memory();
      assert!(encrypted);
      assert!(locked);

      let secure: SecureVec<u8> = SecureVec::with_capacity(0).unwrap();
      let size = secure.allocated_byte_size();
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
      for i in 0..10u8 {
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
      sec.slice_scope(|slice| {
         assert_eq!(slice.len(), 10);
      });
   }

   #[test]
   fn test_clone() {
      let vec: Vec<u8> = vec![1, 2, 3];
      let secure1 = SecureVec::from_vec(vec).unwrap();
      let _secure2 = secure1.clone();
   }

   #[test]
   fn test_do_not_call_forget_on_drain() {
      let vec: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
      let mut secure = SecureVec::from_vec(vec).unwrap();
      let drain = secure.drain(..3);
      core::mem::forget(drain);
      // we can still use secure vec but its state is unreachable
      secure.slice_scope(|secure| {
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
      secure.slice_scope(|secure| {
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
      deserialized.slice_scope(|slice| {
         assert_eq!(slice, &[1, 2, 3]);
      });
   }

   #[test]
   fn test_erase() {
      let vec: Vec<u8> = vec![1, 2, 3];
      let mut secure = SecureVec::from_vec(vec).unwrap();
      secure.erase();
      secure.unlock_scope(|secure| {
         assert_eq!(secure.len, 0);
         assert_eq!(secure.capacity, 3);
      });

      secure.push(1);
      secure.push(2);
      secure.push(3);
      secure.unlock_scope(|secure| {
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
      secure.push(1);
      secure.push(2);
      secure.push(3);
      secure.slice_scope(|slice| {
         assert_eq!(slice, &[1, 2, 3]);
      });

      let mut secure = SecureVec::with_capacity(3).unwrap();
      secure.push(1);
      secure.push(2);
      secure.push(3);
      secure.slice_scope(|slice| {
         assert_eq!(slice, &[1, 2, 3]);
      });
   }

   #[test]
   fn test_index() {
      let vec: Vec<u8> = vec![1, 2, 3];
      let secure = SecureVec::from_vec(vec).unwrap();
      secure.unlock_scope(|secure| {
         assert_eq!(secure[0], 1);
         assert_eq!(secure[1], 2);
         assert_eq!(secure[2], 3);
      });
   }

   #[test]
   fn test_slice_scoped() {
      let vec: Vec<u8> = vec![1, 2, 3];
      let secure = SecureVec::from_vec(vec).unwrap();
      secure.slice_scope(|slice| {
         assert_eq!(slice, &[1, 2, 3]);
      });
   }

   #[test]
   fn test_slice_mut_scoped() {
      let vec: Vec<u8> = vec![1, 2, 3];
      let mut secure = SecureVec::from_vec(vec).unwrap();

      secure.slice_mut_scope(|slice| {
         slice[0] = 4;
         assert_eq!(slice, &mut [4, 2, 3]);
      });

      secure.slice_scope(|slice| {
         assert_eq!(slice, &[4, 2, 3]);
      });
   }

   #[test]
   fn test_iter_scoped() {
      let vec: Vec<u8> = vec![1, 2, 3];
      let secure = SecureVec::from_vec(vec).unwrap();
      let sum: u8 = secure.iter_scope(|iter| iter.map(|&x| x).sum());

      assert_eq!(sum, 6);

      let secure: SecureVec<u8> = SecureVec::with_capacity(3).unwrap();
      let sum: u8 = secure.iter_scope(|iter| iter.map(|&x| x).sum());

      assert_eq!(sum, 0);
   }

   #[test]
   fn test_iter_mut_scoped() {
      let vec: Vec<u8> = vec![1, 2, 3];
      let mut secure = SecureVec::from_vec(vec).unwrap();
      secure.iter_mut_scope(|iter| {
         for elem in iter {
            *elem += 1;
         }
      });

      secure.slice_scope(|slice| {
         assert_eq!(slice, &[2, 3, 4]);
      });
   }
}
