use super::page_size;
use core::{mem, ptr::NonNull};
use memsec::{Prot, mprotect};
use zeroize::Zeroize;

pub struct SecureArray<T, const LENGTH: usize>
where
   T: Zeroize,
{
   ptr: NonNull<T>,
   content: [T; LENGTH],
}

impl<T, const LENGTH: usize> SecureArray<T, LENGTH>
where
   T: Zeroize,
{
   pub fn new(mut content: [T; LENGTH]) -> Self {
      let size = LENGTH * mem::size_of::<T>();
      let aligned_size = (size + page_size() - 1) & !(page_size() - 1);
      let new_ptr = unsafe {
         memsec::malloc_sized(aligned_size)
            .expect("Failed to allocate secure memory")
            .as_ptr() as *mut T
      };

      let ptr = content.as_ptr();
      unsafe {
         std::ptr::copy_nonoverlapping(ptr, new_ptr, LENGTH);
      }

      content.zeroize();

      let secure_array = SecureArray {
         ptr: NonNull::new(new_ptr).expect("Failed to create NonNull"),
         content,
      };

      secure_array.lock_memory();
      secure_array
   }

   pub fn as_ptr(&self) -> *const T {
      self.ptr.as_ptr()
   }

   pub fn as_mut_ptr(&mut self) -> *mut u8 {
      self.ptr.as_ptr() as *mut u8
   }

   pub(crate) fn lock_memory(&self) {
      unsafe {
         let success = mprotect(self.ptr, Prot::NoAccess);
         if !success {
            panic!("LockMemory failed");
         }
      }
   }

   pub(crate) fn unlock_memory(&self) {
      unsafe {
         let success = mprotect(self.ptr, Prot::ReadWrite);
         if !success {
            panic!("UnlockMemory failed");
         }
      }
   }

   pub fn unlock_scope<F, R>(&self, f: F) -> R
   where
      F: FnOnce(&SecureArray<T, LENGTH>) -> R,
   {
      self.unlock_memory();
      let result = f(self);
      self.lock_memory();
      result
   }

   pub fn mut_scope<F, R>(&mut self, f: F) -> R
   where
      F: FnOnce(&mut SecureArray<T, LENGTH>) -> R,
   {
      self.unlock_memory();
      let result = f(self);
      self.lock_memory();
      result
   }

   pub fn erase(&mut self) {
      self.unlock_memory();
      self.content.zeroize();
   }
}





impl<T, const LENGTH: usize> From<[T; LENGTH]> for SecureArray<T, LENGTH>
where
    T: Zeroize,
{
    fn from(s: [T; LENGTH]) -> Self {
        Self::new(s)
    }
}