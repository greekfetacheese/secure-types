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

use super::{Error, SecureArray, alloc, zero_bytes};
use crate::array::SourceWipe;
use core::{
   marker::PhantomData,
   mem,
   ops::{Bound, RangeBounds},
   ptr::{self, NonNull},
};
use zeroize::Zeroize;
#[cfg(feature = "serde")]
use zeroize::Zeroizing;

#[cfg(feature = "use_os")]
use super::free;
#[cfg(feature = "use_os")]
use secure_alloc::Prot;

pub type SecureBytes = SecureVec<u8>;

/// Unlocks the vector's memory on construction and re-locks it on drop —
/// including when the drop happens because the fn closure panicked.
pub(crate) struct UnlockGuard<'a, T: Zeroize> {
   vec: &'a SecureVec<T>,
}

impl<'a, T: Zeroize> UnlockGuard<'a, T> {
   pub(crate) fn new(vec: &'a SecureVec<T>) -> Self {
      let ok = vec.unlock_memory();
      crate::abort_if_protected(ok, "SecureVec::unlock");

      UnlockGuard { vec }
   }
}

impl<'a, T: Zeroize> Drop for UnlockGuard<'a, T> {
   fn drop(&mut self) {
      let ok = self.vec.lock_memory();
      // Failing to re-lock means the protection is silently gone while the value is
      // still alive, so this is a hard error in every profile.
      crate::abort_if_protected(ok, "SecureVec::lock");
   }
}

/// Zeroizes and drops the slots a loop has filled but not committed.
///
/// The owning container commits `len` / `initialized` only after the whole loop, so
/// a panic from `T::clone` leaves the already-written values in the secure
/// allocation. Without this guard they would be neither dropped nor zeroized: their
/// heap payloads (a `String`'s buffer, a `Vec`'s allocation) would outlive the
/// container. `clear` and `Drain::compact` use it for the same reason: the slots
/// they have not discarded yet still hold live values.
pub(crate) struct InitGuard<T: Zeroize> {
   ptr: *mut T,
   written: usize,
}

impl<T: Zeroize> InitGuard<T> {
   /// # Safety
   ///
   /// `ptr` must be the base of a live, exclusively owned allocation of at least
   /// as many writable `T` slots as the loop writes, unprotected for this guard's
   /// whole lifetime. Every slot below `written` must hold a live `T` once
   /// `wrote` has recorded it, and nothing else may drop it.
   pub(crate) unsafe fn new(ptr: *mut T) -> Self {
      InitGuard { ptr, written: 0 }
   }

   /// Records that the slot at `index` now holds a live `T`.
   pub(crate) fn wrote(&mut self, index: usize) {
      self.set_written(index + 1);
   }

   /// Records how many slots currently hold a live `T`.
   ///
   /// `wrote` is the fill-loop spelling, where the count only grows. A discard loop
   /// has to lower it after each element, and a slot stays live until its
   /// `drop_in_place` runs — `zeroize` alone can panic.
   pub(crate) fn set_written(&mut self, written: usize) {
      self.written = written;
   }

   /// Hands the written prefix back to the container, which now tracks it.
   pub(crate) fn commit(mut self) {
      self.written = 0;
   }
}

impl<T: Zeroize> Drop for InitGuard<T> {
   fn drop(&mut self) {
      for i in 0..self.written {
         // SAFETY: `wrote` only recorded slots this guard's constructor proved
         // live and writable, the container still counts them as uninitialised,
         // and nothing else holds a reference to them — so each one is zeroized
         // and dropped exactly once. Zeroize first, while the value is still
         // valid, then run the destructor (a `String`'s buffer is freed here).
         unsafe {
            let slot = self.ptr.add(i);
            (*slot).zeroize();
            core::ptr::drop_in_place(slot);
         }
      }
   }
}

/// Frees a container's allocation when it goes out of scope.
///
/// A container's `Drop` runs element destructors before it releases the region, and a
/// destructor that panics unwinds straight past the release: the region then stays mapped
/// — on the `memfd_secret` path `rw-s`, outside any `unlock*` scope — with the plaintext
/// still in it. Owning the free in a guard declared before the loop makes it run on every
/// exit path, the unwind included.
pub(crate) struct FreeGuard<T> {
   ptr: NonNull<T>,
   #[cfg_attr(feature = "use_os", allow(dead_code))]
   byte_size: usize,
}

impl<T> FreeGuard<T> {
   /// # Safety
   ///
   /// `ptr` must be the container's live allocation and `byte_size` its full byte count;
   /// the allocation is freed exactly once, when this guard drops.
   pub(crate) unsafe fn new(ptr: NonNull<T>, byte_size: usize) -> Self {
      FreeGuard { ptr, byte_size }
   }
}

impl<T> Drop for FreeGuard<T> {
   fn drop(&mut self) {
      #[cfg(feature = "use_os")]
      free(self.ptr);

      #[cfg(not(feature = "use_os"))]
      // SAFETY: `byte_size` is the full allocation size, still owned here; the `Layout`
      // matches the one `alloc` used. Byte-wiping it also removes anything a `clear()`
      // left behind, which `use_os` gets from `secure_alloc::free` instead.
      unsafe {
         zero_bytes(self.ptr.as_ptr() as *mut u8, self.byte_size);

         let layout = Layout::from_size_align_unchecked(self.byte_size, mem::align_of::<T>());
         alloc::alloc::dealloc(self.ptr.as_ptr() as *mut u8, layout);
      }
   }
}
/// Zeroizes and drops a `Drain`'s not-yet-moved tail if compaction unwinds first.
///
/// `Drain::compact` discards the unyielded drained elements before it copies the tail
/// down. A destructor that panics in that loop unwinds past the copy, so without this
/// guard the tail elements are owned by nobody: their `Drop` never runs and the buffers
/// they own keep their plaintext. The guard is armed until the copy has moved them.
struct TailGuard<T: Zeroize> {
   base: *mut T,
   start: usize,
   len: usize,
   armed: bool,
}

impl<T: Zeroize> TailGuard<T> {
   /// # Safety
   ///
   /// `base.add(start .. start + len)` must be live, initialized `T` slots of the
   /// allocation the caller has unprotected, and nothing else may drop them while this
   /// guard is armed.
   unsafe fn new(base: *mut T, start: usize, len: usize) -> Self {
      TailGuard {
         base,
         start,
         len,
         armed: true,
      }
   }

   /// Hands the tail to the caller once the copy has moved it.
   fn disarm(&mut self) {
      self.armed = false;
   }
}

impl<T: Zeroize> Drop for TailGuard<T> {
   fn drop(&mut self) {
      if !self.armed {
         return;
      }

      for offset in (0..self.len).rev() {
         // SAFETY: the constructor proved the range live; the guard is declared after
         // the `UnlockGuard`, so it is dropped while the pages are still open, and each
         // slot is zeroized and dropped exactly once.
         unsafe {
            let slot = self.base.add(self.start + offset);
            (*slot).zeroize();
            ptr::drop_in_place(slot);
         }
      }
   }
}

/// A securely allocated, growable vector, just like `std::vec::Vec`.
///
/// ## Security Model
///
/// When compiled with the `use_os` feature (the default), it provides several layers of protection:
/// - **Zeroization on Drop**: The memory is zeroized and every element is dropped when the vector
///   is dropped.
/// - **Memory Locking**: the allocation is `mprotect`ed `PROT_NONE` outside an access scope —
///   an `unlock*` call, or one of this type's own operations that must touch the bytes
///   (`push`, `clear`/`erase`, `drain`, `reserve`, `Clone`, conversions, serde `Serialize`,
///   and `Drop`) — which stops accidental reads, this process's included, but is not a defence
///   against `ptrace` or a debugger. On the malloc path it is also
///   `mlock`ed on a best-effort basis (the call's result is discarded, so hitting
///   `RLIMIT_MEMLOCK` still constructs; Windows: `VirtualLock`) and, where the OS supports it,
///   excluded from core dumps (`MADV_DONTDUMP` on Linux, `MADV_NOCORE` on FreeBSD/DragonFly).
///   Linux uses `memfd_secret` when the kernel supports it; that backing is neither `mlock`ed
///   nor marked `MADV_DONTDUMP`.
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
      // SAFETY: `alloc` is `unsafe` only as a raw-allocation marker — it has no
      // preconditions beyond rejecting a zero `size`, and returns a pointer
      // aligned for `T`.
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

      let size = capacity
         .checked_mul(size_of::<T>())
         .ok_or(Error::AllocationFailed)?;

      // SAFETY: as in `new` — `alloc` has no preconditions beyond a non-zero
      // `size`, and `size` here is `capacity * size_of::<T>()` for `capacity >= 1`.
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
   /// The `Vec` is zeroized afterwards — on the error paths too.
   ///
   /// # Errors
   ///
   /// Returns [`Error::AllocationFailed`] for any failure to allocate, including
   /// an over-aligned `T` that the other constructors report as
   /// [`Error::AlignmentFailed`], and [`Error::LockFailed`] if the new region
   /// cannot be locked.
   pub fn from_vec(mut vec: Vec<T>) -> Result<Self, Error> {
      if vec.capacity() == 0 {
         // `Vec::reserve` aborts on allocation failure, which would skip the wipe and
         // the `Error::AllocationFailed` this function documents.
         if vec.try_reserve(1).is_err() {
            vec.zeroize();
            return Err(Error::AllocationFailed);
         }
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

      // SAFETY: `alloc` is `unsafe` only as a raw-allocation marker — it has no
      // preconditions beyond rejecting a zero `size`. `size` is
      // `capacity * size_of::<T>()` for `capacity >= 1`.
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
      //
      // SAFETY: `len <= capacity` elements are initialized in `vec`, and `dst`
      // points at a fresh allocation of at least `capacity` elements. Each slot is
      // moved (read + write), never duplicated, and `vec`'s length is zeroed right
      // after so it cannot drop them again.
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
      // SAFETY: every element in `0..len` was moved out above, so `len` must be
      // zero before `vec` is dropped; the buffer stays owned by `vec`.
      unsafe {
         vec.set_len(0);
      }
      // Wiped as bytes: the slots past `len` were never written, so they are only
      // reachable as bytes, not as a `&mut [T]`.
      //
      // SAFETY: after `set_len(0)` the allocation is still owned here and is valid
      // for writes of `old_byte_size` bytes; no `T` will be dropped by the `Vec`.
      unsafe {
         zero_bytes(vec.as_mut_ptr() as *mut u8, old_byte_size);
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
   /// The slice is zeroized afterwards — including when a `T::clone` panics while
   /// the vector is being filled.
   pub fn from_slice_mut(slice: &mut [T]) -> Result<Self, Error>
   where
      T: Clone,
   {
      // Wipes the caller's buffer on every way out of this function, the unwind from
      // a panicking `T::clone` in `init_from_clone` included: a wipe placed after the
      // copy loop is bypassed by the panic.
      let wipe = SourceWipe::new(slice);

      let mut secure_vec = SecureVec::new_with_capacity(wipe.as_slice().len())?;
      secure_vec.init_from_clone(wipe.as_slice());

      drop(wipe);

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
   /// Growth reallocates the region and re-locks it, so this bounds how many
   /// elements can be appended between two reallocations. It is not a bound on
   /// unlock/lock cycles: [`push`](Self::push) unlocks and re-locks per element.
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
   ///
   /// # Re-entrancy
   ///
   /// The closure must not call another `unlock*` method on this vector: the
   /// pages are unprotected once and re-protected when this call returns, so a
   /// nested unlock would re-lock the memory while the inner scope is still
   /// reading it. The same holds for every `unlock*` method.
   ///
   /// Aborts with a diagnostic if the memory-protection call fails.
   pub fn unlock<F, R>(&self, f: F) -> R
   where
      F: FnOnce(&SecureVec<T>) -> R,
   {
      let _guard = UnlockGuard::new(self);
      f(self)
   }

   /// Immutable access to the `SecureVec` as `&[T]`
   ///
   /// The re-entrancy rule of [`unlock`](Self::unlock) applies here: the closure
   /// must not call another `unlock*` method on this vector.
   ///
   /// Aborts with a diagnostic if the memory-protection call fails.
   pub fn unlock_slice<F, R>(&self, f: F) -> R
   where
      F: FnOnce(&[T]) -> R,
   {
      let _guard = UnlockGuard::new(self);
      // SAFETY: the guard unprotects the live allocation, `len` counts only
      // initialized elements, so the slice is in bounds and never reads an
      // uninitialised slot; `&self` rules out a concurrent `&mut`.
      let slice = unsafe { core::slice::from_raw_parts(self.ptr.as_ptr(), self.len) };
      f(slice)
   }

   /// Mutable access to the `SecureVec` as `&mut [T]`
   ///
   /// The re-entrancy rule of [`unlock`](Self::unlock) applies here: the closure
   /// must not call another `unlock*` method on this vector.
   ///
   /// Aborts with a diagnostic if the memory-protection call fails.
   pub fn unlock_slice_mut<F, R>(&mut self, f: F) -> R
   where
      F: FnOnce(&mut [T]) -> R,
   {
      // SAFETY: `&mut self` guarantees exclusive access, the guard unprotects
      // the live allocation, and `len` counts only initialized elements.
      unsafe {
         let _guard = UnlockGuard::new(self);
         let slice = core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len);
         f(slice)
      }
   }

   /// Immutable access to the `SecureVec` as `Iter<T>`
   ///
   /// The re-entrancy rule of [`unlock`](Self::unlock) applies here: the closure
   /// must not call another `unlock*` method on this vector.
   ///
   /// Aborts with a diagnostic if the memory-protection call fails.
   pub fn unlock_iter<F, R>(&self, f: F) -> R
   where
      F: FnOnce(core::slice::Iter<T>) -> R,
   {
      // SAFETY: as in `unlock_slice` — the guard unprotects the live allocation
      // and `len` counts only initialized elements.
      unsafe {
         let _guard = UnlockGuard::new(self);
         let slice = core::slice::from_raw_parts(self.ptr.as_ptr(), self.len);
         let iter = slice.iter();
         f(iter)
      }
   }

   /// Mutable access to the `SecureVec` as `IterMut<T>`
   ///
   /// The re-entrancy rule of [`unlock`](Self::unlock) applies here: the closure
   /// must not call another `unlock*` method on this vector.
   ///
   /// Aborts with a diagnostic if the memory-protection call fails.
   pub fn unlock_iter_mut<F, R>(&mut self, f: F) -> R
   where
      F: FnOnce(core::slice::IterMut<T>) -> R,
   {
      // SAFETY: `&mut self` gives exclusive access; the guard unprotects the
      // live allocation and `len` counts only initialized elements.
      unsafe {
         let _guard = UnlockGuard::new(self);
         let slice = core::slice::from_raw_parts_mut(self.ptr.as_ptr(), self.len);
         let iter = slice.iter_mut();
         f(iter)
      }
   }

   /// Erase the underlying data and clears the vector
   ///
   /// Same as [`clear`](Self::clear): every live element is zeroized and dropped, and the
   /// capacity is preserved for reuse.
   pub fn erase(&mut self) {
      self.clear();
   }

   /// Clears the vector, zeroizing and dropping every element.
   ///
   /// The drop is the part that matters for a `T` that owns heap memory (a `String`, a
   /// `Vec<u8>`, a struct of them): zeroizing wipes what the element points at, and dropping
   /// releases that allocation. Zeroizing alone would leave both the allocation and — for a
   /// container that abandoned the element without a wipe — the plaintext behind.
   ///
   /// The capacity is preserved for reuse and the memory is re-locked afterwards.
   pub fn clear(&mut self) {
      let len = self.len;
      if len == 0 {
         return;
      }

      // The length is reset *before* any destructor runs: a panicking `T::drop` must not
      // leave the vector claiming an element this loop has already dropped, or the vector's
      // own `Drop` would drop it a second time.
      self.len = 0;

      let _guard = UnlockGuard::new(self);

      // SAFETY: the guard unprotects the live allocation; the `len` slots were initialized
      // and are now outside the vector's length, so each is zeroized and dropped exactly once
      // here. Dropping from the back keeps the loop correct regardless of order. The
      // `InitGuard` covers the slots the loop has not reached yet, so a destructor that
      // panics discards them instead of orphaning them — an orphaned element's owned buffer
      // is freed by nobody and keeps its plaintext.
      unsafe {
         let ptr = self.ptr.as_ptr();

         // `written` counts the live prefix from `ptr`. Slots above `i` are already
         // discarded; `i` itself stays live until its `drop_in_place` runs.
         let mut discard = InitGuard::<T>::new(ptr);
         discard.set_written(len);

         for i in (0..len).rev() {
            // `zeroize` can panic too, so the slot is still the guard's until the drop
            // below takes ownership of it.
            discard.set_written(i + 1);
            (*ptr.add(i)).zeroize();
            discard.set_written(i);
            core::ptr::drop_in_place(ptr.add(i));
         }

         discard.commit();
      }
   }

   /// Appends `value` to the back.
   ///
   /// # Panics
   ///
   /// Panics if the vector has to grow and the new capacity overflows `usize` or
   /// the allocation fails — the contract of [`reserve`](Self::reserve), which this
   /// calls first.
   pub fn push(&mut self, value: T) {
      self.reserve(1);

      let dst = self.ptr.as_ptr();
      let write_at = self.len;

      {
         let _guard = UnlockGuard::new(self);

         // SAFETY: `write_at == self.len` and `reserve(1)` above guaranteed
         // `len < capacity`, so the slot is in bounds; it is uninitialised, and
         // `ptr::write` does not read it. `value` is moved in exactly once.
         unsafe {
            core::ptr::write(dst.add(write_at), value);
         }
      }

      self.len = write_at + 1;
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
   pub(crate) fn extend_from_slice(&mut self, src: &[T]) -> Result<(), Error>
   where
      T: Clone,
   {
      if src.is_empty() {
         return Ok(());
      }

      self.try_reserve(src.len())?;

      let write_at = self.len;
      let dst = self.ptr.as_ptr();

      {
         let _guard = UnlockGuard::new(self);

         // SAFETY: `try_reserve` above made room for `src.len()` more elements,
         // so every `dst.add(write_at + i)` is an uninitialised in-bounds slot;
         // `ptr::write` never reads it. `len` is committed only after the loop.
         unsafe {
            // SAFETY: `dst.add(write_at)` is the first of the reserved slots in
            // the live allocation the `UnlockGuard` above unprotects, the
            // `InitGuard` is dropped before the region is re-locked, and `wrote`
            // records exactly the slots that hold a live `T`.
            let mut init = InitGuard::new(dst.add(write_at));

            for (i, item) in src.iter().enumerate() {
               core::ptr::write(dst.add(write_at + i), item.clone());
               init.wrote(i);
            }

            init.commit();
         }
      }

      self.len = write_at + src.len();
      Ok(())
   }

   /// Ensures that the vector has enough capacity for at least `additional` more elements.
   ///
   /// If more capacity is needed, it will reallocate. This may cause the buffer location to change.
   ///
   /// # Panics
   ///
   /// Panics if the new capacity overflows `usize` or if the allocation fails.
   pub fn reserve(&mut self, additional: usize) {
      self.try_reserve(additional).unwrap_or_else(|error| {
         panic!(
            "secure-types: SecureVec::reserve overflow or allocation failed ({error}); SecureVec left unchanged"
         )
      });
   }

   /// Fallible [`reserve`](Self::reserve). The codec uses this so growth is an
   /// [`Error`] rather than a panic, matching [`EncodeError::Secure`].
   ///
   /// The one failure this cannot report is a protection call: the new region is
   /// re-locked after `self.ptr` and `capacity` have been updated, and returning an
   /// error there would hand back a live vector with readable pages, so it aborts
   /// (see `abort_if_protected`).
   pub(crate) fn try_reserve(&mut self, additional: usize) -> Result<(), Error> {
      let required_capacity = self
         .len
         .checked_add(additional)
         .ok_or(Error::AllocationFailed)?;

      if required_capacity <= self.capacity {
         return Ok(());
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

      let new_size = new_capacity
         .checked_mul(mem::size_of::<T>())
         .ok_or(Error::AllocationFailed)?;

      // SAFETY: `alloc` has no preconditions beyond a non-zero `size`; `new_size`
      // is `new_capacity * size_of::<T>()` and `new_capacity >= required > capacity`.
      let new_ptr = unsafe { alloc::<T>(new_size)? };

      // Copy data to new pointer
      // SAFETY: `new_ptr` is a fresh allocation of `new_capacity >= self.len`
      // elements. Each initialized element is moved (read + write) into it, so
      // ownership transfers exactly once; the old buffer's bytes are wiped and
      // then freed with the layout `alloc` used. `self.ptr`/`capacity` are
      // updated only after this block.
      unsafe {
         let ok = self.unlock_memory();
         crate::abort_if_protected(ok, "SecureVec::try_reserve");

         // Move (not copy) elements to new buffer to support non-Copy T correctly.
         // Using read+write transfers ownership of e.g. Strings.
         let len = self.len();
         for i in 0..len {
            let val = core::ptr::read(self.ptr.as_ptr().add(i));
            core::ptr::write(new_ptr.as_ptr().add(i), val);
         }

         // Erase old buffer bytes (after move-out). The whole capacity is wiped,
         // the slots past `len` that were never written included.
         let old_bytes = self.capacity * mem::size_of::<T>();
         zero_bytes(self.ptr.as_ptr() as *mut u8, old_bytes);

         #[cfg(feature = "use_os")]
         free(self.ptr);

         #[cfg(not(feature = "use_os"))]
         {
            let old_size = self.capacity * mem::size_of::<T>();
            let old_layout = Layout::from_size_align_unchecked(old_size, mem::align_of::<T>());
            alloc::alloc::dealloc(self.ptr.as_ptr() as *mut u8, old_layout);
         }
      }

      // Update pointer and capacity, then re-lock the new memory region. A failure
      // here cannot be reported as an error either: returning `Err` would hand back a
      // live vector whose pages are readable, so this aborts like `Drop` does.
      self.ptr = new_ptr;
      self.capacity = new_capacity;
      let ok = self.lock_memory();
      crate::abort_if_protected(ok, "SecureVec::try_reserve");
      Ok(())
   }

   /// Creates a draining iterator that removes the specified range from the vector
   /// and yields the removed items.
   ///
   /// Note: the memory is only unlocked while an item is read and while the iterator
   /// is dropped, so it is left locked once the iterator is gone even if the
   /// iterator is leaked with `mem::forget`. Leaking it also skips the compaction, so
   /// the elements in and after the drained range are never dropped and the buffers
   /// they own keep their plaintext.
   ///
   /// Every yielded element is an owned copy of the secret: zeroize it when you are
   /// done with it, like any other copy.
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
      assert!(
         src.len() <= self.capacity,
         "init_from_clone: src is longer than the capacity"
      );

      {
         let _guard = UnlockGuard::new(self);

         // SAFETY: `src.len() <= self.capacity` (asserted above), so every
         // `dst.add(i)` is an uninitialised in-bounds slot; the guard unprotects
         // the allocation and `ptr::write` never reads the destination. `len` is
         // committed only after the loop.
         unsafe {
            let dst = self.ptr.as_ptr();

            // SAFETY: `dst` is the base of the live allocation the `UnlockGuard`
            // above unprotects, the `InitGuard` is dropped before the region is
            // re-locked, and `wrote` records exactly the slots that hold a live
            // `T` once `ptr::write` has put one there.
            let mut init = InitGuard::new(dst);

            for (i, item) in src.iter().enumerate() {
               core::ptr::write(dst.add(i), item.clone());
               init.wrote(i);
            }

            init.commit();
         }
      }

      self.len = src.len();
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
   /// Panics if `offset + src.len()` exceeds the current length. Aborts with a
   /// diagnostic if the memory cannot be re-locked afterwards. A patch never
   /// grows the vector — use [`extend_from_slice`](Self::extend_from_slice) for that.
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

      // SAFETY: `end <= self.len`, so `offset..end` lies inside the initialized
      // region of the allocation. `src` is a distinct live slice that cannot
      // overlap it, so the copy is non-overlapping. The length is untouched, so
      // no element is created, duplicated, or dropped here.
      {
         let _guard = UnlockGuard::new(self);

         unsafe {
            core::ptr::copy_nonoverlapping(
               src.as_ptr(),
               self.ptr.as_ptr().add(offset),
               src.len(),
            );
         }
      }
   }
}

impl<T: Clone + Zeroize> Clone for SecureVec<T> {
   /// # Panics
   ///
   /// Panics if the clone's secure allocation cannot be made or locked.
   fn clone(&self) -> Self {
      let mut new_vec = SecureVec::new_with_capacity(self.capacity).unwrap();
      self.unlock_slice(|src_slice| {
         new_vec.init_from_clone(src_slice);
      });
      new_vec
   }
}

impl<T: Clone + Zeroize, const LENGTH: usize> From<SecureArray<T, LENGTH>> for SecureVec<T> {
   /// # Panics
   ///
   /// Panics if the new secure allocation cannot be made or locked.
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
      // The guard owns the free, so an element destructor that panics in the loop
      // below cannot skip it. Without that the region stayed mapped and unprotected
      // with the plaintext still in it: measured on the `memfd_secret` path, the
      // data page survives the unwind as `rw-s` and the un-dropped element's bytes
      // are still readable.
      let _free = unsafe { FreeGuard::new(self.ptr, self.capacity * mem::size_of::<T>()) };

      // SAFETY: `drop` has exclusive ownership; `unlock_memory` restores access.
      // Only the `len` initialized elements are touched — zeroizing the
      // uninitialised capacity would interpret poison bytes as a `T`. Each
      // element is zeroized and then dropped exactly once: zeroizing wipes what it
      // owns (a `String`'s buffer) and the drop releases that allocation.
      unsafe {
         let ok = self.unlock_memory();
         crate::abort_if_protected(ok, "SecureVec::drop");

         let ptr = self.ptr.as_ptr();

         // The loop runs backwards so the live set is a prefix of the guard's base:
         // a destructor that panics leaves exactly the un-reached slots to the guard,
         // which zeroizes and drops them while the pages are still open.
         let mut discard = InitGuard::<T>::new(ptr);
         discard.set_written(self.len);

         for i in (0..self.len).rev() {
            // Zeroize can panic too, so the slot stays the guard's until the drop
            // below takes ownership of it.
            discard.set_written(i + 1);
            (*ptr.add(i)).zeroize();
            discard.set_written(i);
            core::ptr::drop_in_place(ptr.add(i));
         }

         discard.commit();
      }
      // `_free` releases the region here on the normal path, and during the unwind
      // when an element destructor panics.
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
               // Reserved fallibly first, for the same reason as the SeqElement
               // visitor below: push would panic out of a decode if the growth
               // failed, and a Deserialize impl has to report the failure instead.
               vec.try_reserve(1).map_err(serde::de::Error::custom)?;
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

         /// Wipe the owned buffer the format handed over, including when the copy
         /// panics: a plain `v.zeroize()` after the call runs only on the success and
         /// error arms, not on the unwind a `T::clone` inside the copy can start.
         fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
         where
            E: serde::de::Error,
         {
            let v = Zeroizing::new(v);
            self.visit_bytes(v.as_slice())
         }
      }

      deserializer.deserialize_bytes(SecureVecVisitor)
   }
}

/// Elements that a [`SecureVec`] or [`SecureArray`] encodes element by element
/// rather than as one byte buffer.
///
/// [`u8`] is deliberately absent. A `u8` container is a byte string, so it encodes as a
/// single bulk buffer — the compact form, and one unlock/lock cycle instead of one per
/// element. A blanket impl that covered `u8` too would overlap with the byte-buffer impls
/// above, and Rust has no specialization, so each element type opts in here instead.
///
/// Implemented for the scalar types listed below; `usize` and `isize` are absent
/// because their width is target-dependent. Implement it for your own type to make
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
               // Reserved fallibly first: `push` would panic out of a decode if the
               // growth failed, and `decode_slice` promises a `DecodeError`.
               vec.try_reserve(1).map_err(serde::de::Error::custom)?;
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
/// exposed. Leaking it still skips the drops of the elements left in the drained range
/// and leaves the length at the drain start. And because `drain` lowers the length
/// before anything is moved, the elements *after* the drained range stay in the
/// allocation outside that length: their owned buffers are never freed either, so the
/// plaintext they hold outlives the vector.
///
/// Elements that are never yielded are zeroized and then dropped when the iterator
/// is dropped, exactly as `clear` and `Drop` discard an element.
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

      // SAFETY: `current_drain_iter_index < drain_end_index <= original len`, so
      // this is an initialized element of the live allocation, unprotected by the
      // guard. It is moved out (never duplicated): the index advances so the slot
      // is not read again, and `compact` treats its old bits as moved-from.
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

      // SAFETY: the guard unprotects the live vector. Every index is within the
      // original length; unyielded drain-range elements and the not-yet-moved tail
      // are zeroized and then dropped exactly once (each by its own guard), the tail
      // is moved (not copied) into the hole, and the leftover slots hold only
      // moved-from / duplicate bit patterns — wiped as bytes, never reinterpreted as
      // a `T`.
      unsafe {
         // The tail elements are still owned by nobody until the copy below moves them
         // down: if a destructor in the discard loop panics, this guard zeroizes and
         // drops them while the pages are open. The loop's `InitGuard` covers the
         // drained range; this covers everything after it.
         let mut tail = TailGuard::<T>::new(base, self.drain_end_index, self.tail_len);

         // Discard drain-range elements that were never yielded. `next` already
         // `ptr::read` them out to the caller; dropping those again would
         // double-free. Each unyielded element is zeroized before it is dropped,
         // exactly as `clear` and `Drop` discard one: the byte wipe below only
         // reaches the slot, so without it the memory a `T` owns (a `String`'s
         // buffer) would be freed with its plaintext intact. Runs for every `T`,
         // not only `needs_drop` ones: a `Zeroize` impl may wipe memory outside
         // the element's own bytes, and `clear`/`Drop` zeroize unconditionally.
         let first = self.current_drain_iter_index;
         let end = self.drain_end_index;

         // Covers the unyielded slots the loop has not reached yet, so a destructor
         // that panics discards them instead of orphaning them. The loop runs from
         // the back, which is what makes the live set a prefix of `base.add(first)`.
         let mut discard = InitGuard::<T>::new(base.add(first));
         discard.set_written(end - first);

         for index in (first..end).rev() {
            let slot = base.add(index);
            // `zeroize` can panic too, so the slot is still the guard's until the
            // drop below takes ownership of it.
            discard.set_written(index - first + 1);
            (*slot).zeroize();
            discard.set_written(index - first);
            ptr::drop_in_place(slot);
         }

         discard.commit();

         let hole_dst_ptr = base.add(self.drain_start_index);
         let tail_src_ptr = base.add(self.drain_end_index);

         if self.tail_len > 0 {
            ptr::copy(tail_src_ptr, hole_dst_ptr, self.tail_len);
         }

         // The tail now lives at the front of the hole, so the guard must not drop it.
         tail.disarm();

         let new_len = self.drain_start_index + self.tail_len;

         // Leftover slots are not valid `T`: they are either dropped unyielded
         // items, moved-from yielded items, or the bitwise source of the tail
         // copy. `T::zeroize` / `drop_in_place` here aliases the caller's
         // values (and the kept tail). Wipe as bytes.
         let leftover_elems = self.original_vec_len.saturating_sub(new_len);
         let leftover_bytes = leftover_elems.saturating_mul(mem::size_of::<T>());
         zero_bytes(base.add(new_len) as *mut u8, leftover_bytes);

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

#[cfg(test)]
mod tests {
   // Every test in this module is gated on `use_os` or `codec`, so the glob is only
   // reachable when one of them is enabled. Importing it unconditionally makes a
   // `--no-default-features` build warn about an unused import.
   #[cfg(any(feature = "use_os", feature = "codec"))]
   use super::*;

   #[cfg(feature = "use_os")]
   use std::process::{Command, Stdio};
   #[cfg(feature = "use_os")]
   use std::sync::atomic::{AtomicUsize, Ordering};

   /// A `T` that records both halves of the element lifecycle, so a leak is
   /// observable without reading freed memory.
   #[cfg(feature = "use_os")]
   struct Owned(u8);

   #[cfg(feature = "use_os")]
   static ZEROIZED: AtomicUsize = AtomicUsize::new(0);
   #[cfg(feature = "use_os")]
   static DROPPED: AtomicUsize = AtomicUsize::new(0);

   #[cfg(feature = "use_os")]
   impl Zeroize for Owned {
      fn zeroize(&mut self) {
         self.0.zeroize();
         ZEROIZED.fetch_add(1, Ordering::SeqCst);
      }
   }

   #[cfg(feature = "use_os")]
   impl Drop for Owned {
      fn drop(&mut self) {
         DROPPED.fetch_add(1, Ordering::SeqCst);
      }
   }

   #[cfg(feature = "use_os")]
   fn tracked_vec(len: usize) -> SecureVec<Owned> {
      let mut vec = SecureVec::new_with_capacity(len).unwrap();

      for i in 0..len {
         vec.push(Owned(i as u8));
      }

      vec
   }

   #[cfg(feature = "use_os")]
   fn counts() -> (usize, usize) {
      (
         ZEROIZED.load(Ordering::SeqCst),
         DROPPED.load(Ordering::SeqCst),
      )
   }

   #[cfg(feature = "use_os")]
   fn reset_counts() {
      ZEROIZED.store(0, Ordering::SeqCst);
      DROPPED.store(0, Ordering::SeqCst);
   }

   /// Every path that discards elements must zeroize *and drop* them: zeroizing
   /// alone wipes their bytes but leaks the allocation they own, and `clear` used
   /// to abandon them without even that.
   #[cfg(feature = "use_os")]
   #[test]
   fn test_discarding_elements_zeroizes_and_drops_them() {
      reset_counts();
      drop(tracked_vec(3));
      assert_eq!(counts(), (3, 3), "Drop");

      reset_counts();
      let mut vec = tracked_vec(3);
      vec.clear();
      assert_eq!(vec.len(), 0);
      assert_eq!(counts(), (3, 3), "clear");

      reset_counts();
      let mut vec = tracked_vec(2);
      vec.erase();
      assert_eq!(vec.len(), 0);
      assert_eq!(counts(), (2, 2), "erase");

      // The capacity survives a clear and is reused by the next push.
      let mut vec = tracked_vec(1);
      vec.clear();
      reset_counts();
      vec.push(Owned(0));
      drop(vec);
      assert_eq!(counts(), (1, 1), "reuse after clear");

      // A drain dropped with elements still inside discards them too: only the
      // yielded element moves out, so only its `Drop` runs here and the unyielded
      // one must be zeroized before it is dropped.
      reset_counts();
      let mut vec = tracked_vec(3);
      {
         let mut drain = vec.drain(0..2);
         drop(drain.next().expect("the drain yields its first element"));
      }
      assert_eq!(vec.len(), 1);
      assert_eq!(counts(), (1, 2), "drain");
   }

   #[cfg(feature = "use_os")]
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

   #[cfg(feature = "use_os")]
   #[test]
   fn test_erase_zeroizes_initialized_slots() {
      let mut secure = SecureVec::from_slice(&[1u8, 2, 3]).unwrap();
      let capacity = secure.capacity;
      secure.erase();
      assert_eq!(secure.len, 0);
      assert_eq!(secure.capacity, capacity);

      let ok = secure.unlock_memory();
      assert!(ok);
      // SAFETY: test-only — the memory was just unlocked above, and the three
      // slots were erased, so reading them is valid and must show zeros.
      unsafe {
         let slice = core::slice::from_raw_parts(secure.ptr.as_ptr(), 3);
         assert_eq!(slice, &[0, 0, 0]);
      }
      let ok = secure.lock_memory();
      assert!(ok);
   }

   #[cfg(feature = "codec")]
   #[test]
   fn test_patch_at_leaves_length_and_capacity_alone() {
      let mut secure = SecureBytes::new_with_capacity(16).unwrap();
      secure.extend_from_slice(b"abc").unwrap();
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
      secure.extend_from_slice(b"first").unwrap();
      secure.reserve(4096);
      secure.extend_from_slice(b"second").unwrap();

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

   #[cfg(feature = "use_os")]
   #[test]
   fn test_forgotten_drain_keeps_memory_locked() {
      let arg = "CRASH_TEST_DRAIN_FORGET_LOCKED";

      if std::env::args().any(|a| a == arg) {
         let vec: Vec<u8> = vec![1, 2, 3, 4, 5];
         let mut secure = SecureVec::from_vec(vec).unwrap();
         let drain = secure.drain(..3);
         core::mem::forget(drain);

         // SAFETY (test-only): a leaked `Drain` must not leave the vector
         // exposed, so this deliberately reads a locked, `PROT_NONE` page and is
         // expected to fault (the child process dies with SIGSEGV).
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

   #[cfg(feature = "use_os")]
   #[test]
   fn test_index_should_fail_when_locked() {
      let arg = "CRASH_TEST_SECUREVEC_LOCKED";

      if std::env::args().any(|a| a == arg) {
         let vec: Vec<u8> = vec![1, 2, 3];
         let secure = SecureVec::from_vec(vec).unwrap();
         // SAFETY (test-only): deliberately dereferences the locked pointer to
         // prove the security model (mlock + `PROT_NONE`) works — the child process
         // is expected to die with SIGSEGV.
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

   /// Counters for the clone-bomb tests. They are deliberately separate from the
   /// `ZEROIZED` / `DROPPED` pair above: libtest runs tests in parallel, so two
   /// tests resetting and asserting the same globals would race.
   ///
   /// Counts every `Tracked::clone` call, so the clone bomb can fire mid-loop.
   #[cfg(feature = "use_os")]
   static CLONES: AtomicUsize = AtomicUsize::new(0);

   /// Counts every `Tracked::zeroize` call.
   #[cfg(feature = "use_os")]
   static CLONE_ZEROIZED: AtomicUsize = AtomicUsize::new(0);

   /// Counts every `Tracked::drop` call.
   #[cfg(feature = "use_os")]
   static CLONE_DROPPED: AtomicUsize = AtomicUsize::new(0);

   /// Owns a `String` like a real secret does, but panics on its second clone.
   #[cfg(feature = "use_os")]
   #[derive(Debug)]
   struct Tracked(String);

   #[cfg(feature = "use_os")]
   impl Tracked {
      fn new(data: impl Into<String>) -> Self {
         Tracked(data.into())
      }
   }

   #[cfg(feature = "use_os")]
   impl Clone for Tracked {
      fn clone(&self) -> Self {
         if CLONES.fetch_add(1, Ordering::SeqCst) == 1 {
            panic!("clone bomb");
         }

         Tracked::new(self.0.clone())
      }
   }

   #[cfg(feature = "use_os")]
   impl Zeroize for Tracked {
      fn zeroize(&mut self) {
         CLONE_ZEROIZED.fetch_add(1, Ordering::SeqCst);
         self.0.zeroize();
      }
   }

   #[cfg(feature = "use_os")]
   impl Drop for Tracked {
      fn drop(&mut self) {
         CLONE_DROPPED.fetch_add(1, Ordering::SeqCst);
      }
   }

   /// `extend_from_slice` is crate-private, so its clone loop is only reachable
   /// from here: a panic from `T::clone` must zeroize and drop the elements
   /// already appended, not leak them past the container.
   ///
   /// The bomb fires on the second clone, so exactly one element was written.
   #[cfg(feature = "use_os")]
   #[test]
   fn test_extend_from_slice_panic_zeroizes_written_prefix() {
      CLONES.store(0, Ordering::SeqCst);
      CLONE_ZEROIZED.store(0, Ordering::SeqCst);
      CLONE_DROPPED.store(0, Ordering::SeqCst);

      let source = [Tracked::new("first")];
      let mut secure = SecureVec::<Tracked>::from_slice(&source).unwrap();

      // The one clone above is expected; only the append is under test.
      CLONES.store(0, Ordering::SeqCst);
      CLONE_ZEROIZED.store(0, Ordering::SeqCst);
      CLONE_DROPPED.store(0, Ordering::SeqCst);

      let more = [Tracked::new("a"), Tracked::new("b"), Tracked::new("c")];
      let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
         secure.extend_from_slice(&more)
      }));

      assert!(
         result.is_err(),
         "the clone bomb must make `extend_from_slice` unwind"
      );
      assert_eq!(
         CLONE_ZEROIZED.load(Ordering::SeqCst),
         1,
         "the element appended before the panic must be zeroized"
      );
      assert_eq!(
         CLONE_DROPPED.load(Ordering::SeqCst),
         1,
         "the element appended before the panic must be dropped"
      );
   }
}
