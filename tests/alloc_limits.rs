//! Requests near `usize::MAX` must be rejected, not wrapped.
//!
//! `secure-alloc` used to compute its region size with unchecked arithmetic, so
//! for the last few dozen sizes before `usize::MAX` the page rounding pushed the
//! total over the top: a debug build panicked on the addition, and a release build
//! wrapped to zero, handed a zero-byte `Layout` to the global allocator and then
//! addressed the guard pages, the canary and the user pointer from the unwrapped
//! length.

#![cfg(feature = "use_os")]

use secure_types::SecureVec;

/// The sizes inside the old wrapping window — widened to cover the header and
/// rounding `SecureVec` applies before it reaches the allocator — must come back
/// as an ordinary allocation error.
#[test]
fn capacities_that_used_to_overflow_the_region_size_are_rejected() {
   let guard = secure_types::secure_alloc::page_size() * 4;

   for offset in (guard.saturating_sub(128))..(guard + 128) {
      let capacity = usize::MAX - offset;

      assert!(
         SecureVec::<u8>::new_with_capacity(capacity).is_err(),
         "usize::MAX - {offset} was accepted"
      );
   }
}

/// The top of the `usize` range is a plain error too, not an overflow.
#[test]
fn capacities_near_usize_max_are_rejected() {
   for offset in 0..64 {
      let capacity = usize::MAX - offset;

      assert!(
         SecureVec::<u8>::new_with_capacity(capacity).is_err(),
         "usize::MAX - {offset} was accepted"
      );
   }
}

/// A `Layout` has to fit in an `isize`; a larger request is a clean failure.
#[test]
fn capacities_above_the_layout_limit_are_rejected() {
   assert!(SecureVec::<u8>::new_with_capacity(usize::MAX / 2).is_err());
}
