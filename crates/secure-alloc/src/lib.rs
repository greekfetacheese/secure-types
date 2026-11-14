#![doc = include_str!("../README.md")]
#![no_std]
#![cfg_attr(feature = "nightly", allow(internal_features))]
#![cfg_attr(feature = "nightly", feature(core_intrinsics))]

mod alloc;
mod mlock;

use core::ptr;

#[cfg(feature = "use_os")]
pub use mlock::{mlock, munlock};

#[cfg(feature = "alloc")]
pub use alloc::{free, malloc, malloc_sized, mprotect, Prot};

#[cfg(feature = "alloc_ext")]
#[cfg(target_os = "linux")]
pub use alloc::allocext::{free_memfd_secret, memfd_secret, memfd_secret_sized};

// -- memcmp --

/// Secure `memeq`.
///
/// # Safety
///
/// `b1` and `b2` must each be valid for reads of `len` bytes for the duration
/// of the call. Every byte is read, so a `len` past the end of either buffer is
/// an out-of-bounds read.
#[inline(never)]
pub unsafe fn memeq(b1: *const u8, b2: *const u8, len: usize) -> bool {
    (0..len)
        .map(|i| ptr::read_volatile(b1.add(i)) ^ ptr::read_volatile(b2.add(i)))
        .fold(0, |sum, next| sum | next)
        .eq(&0)
}

/// Secure `memcmp`.
///
/// # Safety
///
/// `b1` and `b2` must each be valid for reads of `len` bytes for the duration
/// of the call. Every byte is read, so a `len` past the end of either buffer is
/// an out-of-bounds read.
#[inline(never)]
pub unsafe fn memcmp(b1: *const u8, b2: *const u8, len: usize) -> i32 {
    let mut res = 0;
    for i in (0..len).rev() {
        let diff =
            i32::from(ptr::read_volatile(b1.add(i))) - i32::from(ptr::read_volatile(b2.add(i)));
        res = (res & (((diff - 1) & !diff) >> 8)) | diff;
    }
    ((res - 1) >> 8) + (res >> 8) + 1
}

// -- memset / memzero --

/// General `memset`.
///
/// # Safety
///
/// `s` must be valid for writes of `n` bytes for the duration of the call.
#[inline(never)]
pub unsafe fn memset(s: *mut u8, c: u8, n: usize) {
    #[cfg(feature = "nightly")]
    {
        core::intrinsics::volatile_set_memory(s, c, n);
    }

    #[cfg(not(feature = "nightly"))]
    {
        let s = ptr::read_volatile(&s);
        let c = ptr::read_volatile(&c);
        let n = ptr::read_volatile(&n);

        for i in 0..n {
            ptr::write(s.add(i), c);
        }

        let _ = ptr::read_volatile(&s);
    }
}

/// General `memzero`.
///
/// # Safety
///
/// `dest` must be valid for writes of `n` bytes for the duration of the call.
#[inline]
pub unsafe fn memzero(dest: *mut u8, n: usize) {
    memset(dest, 0, n);
}
