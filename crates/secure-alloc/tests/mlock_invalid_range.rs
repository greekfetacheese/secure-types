//! A lock range whose end wraps the address space must be rejected, not rounded.
//!
//! `mlock` and `munlock` take a `usize` length, and the kernel rounds it up to a page.
//! A wrapped `usize::MAX` therefore reaches `mlock` as a short length and reports success
//! having covered nothing, and reaches `munlock` only after the zeroing has already run
//! outside the caller's range. The review that found this added `range_fits`; this test
//! requires both calls to report the failure instead.

#![cfg(feature = "use_os")]

#[test]
fn a_wrapping_range_is_rejected() {
    let mut buf = [0u8; 64];
    let addr = buf.as_mut_ptr();

    // SAFETY: every call here is rejected before it touches memory (`len == 0` is not
    // used with a wrapping address), so no range is dereferenced.
    unsafe {
        assert!(
            !secure_alloc::mlock(addr, usize::MAX),
            "a length that wraps the address space must not report a successful lock"
        );
        assert!(
            !secure_alloc::munlock(addr, usize::MAX),
            "a length that wraps the address space must be rejected before the zeroing"
        );
        assert!(
            !secure_alloc::mlock(usize::MAX as *mut u8, 2),
            "an address at the top of the space must not wrap into a short range"
        );
        assert!(
            !secure_alloc::munlock(usize::MAX as *mut u8, 2),
            "an address at the top of the space must be rejected before the zeroing"
        );
    }
}

#[test]
fn the_zeroing_range_still_fits() {
    let mut buf = [0u8; 64];
    let addr = buf.as_mut_ptr();

    // SAFETY: `buf` is a live, writable range for the call, and a one-byte lock of its
    // first byte is a valid range whatever the environment's `RLIMIT_MEMLOCK` says.
    unsafe {
        let _ = secure_alloc::mlock(addr, 1);
        let _ = secure_alloc::munlock(addr, 1);
    }
}
