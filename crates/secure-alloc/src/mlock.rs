//! mlock / munlock

#![cfg(feature = "use_os")]

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "dragonfly"))]
use core::sync::atomic::{AtomicUsize, Ordering};

/// Page size, cached: `madvise` needs page-aligned addresses, its callers do not.
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "dragonfly"))]
fn page_size() -> Option<usize> {
    static PAGE_SIZE: AtomicUsize = AtomicUsize::new(0);

    let cached = PAGE_SIZE.load(Ordering::Relaxed);
    if cached != 0 {
        return Some(cached);
    }

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if page_size <= 0 {
        return None;
    }

    let page_size = page_size as usize;
    PAGE_SIZE.store(page_size, Ordering::Relaxed);

    Some(page_size)
}

/// The page-aligned range covering `addr..addr + len`, as `madvise` requires.
///
/// `None` when there is nothing to cover (`len == 0`), when the page size is
/// unknown, or when the range cannot be rounded without overflowing.
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "dragonfly"))]
fn page_aligned_range(addr: *mut u8, len: usize) -> Option<(*mut u8, usize)> {
    if len == 0 {
        return None;
    }

    let page_size = page_size()?;
    let start = (addr as usize) & !(page_size - 1);
    let end = (addr as usize).checked_add(len)?;
    let end = end.checked_add(page_size - 1)? & !(page_size - 1);

    Some((start as *mut u8, end - start))
}

/// Apply `advice` to the page-aligned range covering `addr..addr + len`.
///
/// Best-effort: the advice can fail and the result is not reported.
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "dragonfly"))]
unsafe fn madvise_aligned(addr: *mut u8, len: usize, advice: libc::c_int) {
    if let Some((start, len)) = page_aligned_range(addr, len) {
        libc::madvise(start as *mut libc::c_void, len, advice);
    }
}

/// Cross-platform `mlock`.
///
/// * Unix `mlock`, which also excludes the range from core dumps:
///   `madvise(MADV_DONTDUMP)` on Linux, `madvise(MADV_NOCORE)` on FreeBSD and
///   DragonFly. That exclusion is best-effort and its failure is not reported.
/// * Windows `VirtualLock`.
///
/// # Safety
///
/// `addr..addr + len` must be a live mapping owned by the caller and stay mapped
/// for the duration of the call. It does not have to be page-aligned: the range
/// that goes to `madvise` is rounded out to whole pages, and `mlock` rounds it
/// itself. Nothing is dereferenced here, so an invalid range only fails the
/// underlying call, reported as `false`.
pub unsafe fn mlock(addr: *mut u8, len: usize) -> bool {
    #[cfg(target_os = "linux")]
    madvise_aligned(addr, len, libc::MADV_DONTDUMP);

    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    madvise_aligned(addr, len, libc::MADV_NOCORE);

    #[cfg(unix)]
    {
        libc::mlock(addr as *mut libc::c_void, len) == 0
    }

    #[cfg(windows)]
    {
        windows_sys::Win32::System::Memory::VirtualLock(addr.cast(), len) != 0
    }
}

/// Cross-platform `munlock`.
///
/// * Unix `munlock`, which zeroes the range first and restores core-dump
///   inclusion: `madvise(MADV_DODUMP)` on Linux, `madvise(MADV_CORE)` on FreeBSD
///   and DragonFly. Best-effort, as in `mlock`.
/// * Windows `VirtualUnlock`.
///
/// # Safety
///
/// `addr..addr + len` must be a live, writable mapping owned by the caller and
/// stay valid for the duration of the call: the range is zeroed (`memzero`)
/// before it is unlocked. It does not have to be page-aligned.
pub unsafe fn munlock(addr: *mut u8, len: usize) -> bool {
    crate::memzero(addr, len);

    #[cfg(target_os = "linux")]
    madvise_aligned(addr, len, libc::MADV_DODUMP);

    #[cfg(any(target_os = "freebsd", target_os = "dragonfly"))]
    madvise_aligned(addr, len, libc::MADV_CORE);

    #[cfg(unix)]
    {
        libc::munlock(addr as *mut libc::c_void, len) == 0
    }

    #[cfg(windows)]
    {
        windows_sys::Win32::System::Memory::VirtualUnlock(addr.cast(), len) != 0
    }
}
