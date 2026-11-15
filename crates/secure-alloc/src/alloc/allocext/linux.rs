extern crate std;
use self::std::process::abort;
use crate::{alloc::*, Prot};
use core::mem::{self, size_of};
use core::ptr::{self, NonNull};

use self::memfd_secret_alloc::*;

mod memfd_secret_alloc {
    use super::*;
    use core::convert::TryInto;

    /// Create the backing descriptor, close-on-exec.
    ///
    /// `MFD_CLOEXEC` sets that atomically, but not every kernel accepts the flag
    /// for `memfd_secret` and answers `EINVAL`; those fall back to setting it
    /// immediately after creation, which narrows the window to these two calls.
    #[inline]
    unsafe fn secretmem_fd() -> Option<libc::c_int> {
        let fd: Result<libc::c_int, _> =
            libc::syscall(libc::SYS_memfd_secret, libc::MFD_CLOEXEC).try_into();

        if let Some(fd) = fd.ok().filter(|&fd| fd >= 0) {
            return Some(fd);
        }

        let fd: Result<libc::c_int, _> = libc::syscall(libc::SYS_memfd_secret, 0).try_into();
        let fd = fd.ok().filter(|&fd| fd >= 0)?;

        if libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
            libc::close(fd);
            return None;
        }

        Some(fd)
    }

    #[inline]
    pub unsafe fn alloc_memfd_secret(size: usize) -> Option<(NonNull<u8>, libc::c_int)> {
        let fd = secretmem_fd()?;

        // File size is set using ftruncate
        if libc::ftruncate(fd, size as libc::off_t) < 0 {
            libc::close(fd);
            return None;
        }

        let ptr = libc::mmap(
            ptr::null_mut(),
            size,
            Prot::ReadWrite,
            libc::MAP_SHARED,
            fd,
            0,
        );

        if ptr == libc::MAP_FAILED {
            libc::close(fd);
            return None;
        }

        NonNull::new(ptr as *mut u8).map(|ptr| (ptr, fd))
    }
}

unsafe fn _memfd_secret(size: usize) -> Option<*mut u8> {
    ALLOC_INIT.call_once(|| alloc_init());

    //Assert size of unprotected_size (usize) and fd (i32) is less than PAGE_SIZE before allocating memory
    assert!(size_of::<usize>() + size_of::<i32>() <= PAGE_SIZE);

    // Every step that can overflow is checked. A size in the last few dozen values
    // before `usize::MAX` used to wrap the page-rounded total to zero, and the guard
    // pages, canary and user pointer were then addressed from the unwrapped length.
    let size_with_canary = CANARY_SIZE.checked_add(size)?;
    let unprotected_size = page_round(size_with_canary)?;
    let total_size = PAGE_SIZE.checked_mul(3)?.checked_add(unprotected_size)?;

    // A `Layout` must fit in `isize`; anything larger is an allocation failure, not
    // an invalid layout to hand to `mmap`.
    if total_size > isize::MAX as usize {
        return None;
    }

    // aligned alloc ptr
    let (base_ptr, fd) = alloc_memfd_secret(total_size)?;
    let base_ptr = base_ptr.as_ptr();
    let fd_ptr = base_ptr.add(size_of::<usize>());
    let unprotected_ptr = base_ptr.add(PAGE_SIZE * 2);

    // mprotect can be used to change protection flag after mmap setup
    // https://www.gnu.org/software/libc/manual/html_node/Memory-Protection.html#index-mprotect
    _mprotect(base_ptr.add(PAGE_SIZE), PAGE_SIZE, Prot::NoAccess);
    _mprotect(
        unprotected_ptr.add(unprotected_size),
        PAGE_SIZE,
        Prot::NoAccess,
    );

    let canary_ptr = unprotected_ptr.add(unprotected_size - size_with_canary);
    let user_ptr = canary_ptr.add(CANARY_SIZE);
    #[allow(static_mut_refs)]
    ptr::copy_nonoverlapping(CANARY.as_ptr(), canary_ptr, CANARY_SIZE);
    ptr::write_unaligned(base_ptr as *mut usize, unprotected_size);
    ptr::write_unaligned(fd_ptr as *mut libc::c_int, fd);
    ptr::write_unaligned(base_ptr.add(MEMFD_TAG_OFFSET) as *mut usize, MEMFD_TAG);
    _mprotect(base_ptr, PAGE_SIZE, Prot::ReadOnly);

    assert_eq!(unprotected_ptr_from_user_ptr(user_ptr), unprotected_ptr);

    Some(user_ptr)
}

/// Linux specific `memfd_secret` backed allocation
///
/// # Safety
///
/// The returned memory is filled with `0xd0`, which is not a valid `T` for most
/// types; initialise it before reading it as one. Release the allocation exactly
/// once with `free_memfd_secret` — not `free` — and do not read or write outside
/// the region it was allocated for.
#[inline]
pub unsafe fn memfd_secret<T>() -> Option<NonNull<T>> {
    _memfd_secret(mem::size_of::<T>()).map(|memptr| {
        ptr::write_bytes(memptr, GARBAGE_VALUE, mem::size_of::<T>());
        NonNull::new_unchecked(memptr as *mut T)
    })
}

/// Linux specific `memfd_secret` backed `sized` allocation
///
/// # Safety
///
/// The returned bytes are filled with `0xd0`. Release the allocation exactly
/// once with `free_memfd_secret` — not `free`.
#[inline]
pub unsafe fn memfd_secret_sized(size: usize) -> Option<NonNull<[u8]>> {
    _memfd_secret(size).map(|memptr| {
        ptr::write_bytes(memptr, GARBAGE_VALUE, size);
        NonNull::new_unchecked(core::ptr::slice_from_raw_parts_mut(memptr, size))
    })
}

/// Secure `free` for memfd_secret allocations,
/// i.e. provides read write access back to mprotect guard pages
/// and unmaps mmaped secrets
///
/// # Safety
///
/// `memptr` must be a live pointer returned by `memfd_secret` or
/// `memfd_secret_sized` and not yet freed. The range is zeroed, unmapped and its
/// file descriptor closed, so every pointer into it is dangling afterwards. A
/// pointer from `free`, or any other foreign pointer, aborts on the allocator tag
/// before the descriptor is read or the canary checked, so it cannot close an
/// unrelated descriptor; a pointer whose metadata page is unreadable also faults
/// there. The data region is made readable again before the canary is checked, so an
/// allocation the caller left `mprotect`ed `NoAccess` is freed normally.
pub unsafe fn free_memfd_secret<T: ?Sized>(memptr: NonNull<T>) {
    use libc::c_void;

    let memptr = memptr.as_ptr() as *mut u8;

    // get unprotected ptr
    let canary_ptr = memptr.sub(CANARY_SIZE);
    let unprotected_ptr = unprotected_ptr_from_user_ptr(memptr);
    let base_ptr = unprotected_ptr.sub(PAGE_SIZE * 2);

    // Check the allocator tag before the descriptor is read. A `malloc` header's
    // spare slot is explicitly defined (see `NOT_MEMFD_TAG`), so this is never an
    // uninitialised read.
    if ptr::read(base_ptr.add(MEMFD_TAG_OFFSET) as *const usize) != MEMFD_TAG {
        abort();
    }

    let fd_ptr = base_ptr.add(size_of::<usize>()) as *mut libc::c_int;
    let unprotected_size = ptr::read(base_ptr as *const usize);
    let fd = ptr::read(fd_ptr);

    // The canary lives in the data region, so restore access before reading it: an
    // allocation the caller left `NoAccess` must still be freed. The tag above and
    // the descriptor here both come from the metadata page, which the caller does not
    // protect.
    let total_size = PAGE_SIZE + PAGE_SIZE + unprotected_size + PAGE_SIZE;
    _mprotect(base_ptr, total_size, Prot::ReadWrite);

    // check
    #[allow(static_mut_refs)]
    if !crate::memeq(canary_ptr as *const u8, CANARY.as_ptr(), CANARY_SIZE) {
        abort();
    }

    // free
    crate::memzero(unprotected_ptr, unprotected_size);

    let res = libc::munmap(base_ptr as *mut c_void, total_size);
    if res < 0 {
        abort();
    }

    let res = libc::close(fd);
    if res < 0 {
        abort();
    }
}
