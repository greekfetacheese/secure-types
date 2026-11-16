//! alloc

#![cfg(feature = "alloc")]

pub mod allocext;

extern crate std;
use self::raw_alloc::*;
use self::std::process::abort;
use self::std::sync::Once;
use core::mem;
use core::ptr::{self, NonNull};

const GARBAGE_VALUE: u8 = 0xd0;
const CANARY_SIZE: usize = 16;

/// Marks the metadata page of a `malloc`/`malloc_sized` allocation.
const MALLOC_TAG: usize = 0x4D41_4C4C; // "MALL"
/// Marks the metadata page of a `memfd_secret` allocation.
const MEMFD_TAG: usize = 0x4D46_4453; // "MFDS"

/// Value written to the `memfd_secret` tag slot of a `malloc` header.
///
/// Both layouts keep the data-region length at offset 0. A `malloc` allocation
/// stores its tag in the next `usize`; a `memfd_secret` allocation stores its
/// descriptor there, so its tag sits one `usize` further along. Writing a defined
/// value into that further slot keeps both checks reading initialised metadata and
/// makes the two tags exclusive.
const NOT_MEMFD_TAG: usize = 0;

/// Offsets of the allocator tags in the metadata page.
const MALLOC_TAG_OFFSET: usize = mem::size_of::<usize>();
const MEMFD_TAG_OFFSET: usize = MALLOC_TAG_OFFSET + mem::size_of::<usize>();

static ALLOC_INIT: Once = Once::new();
static mut PAGE_SIZE: usize = 0;
static mut PAGE_MASK: usize = 0;
static mut CANARY: [u8; CANARY_SIZE] = [0; CANARY_SIZE];

// -- alloc init --

#[inline]
unsafe fn alloc_init() {
    #[cfg(unix)]
    {
        PAGE_SIZE = libc::sysconf(libc::_SC_PAGESIZE) as usize;
    }

    #[cfg(windows)]
    {
        let mut si = mem::MaybeUninit::uninit();
        windows_sys::Win32::System::SystemInformation::GetSystemInfo(si.as_mut_ptr());
        PAGE_SIZE = (*si.as_ptr()).dwPageSize as usize;
    }

    if PAGE_SIZE < CANARY_SIZE || PAGE_SIZE < mem::size_of::<usize>() {
        panic!("page size too small");
    }

    PAGE_MASK = PAGE_SIZE - 1;

    #[allow(static_mut_refs)]
    getrandom::fill(&mut CANARY).unwrap();
}

/// The page size this allocator lays its regions out with.
///
/// It is the unit the guard pages and `mprotect` work in, and the data region is
/// rounded up to a multiple of it. It is **not a guarantee** of the returned
/// pointer's alignment: that pointer sits `size` bytes below the end of the
/// page-rounded data region, so it only lands on a page boundary when `size` is
/// a whole number of pages. `malloc::<T>` and `memfd_secret::<T>` are aligned
/// for `T` while `align_of::<T>() <= page_size()`, because their size is
/// `size_of::<T>()`, a multiple of `align_of::<T>()`, and the offset above is a
/// multiple of the alignment only when the alignment divides the page.
/// `malloc_sized` and `memfd_secret_sized` carry no such guarantee, and neither
/// does an over-aligned `T`, so a result that needs a stronger alignment has to
/// be checked.
#[inline]
pub fn page_size() -> usize {
    ALLOC_INIT.call_once(|| unsafe { alloc_init() });

    // SAFETY: `alloc_init` ran above and wrote `PAGE_SIZE` before this read; the
    // `Once` is the happens-before edge for every caller.
    unsafe { PAGE_SIZE }
}

// -- aligned alloc / aligned free --

mod raw_alloc {
    use super::std::alloc::{alloc, dealloc, Layout};
    use super::*;

    #[inline]
    pub unsafe fn alloc_aligned(size: usize) -> Option<NonNull<u8>> {
        let layout = Layout::from_size_align_unchecked(size, PAGE_SIZE);
        NonNull::new(alloc(layout))
    }

    #[inline]
    pub unsafe fn free_aligned(memptr: *mut u8, size: usize) {
        let layout = Layout::from_size_align_unchecked(size, PAGE_SIZE);
        dealloc(memptr, layout);
    }
}

// -- mprotect --

/// Prot enum.
#[cfg(unix)]
#[allow(non_snake_case, non_upper_case_globals)]
pub mod Prot {
    pub use libc::c_int as Ty;

    pub const NoAccess: Ty = libc::PROT_NONE;
    pub const ReadOnly: Ty = libc::PROT_READ;
    /// `PROT_WRITE`, passed to `mprotect` unchanged. On architectures where a
    /// writable page is readable this is **not** write-only: a page mapped with it
    /// can be read back by this process (x86-64 is one).
    pub const WriteOnly: Ty = libc::PROT_WRITE;
    pub const ReadWrite: Ty = libc::PROT_READ | libc::PROT_WRITE;
    pub const Execute: Ty = libc::PROT_EXEC;
    pub const ReadExec: Ty = libc::PROT_READ | libc::PROT_EXEC;
    pub const WriteExec: Ty = libc::PROT_WRITE | libc::PROT_EXEC;
    pub const ReadWriteExec: Ty = libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC;
}

/// Prot enum.
#[cfg(windows)]
#[allow(non_snake_case, non_upper_case_globals)]
pub mod Prot {
    pub use windows_sys::Win32::System::Memory::PAGE_PROTECTION_FLAGS as Ty;

    pub const NoAccess: Ty = windows_sys::Win32::System::Memory::PAGE_NOACCESS;
    pub const ReadOnly: Ty = windows_sys::Win32::System::Memory::PAGE_READONLY;
    pub const ReadWrite: Ty = windows_sys::Win32::System::Memory::PAGE_READWRITE;
    pub const WriteCopy: Ty = windows_sys::Win32::System::Memory::PAGE_WRITECOPY;
    pub const Execute: Ty = windows_sys::Win32::System::Memory::PAGE_EXECUTE;
    pub const ReadExec: Ty = windows_sys::Win32::System::Memory::PAGE_EXECUTE_READ;
    pub const ReadWriteExec: Ty = windows_sys::Win32::System::Memory::PAGE_EXECUTE_READWRITE;
    pub const WriteCopyExec: Ty = windows_sys::Win32::System::Memory::PAGE_EXECUTE_WRITECOPY;
    pub const Guard: Ty = windows_sys::Win32::System::Memory::PAGE_GUARD;
    pub const NoCache: Ty = windows_sys::Win32::System::Memory::PAGE_NOCACHE;
    pub const WriteCombine: Ty = windows_sys::Win32::System::Memory::PAGE_WRITECOMBINE;
    pub const RevertToFileMap: Ty = windows_sys::Win32::System::Memory::PAGE_REVERT_TO_FILE_MAP;
    pub const TargetsInvalid: Ty = windows_sys::Win32::System::Memory::PAGE_TARGETS_INVALID;
    pub const TargetsNoUpdate: Ty = windows_sys::Win32::System::Memory::PAGE_TARGETS_NO_UPDATE;
}

/// Unix `mprotect`.
#[cfg(unix)]
#[inline]
pub unsafe fn _mprotect(ptr: *mut u8, len: usize, prot: Prot::Ty) -> bool {
    libc::mprotect(ptr as *mut libc::c_void, len, prot as libc::c_int) == 0
}

/// Windows `VirtualProtect`.
#[cfg(windows)]
#[inline]
pub unsafe fn _mprotect(ptr: *mut u8, len: usize, prot: Prot::Ty) -> bool {
    let mut old = mem::MaybeUninit::uninit();
    windows_sys::Win32::System::Memory::VirtualProtect(ptr.cast(), len, prot, old.as_mut_ptr()) != 0
}

/// Secure `mprotect`.
///
/// # Safety
///
/// `memptr` must be a live pointer returned by `malloc`, `malloc_sized`,
/// `memfd_secret` or `memfd_secret_sized` and not yet freed, and the caller must
/// hold up whatever flags it installs: no access may violate them until they are
/// changed again or the allocation is freed. A pointer whose metadata page does
/// not carry either allocator tag aborts rather than being re-protected. A
/// `false` return means the platform rejected the call; do not assume the
/// requested flags are in place.
#[cfg(any(unix, windows))]
pub unsafe fn mprotect<T: ?Sized>(memptr: NonNull<T>, prot: Prot::Ty) -> bool {
    let memptr = memptr.as_ptr() as *mut u8;

    let unprotected_ptr = unprotected_ptr_from_user_ptr(memptr);
    let base_ptr = unprotected_ptr.sub(PAGE_SIZE * 2);

    // Check the allocator tag before trusting the length at offset 0. Either tag is
    // accepted: `secure-types` re-protects `memfd_secret` allocations through this
    // same entry point.
    if ptr::read(base_ptr.add(MALLOC_TAG_OFFSET) as *const usize) != MALLOC_TAG
        && ptr::read(base_ptr.add(MEMFD_TAG_OFFSET) as *const usize) != MEMFD_TAG
    {
        abort();
    }

    let unprotected_size = ptr::read(base_ptr as *const usize);
    _mprotect(unprotected_ptr, unprotected_size, prot)
}

// -- malloc / free --

/// Rounds `size` up to the next multiple of the page size.
///
/// Returns `None` when the rounding itself would overflow, so a caller can reject an
/// impossible size instead of wrapping it to a small one.
#[inline]
unsafe fn page_round(size: usize) -> Option<usize> {
    size.checked_add(PAGE_MASK).map(|size| size & !PAGE_MASK)
}

#[inline]
unsafe fn unprotected_ptr_from_user_ptr(memptr: *const u8) -> *mut u8 {
    let canary_ptr = memptr.sub(CANARY_SIZE);
    let unprotected_ptr_u = canary_ptr as usize & !PAGE_MASK;
    if unprotected_ptr_u <= PAGE_SIZE * 2 {
        abort();
    }
    unprotected_ptr_u as *mut u8
}

unsafe fn _malloc(size: usize) -> Option<*mut u8> {
    ALLOC_INIT.call_once(|| alloc_init());

    // Every step that can overflow is checked. A size in the last few dozen values
    // before `usize::MAX` used to wrap the page-rounded total to zero, and the guard
    // pages, canary and user pointer were then addressed from the unwrapped length.
    let size_with_canary = CANARY_SIZE.checked_add(size)?;
    let unprotected_size = page_round(size_with_canary)?;
    let total_size = PAGE_SIZE.checked_mul(3)?.checked_add(unprotected_size)?;

    // A `Layout` must fit in `isize`; anything larger is an allocation failure, not
    // an invalid layout to hand to the global allocator.
    if total_size > isize::MAX as usize {
        return None;
    }

    // aligned alloc ptr
    let base_ptr = alloc_aligned(total_size)?.as_ptr();
    let unprotected_ptr = base_ptr.add(PAGE_SIZE * 2);

    // mprotect ptr
    _mprotect(base_ptr.add(PAGE_SIZE), PAGE_SIZE, Prot::NoAccess);
    _mprotect(
        unprotected_ptr.add(unprotected_size),
        PAGE_SIZE,
        Prot::NoAccess,
    );
    crate::mlock(unprotected_ptr, unprotected_size);

    let canary_ptr = unprotected_ptr.add(unprotected_size - size_with_canary);
    let user_ptr = canary_ptr.add(CANARY_SIZE);
    #[allow(static_mut_refs)]
    ptr::copy_nonoverlapping(CANARY.as_ptr(), canary_ptr, CANARY_SIZE);
    ptr::write_unaligned(base_ptr as *mut usize, unprotected_size);
    ptr::write_unaligned(base_ptr.add(MALLOC_TAG_OFFSET) as *mut usize, MALLOC_TAG);
    // Define the spare tag slot as well, so neither `mprotect` nor
    // `free_memfd_secret` reads uninitialised metadata or mistakes this header for
    // a `memfd_secret` one.
    ptr::write_unaligned(base_ptr.add(MEMFD_TAG_OFFSET) as *mut usize, NOT_MEMFD_TAG);
    _mprotect(base_ptr, PAGE_SIZE, Prot::ReadOnly);

    assert_eq!(unprotected_ptr_from_user_ptr(user_ptr), unprotected_ptr);

    Some(user_ptr)
}

/// Secure `malloc`.
///
/// # Safety
///
/// The returned memory is filled with `0xd0`, which is not a valid `T` for most
/// types; initialise it before reading it as one. Release the allocation exactly
/// once with `free` — not `dealloc`, and not `free_memfd_secret` — and do not
/// read or write outside the region it was allocated for.
///
/// The pointer is aligned for `T` only while `align_of::<T>() <= page_size()`. The
/// user region starts `page_round(size + canary) - size` bytes into the mapping, which
/// is a multiple of the alignment only when the alignment divides a page — so an
/// over-aligned `T` gets a misaligned pointer, and writing through it is undefined
/// behaviour.
#[inline]
pub unsafe fn malloc<T>() -> Option<NonNull<T>> {
    _malloc(mem::size_of::<T>()).map(|memptr| {
        ptr::write_bytes(memptr, GARBAGE_VALUE, mem::size_of::<T>());
        NonNull::new_unchecked(memptr as *mut T)
    })
}

/// Secure `malloc_sized`.
///
/// # Safety
///
/// The returned bytes are filled with `0xd0`. Release the allocation exactly
/// once with `free` — not `dealloc`, and not `free_memfd_secret`.
#[inline]
pub unsafe fn malloc_sized(size: usize) -> Option<NonNull<[u8]>> {
    _malloc(size).map(|memptr| {
        ptr::write_bytes(memptr, GARBAGE_VALUE, size);
        NonNull::new_unchecked(core::ptr::slice_from_raw_parts_mut(memptr, size))
    })
}

/// Secure `free`.
///
/// # Safety
///
/// `memptr` must be a live pointer returned by `malloc` or `malloc_sized` and
/// not yet freed. The data-region length is read from the allocation's metadata
/// page, so `T` only has to carry the address, not match the allocation's type;
/// afterwards every pointer into the allocation is dangling. A pointer from
/// `free_memfd_secret`, or any other foreign pointer, aborts on the allocator tag
/// before its length is used rather than on the canary, so it never reaches
/// `dealloc`; a pointer whose metadata page is unreadable also faults there. The
/// data region is made readable again before the canary is checked, so an allocation
/// the caller left `mprotect`ed `NoAccess` is freed normally.
pub unsafe fn free<T: ?Sized>(memptr: NonNull<T>) {
    let memptr = memptr.as_ptr() as *mut u8;

    // get unprotected ptr
    let canary_ptr = memptr.sub(CANARY_SIZE);
    let unprotected_ptr = unprotected_ptr_from_user_ptr(memptr);
    let base_ptr = unprotected_ptr.sub(PAGE_SIZE * 2);

    // Check the allocator tag before trusting the size. The metadata page is not
    // part of what the caller protects, so this reads even when the allocation is
    // left `NoAccess`.
    if ptr::read(base_ptr.add(MALLOC_TAG_OFFSET) as *const usize) != MALLOC_TAG {
        abort();
    }

    let unprotected_size = ptr::read(base_ptr as *const usize);

    // The canary lives in the data region, so restore access before reading it: the
    // caller is allowed to leave the allocation protected until it is freed, and a
    // check that faulted there would kill the process instead of reaching the
    // diagnostic abort below.
    let total_size = PAGE_SIZE + PAGE_SIZE + unprotected_size + PAGE_SIZE;
    _mprotect(base_ptr, total_size, Prot::ReadWrite);

    // check
    #[allow(static_mut_refs)]
    if !crate::memeq(canary_ptr as *const u8, CANARY.as_ptr(), CANARY_SIZE) {
        abort();
    }

    // free
    crate::munlock(unprotected_ptr, unprotected_size);

    free_aligned(base_ptr, total_size);
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sizes in the window that used to overflow the region total are rejected
    /// instead of wrapping into a tiny allocation.
    #[test]
    fn oversized_region_size_is_rejected() {
        let guard = page_size() * 4;

        for offset in (guard - 32)..(guard + 32) {
            let size = usize::MAX - offset;
            // The crate is edition 2018, where a panic message only formats its
            // arguments when they are passed explicitly.
            assert!(
                unsafe { malloc_sized(size) }.is_none(),
                "usize::MAX - {} should be rejected",
                offset
            );
        }

        assert!(unsafe { malloc_sized(usize::MAX) }.is_none());
    }

    /// `malloc::<T>` is aligned for `T`, but `malloc_sized` is page-aligned only
    /// for a page-multiple size: the pointer sits `size` bytes below the end of the
    /// page-rounded data region. Pins the guarantee `page_size` documents.
    #[test]
    fn malloc_is_aligned_for_t_while_malloc_sized_is_not_page_aligned() {
        let allocation = unsafe { malloc::<u64>() }.expect("allocation");
        assert_eq!(
            allocation.as_ptr() as usize % mem::align_of::<u64>(),
            0,
            "malloc::<T> must be aligned for T"
        );
        unsafe { free(allocation) };

        let allocation = unsafe { malloc_sized(24) }.expect("allocation");
        assert_ne!(
            allocation.as_ptr() as *const u8 as usize % page_size(),
            0,
            "malloc_sized is only page-aligned for a page-multiple size"
        );
        unsafe { free(allocation) };

        let allocation = unsafe { malloc_sized(page_size()) }.expect("allocation");
        assert_eq!(
            allocation.as_ptr() as *const u8 as usize % page_size(),
            0,
            "a page-multiple size does land on a page boundary"
        );
        unsafe { free(allocation) };
    }

    #[test]
    fn malloc_header_carries_the_allocator_tag() {
        let mem = unsafe { malloc_sized(32) }.expect("allocation");
        let base = unsafe { unprotected_ptr_from_user_ptr(mem.as_ptr() as *const u8) };
        let tag =
            unsafe { ptr::read(base.sub(PAGE_SIZE * 2).add(MALLOC_TAG_OFFSET) as *const usize) };

        assert_eq!(tag, MALLOC_TAG);

        unsafe { free(mem) };
    }

    /// The spare tag slot must be defined, so `free_memfd_secret` and `mprotect`
    /// never read uninitialised metadata and cannot mistake this header for a
    /// `memfd_secret` one.
    #[test]
    fn malloc_header_defines_the_memfd_tag_slot() {
        let mem = unsafe { malloc_sized(32) }.expect("allocation");
        let base = unsafe { unprotected_ptr_from_user_ptr(mem.as_ptr() as *const u8) };
        let tag =
            unsafe { ptr::read(base.sub(PAGE_SIZE * 2).add(MEMFD_TAG_OFFSET) as *const usize) };

        assert_eq!(tag, NOT_MEMFD_TAG);

        unsafe { free(mem) };
    }

    /// `mprotect` accepts a `malloc` allocation (its tag is `MALL`), and the
    /// allocation is still freeable afterwards.
    #[test]
    fn mprotect_accepts_a_malloc_allocation() {
        let mem = unsafe { malloc_sized(32) }.expect("allocation");

        assert!(unsafe { mprotect(mem, Prot::ReadOnly) });
        assert!(unsafe { mprotect(mem, Prot::ReadWrite) });

        unsafe { free(mem) };
    }

    /// `mprotect` accepts a `memfd_secret` allocation too (its tag is `MFDS`);
    /// `secure-types` protects these allocations through the same entry point.
    #[cfg(all(feature = "alloc_ext", target_os = "linux"))]
    #[test]
    fn mprotect_accepts_a_memfd_secret_allocation() {
        let Some(mem) = (unsafe { crate::memfd_secret_sized(32) }) else {
            return;
        };

        assert!(unsafe { mprotect(mem, Prot::ReadOnly) });
        assert!(unsafe { mprotect(mem, Prot::ReadWrite) });

        unsafe { crate::free_memfd_secret(mem) };
    }

    #[cfg(all(feature = "alloc_ext", target_os = "linux"))]
    #[test]
    fn memfd_secret_header_carries_the_allocator_tag() {
        let Some(mem) = (unsafe { crate::memfd_secret_sized(32) }) else {
            return;
        };
        let base = unsafe { unprotected_ptr_from_user_ptr(mem.as_ptr() as *const u8) };
        let tag =
            unsafe { ptr::read(base.sub(PAGE_SIZE * 2).add(MEMFD_TAG_OFFSET) as *const usize) };

        assert_eq!(tag, MEMFD_TAG);

        unsafe { crate::free_memfd_secret(mem) };
    }
}
