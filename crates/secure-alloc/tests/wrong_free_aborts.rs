//! A free through the wrong allocator must abort.
//!
//! `free` and `free_memfd_secret` both take a `NonNull<T>`, so the type system
//! cannot stop a caller from pairing them wrongly. Without an allocator tag,
//! `free_memfd_secret` on a `malloc` allocation would `close` the integer stored
//! where the descriptor lives on the other layout (`close(0)` closes stdin), and
//! `free` on a `memfd_secret` allocation would hand `secretmem` memory to the
//! global allocator's `dealloc`. Each test re-executes itself with a marker: the
//! child performs the mismatched free, the parent requires it to die with
//! `SIGABRT`. A child that reaches `exit(3)` means the tag was not enforced; a child
//! that exits `EXIT_MEMFD_UNAVAILABLE` means `memfd_secret` is unavailable here and
//! the parent skips.

#![cfg(all(target_os = "linux", feature = "alloc_ext"))]

use std::os::unix::process::ExitStatusExt;
use std::process::Command;

/// Set in the child that frees a `malloc` allocation with `free_memfd_secret`.
const CHILD_FREE_MALLOC_WITH_MEMFD: &str = "SECURE_ALLOC_FREE_MALLOC_WITH_MEMFD";
/// Set in the child that frees a `memfd_secret` allocation with `free`.
const CHILD_FREE_MEMFD_WITH_MALLOC: &str = "SECURE_ALLOC_FREE_MEMFD_WITH_MALLOC";
/// Set in the child that clears a `malloc` header tag and then calls `mprotect`.
const CHILD_MPROTECT_UNTAGGED: &str = "SECURE_ALLOC_MPROTECT_UNTAGGED";
/// Set in the child that clears a `malloc` header tag and then calls `free`.
const CHILD_FREE_UNTAGGED_MALLOC: &str = "SECURE_ALLOC_FREE_UNTAGGED_MALLOC";
/// Set in the child that clears a `memfd_secret` header tag and then calls
/// `free_memfd_secret`.
const CHILD_FREE_UNTAGGED_MEMFD: &str = "SECURE_ALLOC_FREE_UNTAGGED_MEMFD";

/// Exit code a child uses when `memfd_secret` is unavailable, so the parent can skip
/// instead of failing on a kernel where the allocation cannot be made.
const EXIT_MEMFD_UNAVAILABLE: i32 = 77;

fn run_child(test: &str, marker: &str) -> std::process::ExitStatus {
    Command::new(std::env::current_exe().unwrap())
        .arg(test)
        .arg("--exact")
        .arg("--nocapture")
        .env(marker, "1")
        .status()
        .expect("failed to execute the test binary")
}

fn assert_aborted(status: std::process::ExitStatus) {
    assert_eq!(
        status.signal(),
        Some(libc::SIGABRT),
        "expected the child to abort, got {:?}",
        status
    );
}

#[test]
fn free_memfd_secret_on_malloc_allocation_aborts() {
    if std::env::var_os(CHILD_FREE_MALLOC_WITH_MEMFD).is_some() {
        let mem = unsafe { secure_alloc::malloc_sized(32) }.expect("allocation");
        unsafe { secure_alloc::free_memfd_secret(mem) };
        // The tag was not enforced: the call closed something and returned.
        std::process::exit(3);
    }

    assert_aborted(run_child(
        "free_memfd_secret_on_malloc_allocation_aborts",
        CHILD_FREE_MALLOC_WITH_MEMFD,
    ));
}

#[test]
fn free_on_memfd_secret_allocation_aborts() {
    if std::env::var_os(CHILD_FREE_MEMFD_WITH_MALLOC).is_some() {
        let Some(mem) = (unsafe { secure_alloc::memfd_secret_sized(32) }) else {
            eprintln!("skipping: memfd_secret is unavailable on this kernel");
            std::process::exit(EXIT_MEMFD_UNAVAILABLE);
        };
        unsafe { secure_alloc::free(mem) };
        // The tag was not enforced: the call returned (or glibc freed it).
        std::process::exit(3);
    }

    let Some(mem) = (unsafe { secure_alloc::memfd_secret_sized(32) }) else {
        eprintln!("skipping: memfd_secret is unavailable on this kernel");
        return;
    };
    unsafe { secure_alloc::free_memfd_secret(mem) };

    let status = run_child(
        "free_on_memfd_secret_allocation_aborts",
        CHILD_FREE_MEMFD_WITH_MALLOC,
    );

    // The child allocates its own allocation: if the kernel ran out of descriptors or
    // the sandbox denies `memfd_secret`, it reports that instead of aborting, and the
    // parent skips rather than failing on an environment it cannot test.
    if status.code() == Some(EXIT_MEMFD_UNAVAILABLE) {
        eprintln!("skipping: memfd_secret is unavailable in the child");
        return;
    }

    assert_aborted(status);
}

/// A metadata page that carries neither allocator tag must abort `mprotect` too,
/// before it trusts the length at offset 0. The child clears the tag of a live
/// allocation's metadata page (read-only after allocation, so it is made writable
/// first).
#[test]
fn mprotect_on_an_untagged_allocation_aborts() {
    if std::env::var_os(CHILD_MPROTECT_UNTAGGED).is_some() {
        let mem = unsafe { secure_alloc::malloc_sized(32) }.expect("allocation");
        let page_size = secure_alloc::page_size();
        let ptr = mem.as_ptr() as *mut u8;

        // Same derivation as the allocator: page-align the canary pointer, then step
        // back over the guard page to the metadata page.
        let unprotected = (ptr as usize - 16) & !(page_size - 1);
        let base = unprotected - 2 * page_size;

        let res = unsafe {
            libc::mprotect(
                base as *mut libc::c_void,
                page_size,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        };
        assert_eq!(res, 0, "failed to make the metadata page writable");

        // Clear the allocator tag: the second `usize` of the metadata page.
        unsafe { (base as *mut usize).add(1).write(0) };

        unsafe { secure_alloc::mprotect(mem, secure_alloc::Prot::ReadWrite) };
        // The tag was not enforced: the call returned.
        std::process::exit(3);
    }

    assert_aborted(run_child(
        "mprotect_on_an_untagged_allocation_aborts",
        CHILD_MPROTECT_UNTAGGED,
    ));
}

/// Clears the allocator tag of a live allocation's metadata page, returning its base.
///
/// The page is read-only after allocation, so it is made writable first. The derivation
/// is the allocator's: page-align the canary pointer, then step back over the guard page.
///
/// # Safety
///
/// `memptr` must be the user pointer of a live allocation from this crate, and the caller
/// must be a child process that is about to die: the header is left corrupt.
unsafe fn clear_tag(memptr: *const u8, tag_offset: usize) {
    let page_size = secure_alloc::page_size();
    let unprotected = (memptr as usize - 16) & !(page_size - 1);
    let base = unprotected - 2 * page_size;

    let res = libc::mprotect(
        base as *mut libc::c_void,
        page_size,
        libc::PROT_READ | libc::PROT_WRITE,
    );
    assert_eq!(res, 0, "failed to make the metadata page writable");

    (base as *mut usize).add(tag_offset).write(0);
}

/// A `free` that reaches an allocation whose `MALL` tag was cleared must abort on the tag,
/// not go on to trust the length and the canary. Without the check the free would complete
/// (the canary is untouched and the block is a real allocation) and the child would exit 3.
#[test]
fn free_on_an_untagged_malloc_allocation_aborts() {
    if std::env::var_os(CHILD_FREE_UNTAGGED_MALLOC).is_some() {
        let mem = unsafe { secure_alloc::malloc_sized(32) }.expect("allocation");

        // MALLOC_TAG_OFFSET is one usize into the metadata page.
        unsafe { clear_tag(mem.as_ptr() as *const u8, 1) };

        unsafe { secure_alloc::free(mem) };
        // The tag was not enforced: the free completed.
        std::process::exit(3);
    }

    assert_aborted(run_child(
        "free_on_an_untagged_malloc_allocation_aborts",
        CHILD_FREE_UNTAGGED_MALLOC,
    ));
}

/// The same for `free_memfd_secret`: a cleared `MFDS` tag must abort before the descriptor
/// is read. Without the check the teardown would unmap the region and close the descriptor
/// and return, so the child would exit 3.
#[test]
fn free_memfd_secret_on_an_untagged_memfd_allocation_aborts() {
    if std::env::var_os(CHILD_FREE_UNTAGGED_MEMFD).is_some() {
        let Some(mem) = (unsafe { secure_alloc::memfd_secret_sized(32) }) else {
            eprintln!("skipping: memfd_secret is unavailable on this kernel");
            std::process::exit(EXIT_MEMFD_UNAVAILABLE);
        };

        // MEMFD_TAG_OFFSET is two usizes into the metadata page; the slot between them
        // holds the descriptor and the pad, whose low half is what the fd is read from.
        unsafe { clear_tag(mem.as_ptr() as *const u8, 2) };

        unsafe { secure_alloc::free_memfd_secret(mem) };
        // The tag was not enforced: the teardown completed.
        std::process::exit(3);
    }

    let status = run_child(
        "free_memfd_secret_on_an_untagged_memfd_allocation_aborts",
        CHILD_FREE_UNTAGGED_MEMFD,
    );

    if status.code() == Some(EXIT_MEMFD_UNAVAILABLE) {
        eprintln!("skipping: memfd_secret is unavailable in the child");
        return;
    }

    assert_aborted(status);
}
