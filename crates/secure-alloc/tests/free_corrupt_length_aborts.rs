//! A data-region length that cannot produce a region total must abort the free.
//!
//! `free` and `free_memfd_secret` read the data-region length out of the metadata page and
//! derive the region total from it. A length that wraps that total would restore a short
//! range, compare the canary at a wild address and hand `dealloc` a layout the allocation
//! never had, so both frees abort instead of continuing. The page is read-only after
//! allocation, so the child makes it writable first and writes the length itself; each test
//! re-executes itself the way `wrong_free_aborts` does, so the abort cannot take the test
//! process down with it.

#![cfg(all(unix, feature = "alloc"))]

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Output};

/// Set in the child that corrupts a `malloc` allocation's data-region length.
const CHILD_MALLOC: &str = "SECURE_ALLOC_FREE_CORRUPT_LENGTH_MALLOC";

/// Set in the child that corrupts a `memfd_secret` allocation's data-region length.
#[cfg(all(target_os = "linux", feature = "alloc_ext"))]
const CHILD_MEMFD: &str = "SECURE_ALLOC_FREE_CORRUPT_LENGTH_MEMFD";

/// Exit code a child uses when `memfd_secret` is unavailable, so the parent can skip.
#[cfg(all(target_os = "linux", feature = "alloc_ext"))]
const EXIT_MEMFD_UNAVAILABLE: i32 = 77;

/// The diagnostic a free writes before it aborts on a length it cannot total.
///
/// Built from `usize::MAX` rather than hardcoded so the expected line matches the width of the
/// platform the suite runs on.
fn corrupt_length_diagnostic() -> String {
    let len = usize::MAX;
    format!("secure-alloc: corrupt allocation header: len {len:#x} overflows the region total")
}

fn run_child(test: &str, marker: &str) -> Output {
    Command::new(std::env::current_exe().unwrap())
        .arg(test)
        .arg("--exact")
        .arg("--nocapture")
        .env(marker, "1")
        .output()
        .expect("failed to execute the test binary")
}

fn stderr_of(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// The child must abort *and* say why: the abort itself does not distinguish the length check
/// from the tag and canary aborts, which print nothing.
fn assert_aborted(output: &Output, expected: &str) {
    let stderr = stderr_of(output);

    assert_eq!(
        output.status.signal(),
        Some(libc::SIGABRT),
        "expected the child to abort, got {:?}: {}",
        output.status,
        stderr
    );
    assert!(
        stderr.contains(expected),
        "the child must report the length it rejected ({:?}): {}",
        expected,
        stderr
    );
}

/// Writes `len` into the metadata page of the allocation `memptr` belongs to.
///
/// The page is `ReadOnly` after allocation, so it is made writable first. The derivation
/// is the allocator's: page-align the canary pointer, then step back over the guard page.
///
/// # Safety
///
/// `memptr` must be the user pointer of a live allocation from this crate, and the caller
/// must be a child process that is about to die: the header is left corrupt, so the
/// allocation can never be released again.
unsafe fn corrupt_region_length(memptr: *const u8, len: usize) {
    let page = secure_alloc::page_size();
    let unprotected = (memptr as usize - 16) & !(page - 1);
    let base = unprotected - 2 * page;

    let res = libc::mprotect(
        base as *mut libc::c_void,
        page,
        libc::PROT_READ | libc::PROT_WRITE,
    );
    assert_eq!(res, 0, "failed to make the metadata page writable");

    (base as *mut usize).write(len);
}

#[test]
fn free_aborts_on_a_region_length_that_would_wrap() {
    if std::env::var_os(CHILD_MALLOC).is_some() {
        let mem = unsafe { secure_alloc::malloc_sized(32) }.expect("allocation");
        unsafe { corrupt_region_length(mem.as_ptr() as *const u8, usize::MAX) };

        // SAFETY: `mem` is a live allocation from the allocator above, released exactly once
        // here, and the child exits without touching it again whatever the call does.
        unsafe { secure_alloc::free(mem) };

        // The total wrapped instead of aborting.
        std::process::exit(3);
    }

    let output = run_child(
        "free_aborts_on_a_region_length_that_would_wrap",
        CHILD_MALLOC,
    );

    assert_aborted(&output, &corrupt_length_diagnostic());
}

#[cfg(all(target_os = "linux", feature = "alloc_ext"))]
#[test]
fn free_memfd_secret_aborts_on_a_region_length_that_would_wrap() {
    if std::env::var_os(CHILD_MEMFD).is_some() {
        let Some(mem) = (unsafe { secure_alloc::memfd_secret_sized(32) }) else {
            std::process::exit(EXIT_MEMFD_UNAVAILABLE);
        };
        unsafe { corrupt_region_length(mem.as_ptr() as *const u8, usize::MAX) };

        // SAFETY: as above, for the allocation this function made.
        unsafe { secure_alloc::free_memfd_secret(mem) };

        // The total wrapped instead of aborting.
        std::process::exit(3);
    }

    let output = run_child(
        "free_memfd_secret_aborts_on_a_region_length_that_would_wrap",
        CHILD_MEMFD,
    );

    // The child makes its own allocation: if the kernel or the sandbox refuses
    // `memfd_secret`, it reports that instead of aborting and the parent skips.
    if output.status.code() == Some(EXIT_MEMFD_UNAVAILABLE) {
        eprintln!("skipping: memfd_secret is unavailable in the child");
        return;
    }

    assert_aborted(&output, &corrupt_length_diagnostic());
}
