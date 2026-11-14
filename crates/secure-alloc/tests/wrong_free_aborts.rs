//! A free through the wrong allocator must abort.
//!
//! `free` and `free_memfd_secret` both take a `NonNull<T>`, so the type system
//! cannot stop a caller from pairing them wrongly. Without an allocator tag,
//! `free_memfd_secret` on a `malloc` allocation would `close` the integer stored
//! where the descriptor lives on the other layout (`close(0)` closes stdin), and
//! `free` on a `memfd_secret` allocation would hand `secretmem` memory to the
//! global allocator's `dealloc`. Each test re-executes itself with a marker: the
//! child performs the mismatched free, the parent requires it to die with
//! `SIGABRT`. A child that reaches `exit(3)` means the tag was not enforced.

#![cfg(all(target_os = "linux", feature = "alloc_ext"))]

use std::os::unix::process::ExitStatusExt;
use std::process::Command;

/// Set in the child that frees a `malloc` allocation with `free_memfd_secret`.
const CHILD_FREE_MALLOC_WITH_MEMFD: &str = "SECURE_ALLOC_FREE_MALLOC_WITH_MEMFD";
/// Set in the child that frees a `memfd_secret` allocation with `free`.
const CHILD_FREE_MEMFD_WITH_MALLOC: &str = "SECURE_ALLOC_FREE_MEMFD_WITH_MALLOC";

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
            return;
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

    assert_aborted(run_child(
        "free_on_memfd_secret_allocation_aborts",
        CHILD_FREE_MEMFD_WITH_MALLOC,
    ));
}
