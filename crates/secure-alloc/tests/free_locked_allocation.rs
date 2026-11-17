//! Freeing an allocation that is still `mprotect`ed `NoAccess` must work.
//!
//! `free` and `free_memfd_secret` read the canary out of the data region, and they
//! used to do it before restoring read/write access. An allocation the caller left
//! protected therefore faulted (SIGSEGV) instead of being released — while
//! `mprotect`'s own contract says the flags may stand "until they are changed again
//! or the allocation is freed".
//!
//! Each test re-executes itself: the child protects the allocation and frees it, and
//! the parent requires a clean exit. A fault in the child is the failure.
#![cfg(feature = "alloc")]

use std::process::Command;

/// Set in the child that frees a locked `malloc` allocation.
const CHILD_MALLOC: &str = "SECURE_ALLOC_FREE_LOCKED_MALLOC";
/// Set in the child that frees a locked `memfd_secret` allocation.
#[cfg(all(target_os = "linux", feature = "alloc_ext"))]
const CHILD_MEMFD: &str = "SECURE_ALLOC_FREE_LOCKED_MEMFD";
/// Exit code a child uses when `memfd_secret` is unavailable, so the parent can skip.
#[cfg(all(target_os = "linux", feature = "alloc_ext"))]
const EXIT_MEMFD_UNAVAILABLE: i32 = 77;

fn run_child(test: &str, marker: &str) -> std::process::Output {
    Command::new(std::env::current_exe().unwrap())
        .arg(test)
        .arg("--exact")
        .arg("--nocapture")
        .env(marker, "1")
        .output()
        .expect("failed to execute the test binary")
}

#[test]
fn free_of_a_locked_malloc_allocation_succeeds() {
    if std::env::var_os(CHILD_MALLOC).is_some() {
        let mem = unsafe { secure_alloc::malloc_sized(32) }.expect("allocation");
        assert!(unsafe { secure_alloc::mprotect(mem, secure_alloc::Prot::NoAccess) });

        unsafe { secure_alloc::free(mem) };
        // Fall out of the test so the harness prints its summary; the parent also
        // requires that summary, which a renamed `--exact` filter never produces.
        return;
    }

    let output = run_child("free_of_a_locked_malloc_allocation_succeeds", CHILD_MALLOC);

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        output.status.success(),
        "freeing an allocation left NoAccess must succeed, but the child exited with {:?}",
        output.status
    );
    // A `--exact` filter that matches no test also exits 0, so a rename must not let this
    // regression test pass without running the body.
    assert!(
        stdout.contains("1 passed"),
        "the child must run free_of_a_locked_malloc_allocation_succeeds exactly once: {}",
        stdout
    );
}

#[cfg(all(target_os = "linux", feature = "alloc_ext"))]
#[test]
fn free_of_a_locked_memfd_secret_allocation_succeeds() {
    if std::env::var_os(CHILD_MEMFD).is_some() {
        let Some(mem) = (unsafe { secure_alloc::memfd_secret_sized(32) }) else {
            std::process::exit(EXIT_MEMFD_UNAVAILABLE);
        };
        assert!(unsafe { secure_alloc::mprotect(mem, secure_alloc::Prot::NoAccess) });

        unsafe { secure_alloc::free_memfd_secret(mem) };
        return;
    }

    let output = run_child(
        "free_of_a_locked_memfd_secret_allocation_succeeds",
        CHILD_MEMFD,
    );

    if output.status.code() == Some(EXIT_MEMFD_UNAVAILABLE) {
        eprintln!("skipping: memfd_secret is unavailable on this kernel");
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(
        output.status.success(),
        "freeing a memfd_secret allocation left NoAccess must succeed, but the child exited with {:?}",
        output.status
    );
    assert!(
        stdout.contains("1 passed"),
        "the child must run free_of_a_locked_memfd_secret_allocation_succeeds exactly once: {}",
        stdout
    );
}
