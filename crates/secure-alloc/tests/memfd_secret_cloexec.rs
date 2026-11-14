//! The `memfd_secret` backing descriptor must not survive `exec`.
//!
//! A `memfd_secret` allocation keeps its file descriptor for the whole life of
//! the allocation, because `free_memfd_secret` needs it to unmap the pages and
//! close the file. Without `FD_CLOEXEC`, every child the host spawns inherits a
//! handle to the secret memory and can read it. This test re-executes itself and
//! checks that the descriptor is gone on the other side.

#![cfg(all(target_os = "linux", feature = "alloc_ext"))]

use std::process::Command;

/// Set in the child, holding the descriptor the parent allocated.
const CHILD_FD: &str = "SECURE_ALLOC_MEMFD_SECRET_FD";

/// Descriptor number of a live `secretmem` file in this process, if any.
fn secretmem_fd() -> Option<i32> {
    std::fs::read_dir("/proc/self/fd")
        .ok()?
        .filter_map(|entry| {
            let entry = entry.ok()?;
            let fd = entry.file_name().to_str()?.parse().ok()?;
            let target = std::fs::read_link(entry.path()).ok()?;
            // `/secretmem (deleted)` on the kernels this has been tried on.
            target.to_string_lossy().contains("secretmem").then_some(fd)
        })
        .next()
}

#[test]
fn secretmem_descriptor_is_close_on_exec() {
    if let Ok(fd) = std::env::var(CHILD_FD) {
        // Child: the descriptor must not exist in this process.
        let fd: i32 = fd.parse().expect("bad descriptor in the child environment");
        let open = unsafe { libc::fcntl(fd, libc::F_GETFD) } >= 0;
        assert!(!open, "descriptor {} was inherited across exec", fd);
        return;
    }

    let Some(allocation) = (unsafe { secure_alloc::memfd_secret::<[u8; 32]>() }) else {
        eprintln!("skipping: memfd_secret is unavailable on this kernel");
        return;
    };

    let Some(fd) = secretmem_fd() else {
        eprintln!("skipping: no secretmem descriptor found for the live allocation");
        unsafe { secure_alloc::free_memfd_secret(allocation) };
        return;
    };

    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    assert!(flags >= 0, "F_GETFD failed on descriptor {}", fd);
    assert_ne!(
        flags & libc::FD_CLOEXEC,
        0,
        "descriptor {} is not close-on-exec",
        fd
    );

    let status = Command::new(std::env::current_exe().unwrap())
        .env(CHILD_FD, fd.to_string())
        .status()
        .expect("failed to execute the test binary");

    unsafe { secure_alloc::free_memfd_secret(allocation) };

    assert!(
        status.success(),
        "descriptor {} was inherited across exec",
        fd
    );
}
