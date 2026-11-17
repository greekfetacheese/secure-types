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

/// `memfd_secret` takes `O_CLOEXEC`, not `memfd_create`'s `MFD_CLOEXEC`.
///
/// The flag has to be the one the kernel accepts, or the descriptor is not
/// close-on-exec at creation and the inherited-by-`exec` window the test above
/// guards stays open until a separate `fcntl` runs. That end state cannot tell the
/// two paths apart — the fallback sets the flag as well — so this pins the value the
/// code has to pass.
#[test]
fn memfd_secret_accepts_o_cloexec() {
    let fd = unsafe { libc::syscall(libc::SYS_memfd_secret, libc::O_CLOEXEC) };

    if fd < 0 {
        let error = std::io::Error::last_os_error();

        // A kernel that refuses the flag itself is exactly the case the allocator's
        // fcntl fallback exists for; it is not a failure of this crate.
        if matches!(
            error.raw_os_error(),
            Some(libc::ENOSYS) | Some(libc::EINVAL) | Some(libc::EPERM)
        ) {
            eprintln!("skipping: this kernel does not accept memfd_secret(O_CLOEXEC): {error}");
            return;
        }

        panic!("memfd_secret(O_CLOEXEC) failed: {}", error);
    }

    let fd = fd as i32;
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    unsafe { libc::close(fd) };

    assert!(flags >= 0, "F_GETFD failed on descriptor {}", fd);
    assert_ne!(
        flags & libc::FD_CLOEXEC,
        0,
        "memfd_secret(O_CLOEXEC) did not mark the descriptor close-on-exec at creation"
    );
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

    // Run only this test in the child. Without the filter the whole binary runs there, and the
    // sibling `memfd_secret_accepts_o_cloexec` opens a `secretmem` descriptor of its own: when
    // that lands on `fd`, the child's "the descriptor is closed" check fails spuriously.
    //
    // The child is judged by more than its exit status: a `--exact` filter that matches no test
    // also exits 0, so a rename would let this regression test pass without running anything.
    let output = Command::new(std::env::current_exe().unwrap())
        .arg("secretmem_descriptor_is_close_on_exec")
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_FD, fd.to_string())
        .output()
        .expect("failed to execute the test binary");

    unsafe { secure_alloc::free_memfd_secret(allocation) };

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let ran_once = stdout.contains("1 passed");

    assert!(
        output.status.success(),
        "descriptor {} was inherited across exec: {}",
        fd,
        stderr
    );
    assert!(
        ran_once,
        "the child must run secretmem_descriptor_is_close_on_exec exactly once: {}",
        stdout
    );
}

/// The flag has to be set by the memfd_secret call itself, not by the fallback fcntl:
/// the fallback leaves the descriptor inheritable between the two calls, which is the
/// window memfd_secret's own O_CLOEXEC closes.
///
/// A seccomp filter denies fcntl(fd, F_SETFD, FD_CLOEXEC) with EPERM. On a kernel that
/// accepts the flagged syscall (the case under test), an allocation that needed the
/// fallback therefore returns None - a failure, not a skip - and one that succeeds must
/// already carry FD_CLOEXEC.
#[test]
fn the_descriptor_is_close_on_exec_at_creation() {
    if std::env::var_os(CHILD_FCNTL_DENIED).is_some() {
        // Whether this kernel accepts the flag at all is a different test's subject.
        let probe = unsafe { libc::syscall(libc::SYS_memfd_secret, libc::O_CLOEXEC) };

        if probe < 0 {
            eprintln!("skipping: this kernel does not accept memfd_secret(O_CLOEXEC)");
            std::process::exit(EXIT_SKIP);
        }

        unsafe { libc::close(probe as libc::c_int) };

        if !deny_fcntl_setfd() {
            eprintln!("skipping: this process cannot install a seccomp filter");
            std::process::exit(EXIT_SKIP);
        }

        let Some(allocation) = (unsafe { secure_alloc::memfd_secret::<[u8; 32]>() }) else {
            // The crate fell back to fcntl, which the filter proves it calls.
            std::process::exit(3);
        };

        let Some(fd) = secretmem_fd() else {
            unsafe { secure_alloc::free_memfd_secret(allocation) };
            eprintln!("skipping: no secretmem descriptor found for the live allocation");
            std::process::exit(EXIT_SKIP);
        };

        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };

        unsafe { secure_alloc::free_memfd_secret(allocation) };

        if flags < 0 || flags & libc::FD_CLOEXEC == 0 {
            std::process::exit(4);
        }

        return;
    }

    let output = Command::new(std::env::current_exe().unwrap())
        .arg("the_descriptor_is_close_on_exec_at_creation")
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_FCNTL_DENIED, "1")
        .output()
        .expect("failed to execute the test binary");

    if output.status.code() == Some(EXIT_SKIP) {
        eprintln!("skipping: the creation-time flag cannot be tested here");
        return;
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "the descriptor must be close-on-exec without any fcntl call: {:?}: {}",
        output.status,
        stderr
    );
    assert!(
        stdout.contains("1 passed"),
        "the child must run the_descriptor_is_close_on_exec_at_creation exactly once: {}",
        stdout
    );
}

/// Set in the child that installs the fcntl-denying filter and runs the test body.
const CHILD_FCNTL_DENIED: &str = "SECURE_ALLOC_MEMFD_SECRET_FCNTL_DENIED";

/// Exit code a child uses when the property cannot be exercised on this host.
const EXIT_SKIP: i32 = 77;

/// SECCOMP_RET_ALLOW and SECCOMP_RET_ERRNO, from linux/seccomp.h.
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;

/// SECCOMP_MODE_FILTER, from linux/seccomp.h.
const SECCOMP_MODE_FILTER: libc::c_ulong = 2;

/// cBPF opcodes from linux/filter.h: BPF_LD|BPF_W|BPF_ABS, BPF_JMP|BPF_JEQ|BPF_K,
/// BPF_RET|BPF_K.
const BPF_LD_ABS_W: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;

/// Offsets into struct seccomp_data: the syscall number and args[1] / args[2].
const SECCOMP_DATA_NR: u32 = 0;
const SECCOMP_DATA_ARG1: u32 = 24;
const SECCOMP_DATA_ARG2: u32 = 32;

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

/// Denies exactly fcntl(fd, F_SETFD, FD_CLOEXEC) with EPERM.
///
/// Returns false when the process cannot install a seccomp filter, so the caller can skip
/// instead of failing in a sandbox that forbids it.
fn deny_fcntl_setfd() -> bool {
    let rejected = SECCOMP_RET_ERRNO | libc::EPERM as u32;

    let filter = [
        stmt(BPF_LD_ABS_W, SECCOMP_DATA_NR),
        jump(BPF_JEQ_K, libc::SYS_fcntl as u32, 0, 5),
        stmt(BPF_LD_ABS_W, SECCOMP_DATA_ARG1),
        jump(BPF_JEQ_K, libc::F_SETFD as u32, 0, 3),
        stmt(BPF_LD_ABS_W, SECCOMP_DATA_ARG2),
        jump(BPF_JEQ_K, libc::FD_CLOEXEC as u32, 0, 1),
        stmt(BPF_RET_K, rejected),
        stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
    ];

    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };

    // SAFETY: both calls take integers and a pointer to a filter that outlives them, and
    // the filter is a well-formed eight-statement cBPF program.
    unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0, 0, 0) == 0
            && libc::prctl(
                libc::PR_SET_SECCOMP,
                SECCOMP_MODE_FILTER,
                &prog as *const libc::sock_fprog,
            ) == 0
    }
}
