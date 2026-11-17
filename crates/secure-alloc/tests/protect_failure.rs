//! A protection change the kernel rejects must not be ignored.
//!
//! Two ways to make `mprotect` fail without root are used here:
//!
//! * a seccomp filter that answers `ENOMEM` for `mprotect` — for every call, which
//!   rejects the guard page, or for every call but `PROT_NONE`, which lets the guards
//!   through and rejects the read-only metadata page;
//! * `munmap`ing a page inside a live allocation, so the whole-region restore `free`
//!   and `free_memfd_secret` perform covers a hole and the kernel answers `ENOMEM`.
//!
//! The allocation paths refuse the region and return `None`, because they have an
//! `Option` channel. The free paths abort, because they have none. Each test re-executes
//! the test binary with a marker, the way `wrong_free_aborts` does, so an abort cannot
//! take the test process down with it.

#![cfg(all(target_os = "linux", feature = "alloc"))]

use std::os::unix::process::ExitStatusExt;
use std::process::{Command, Output};

/// Exit code a child uses when `memfd_secret` is unavailable, so the parent can skip.
#[cfg(feature = "alloc_ext")]
const EXIT_MEMFD_UNAVAILABLE: i32 = 77;

/// Exit code a child uses when the process cannot install a seccomp filter, so the parent
/// can skip instead of reporting a red suite on a sandbox that forbids it.
const EXIT_SECCOMP_UNAVAILABLE: i32 = 78;

/// Set in the child whose guard page cannot be installed.
const CHILD_GUARD_PAGE: &str = "SECURE_ALLOC_PROTECT_GUARD_PAGE";
/// Set in the child whose read-only metadata page cannot be installed.
const CHILD_METADATA_PAGE: &str = "SECURE_ALLOC_PROTECT_METADATA_PAGE";
/// Set in the child whose `free` restore cannot cover the region.
const CHILD_FREE_RESTORE: &str = "SECURE_ALLOC_PROTECT_FREE_RESTORE";
/// Set in the child whose `free_memfd_secret` restore cannot cover the region.
#[cfg(feature = "alloc_ext")]
const CHILD_MEMFD_RESTORE: &str = "SECURE_ALLOC_PROTECT_MEMFD_RESTORE";

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

/// A rejected change is reported with the range it covered and the error the call left
/// behind. The seccomp filter answers `ENOMEM`, so the number is 12.
fn assert_protection_detail(stderr: &str, what: &str) {
    let site = format!("secure-alloc: mprotect failed: {what} (ptr 0x");
    // Edition 2018: a panic message is only a format string when its arguments are passed
    // explicitly.
    let message = format!(
        "the child must name the rejected change and the range it covered ({site:?}): {stderr:?}"
    );
    assert!(stderr.contains(&site), "{}", message);

    let message = format!("the child must carry the ENOMEM the filter answers with: {stderr:?}");
    assert!(stderr.contains("os error 12"), "{}", message);
}

/// `SECCOMP_RET_ALLOW` and `SECCOMP_RET_ERRNO`, from `linux/seccomp.h`.
const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;

/// `SECCOMP_MODE_FILTER`, from `linux/seccomp.h`.
const SECCOMP_MODE_FILTER: libc::c_ulong = 2;

/// cBPF opcodes from `linux/filter.h`: `BPF_LD | BPF_W | BPF_ABS`,
/// `BPF_JMP | BPF_JEQ | BPF_K` and `BPF_RET | BPF_K`.
const BPF_LD_ABS_W: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;

/// Offsets into `struct seccomp_data`: the syscall number, and `args[2]` — the `prot`
/// argument of `mprotect`.
const SECCOMP_DATA_NR: u32 = 0;
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

/// Installs a seccomp filter that answers `mprotect` with `ENOMEM`.
///
/// `allow_prot_none` lets the guard-page calls through, so the filter reaches the
/// read-only metadata page instead of stopping at the first guard.
///
/// Returns `false` when the process cannot install a seccomp filter, so the caller can
/// skip instead of failing on a host that forbids it.
fn deny_mprotect(allow_prot_none: bool) -> bool {
    let rejected = SECCOMP_RET_ERRNO | libc::ENOMEM as u32;

    let mprotect = libc::SYS_mprotect as u32;

    let filter = if allow_prot_none {
        vec![
            stmt(BPF_LD_ABS_W, SECCOMP_DATA_NR),
            jump(BPF_JEQ_K, mprotect, 0, 3),
            stmt(BPF_LD_ABS_W, SECCOMP_DATA_ARG2),
            jump(BPF_JEQ_K, libc::PROT_NONE as u32, 1, 0),
            stmt(BPF_RET_K, rejected),
            stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
        ]
    } else {
        vec![
            stmt(BPF_LD_ABS_W, SECCOMP_DATA_NR),
            jump(BPF_JEQ_K, mprotect, 0, 1),
            stmt(BPF_RET_K, rejected),
            stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
        ]
    };

    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };

    // SAFETY: both calls take integers and a pointer to a filter that outlives the
    // calls, and the filter is a well-formed four-statement cBPF program.
    let installed = unsafe {
        libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0, 0, 0) == 0
            && libc::prctl(
                libc::PR_SET_SECCOMP,
                SECCOMP_MODE_FILTER,
                &prog as *const libc::sock_fprog,
            ) == 0
    };

    if !installed {
        let error = std::io::Error::last_os_error();
        eprintln!("skipping: cannot install a seccomp filter: {error}");
    }

    installed
}

/// The guard page is the first protection change an allocation makes. A rejected one
/// must fail the allocation rather than hand out a region that cannot fault.
#[test]
fn allocation_returns_none_when_the_guard_page_is_rejected() {
    if std::env::var_os(CHILD_GUARD_PAGE).is_some() {
        if !deny_mprotect(false) {
            std::process::exit(EXIT_SECCOMP_UNAVAILABLE);
        }

        // Every internal `mprotect` is refused from here on, so the guard page cannot be
        // installed and the region must not be handed out.
        if unsafe { secure_alloc::malloc_sized(32) }.is_some() {
            std::process::exit(3);
        }

        return;
    }

    let output = run_child(
        "allocation_returns_none_when_the_guard_page_is_rejected",
        CHILD_GUARD_PAGE,
    );
    if output.status.code() == Some(EXIT_SECCOMP_UNAVAILABLE) {
        eprintln!("skipping: this process cannot install a seccomp filter");
        return;
    }

    let stderr = stderr_of(&output);

    assert!(
        output.status.success(),
        "the child must report an allocation failure, not abort or panic: {:?}\n{stderr}",
        output.status
    );
    assert!(
        stderr.contains("secure-alloc: mprotect failed: malloc guard page"),
        "the child must name the rejected protection change: {:?}",
        stderr
    );
    assert_protection_detail(&stderr, "malloc guard page");
    // The guard page is the first change; a rejected one must end the allocation there.
    // If the guard results were discarded, the code would go on and also report the
    // metadata change, which this pins.
    assert!(
        !stderr.contains("secure-alloc: mprotect failed: malloc metadata"),
        "a rejected guard page must not be followed by the metadata change: {:?}",
        stderr
    );
}

/// A metadata page left writable would let the caller rewrite the length and the tag.
/// A rejected change must fail the allocation instead.
#[test]
fn allocation_returns_none_when_the_metadata_page_is_rejected() {
    if std::env::var_os(CHILD_METADATA_PAGE).is_some() {
        // `PROT_NONE` is allowed, so both guards are installed and only the read-only
        // metadata page is refused.
        if !deny_mprotect(true) {
            std::process::exit(EXIT_SECCOMP_UNAVAILABLE);
        }

        if unsafe { secure_alloc::malloc_sized(32) }.is_some() {
            std::process::exit(3);
        }

        return;
    }

    let output = run_child(
        "allocation_returns_none_when_the_metadata_page_is_rejected",
        CHILD_METADATA_PAGE,
    );

    if output.status.code() == Some(EXIT_SECCOMP_UNAVAILABLE) {
        eprintln!("skipping: this process cannot install a seccomp filter");
        return;
    }

    let stderr = stderr_of(&output);

    assert!(
        output.status.success(),
        "the child must report an allocation failure, not abort or panic: {:?}\n{stderr}",
        output.status
    );
    assert!(
        stderr.contains("secure-alloc: mprotect failed: malloc metadata"),
        "the child must name the rejected protection change: {:?}",
        stderr
    );
    assert_protection_detail(&stderr, "malloc metadata");
}

/// `free` has no error channel, so a restore that cannot cover the region must abort
/// rather than read the canary and zeroize memory in an unknown protection state.
#[test]
fn free_aborts_when_the_restore_is_rejected() {
    if std::env::var_os(CHILD_FREE_RESTORE).is_some() {
        let mem = unsafe { secure_alloc::malloc_sized(32) }.expect("allocation");
        let page = secure_alloc::page_size();

        // Same derivation as the allocator: page-align the canary pointer, then step
        // back over the guard page to the metadata page.
        let unprotected = ((mem.as_ptr() as *const u8 as usize) - 16) & !(page - 1);
        let base = unprotected - 2 * page;

        // Punch a hole in the leading guard page: the restore `free` runs over the whole
        // region now covers unmapped memory, which `mprotect` answers with `ENOMEM`.
        let res = unsafe { libc::munmap((base + page) as *mut libc::c_void, page) };
        assert_eq!(res, 0, "failed to unmap the guard page");

        unsafe { secure_alloc::free(mem) };
        std::process::exit(3);
    }

    let output = run_child(
        "free_aborts_when_the_restore_is_rejected",
        CHILD_FREE_RESTORE,
    );
    let stderr = stderr_of(&output);

    assert_eq!(
        output.status.signal(),
        Some(libc::SIGABRT),
        "the child must abort when the restore cannot cover the region, got {:?}\n{stderr}",
        output.status
    );
    assert!(
        stderr.contains("secure-alloc: mprotect failed: free restore"),
        "the child must name the rejected protection change: {:?}",
        stderr
    );
    assert_protection_detail(&stderr, "free restore");
}

/// The same for the `memfd_secret` teardown, whose restore precedes `munmap`.
#[cfg(feature = "alloc_ext")]
#[test]
fn free_memfd_secret_aborts_when_the_restore_is_rejected() {
    if std::env::var_os(CHILD_MEMFD_RESTORE).is_some() {
        let Some(mem) = (unsafe { secure_alloc::memfd_secret_sized(32) }) else {
            std::process::exit(EXIT_MEMFD_UNAVAILABLE);
        };

        let page = secure_alloc::page_size();
        let unprotected = ((mem.as_ptr() as *const u8 as usize) - 16) & !(page - 1);
        let base = unprotected - 2 * page;

        let res = unsafe { libc::munmap((base + page) as *mut libc::c_void, page) };
        assert_eq!(res, 0, "failed to unmap the guard page");

        unsafe { secure_alloc::free_memfd_secret(mem) };
        std::process::exit(3);
    }

    let output = run_child(
        "free_memfd_secret_aborts_when_the_restore_is_rejected",
        CHILD_MEMFD_RESTORE,
    );

    // The child allocates its own region: if the kernel or the sandbox refuses
    // `memfd_secret`, it reports that instead of aborting and the parent skips.
    if output.status.code() == Some(EXIT_MEMFD_UNAVAILABLE) {
        eprintln!("skipping: memfd_secret is unavailable in the child");
        return;
    }

    let stderr = stderr_of(&output);

    assert_eq!(
        output.status.signal(),
        Some(libc::SIGABRT),
        "the child must abort when the restore cannot cover the region, got {:?}\n{stderr}",
        output.status
    );
    assert!(
        stderr.contains("secure-alloc: mprotect failed: memfd free restore"),
        "the child must name the rejected protection change: {:?}",
        stderr
    );
    assert_protection_detail(&stderr, "memfd free restore");
}
