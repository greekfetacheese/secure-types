//! A failed allocation must give its lock back.
//!
//! `_malloc` locks the data region before it installs the read-only metadata page. When
//! that last protection change is rejected the region is released, and releasing it
//! without `munlock` leaves the pages locked and dump-excluded inside the global
//! allocator's heap: the `RLIMIT_MEMLOCK` charge is never returned, and a later ordinary
//! allocation in the same chunk silently inherits the dump exclusion. This test rejects
//! exactly that one `mprotect` (`prot == PROT_READ`, with a seccomp filter) so both guard
//! pages still install, and reads `VmLck` back. It re-executes itself the way the other
//! abort tests do: the filter is permanent for the process that installs it.

#![cfg(all(target_os = "linux", feature = "alloc"))]

use std::process::{Command, Output};

/// Set in the child that makes the failed allocations.
const CHILD: &str = "SECURE_ALLOC_MLOCK_RELEASE_LEAK";

/// Exit code the child uses when `mlock` cannot succeed here, so the parent can skip: with
/// nothing lockable the leak check would pass no matter what the code does.
const EXIT_SKIP: i32 = 77;

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

/// Offsets into `struct seccomp_data`: the syscall number, and `args[2]` - the `prot`
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

/// Answers `mprotect` with `ENOMEM` when it asks for exactly `PROT_READ`.
///
/// That is the metadata page only: the guard pages ask for `PROT_NONE` and the release for
/// `PROT_READ | PROT_WRITE`, so an allocation reaches the metadata change with its region
/// locked and then fails there.
fn deny_read_only_mprotect() {
    let rejected = SECCOMP_RET_ERRNO | libc::ENOMEM as u32;

    let mprotect = libc::SYS_mprotect as u32;

    let filter = [
        stmt(BPF_LD_ABS_W, SECCOMP_DATA_NR),
        jump(BPF_JEQ_K, mprotect, 0, 3),
        stmt(BPF_LD_ABS_W, SECCOMP_DATA_ARG2),
        jump(BPF_JEQ_K, libc::PROT_READ as u32, 0, 1),
        stmt(BPF_RET_K, rejected),
        stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
    ];

    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_ptr() as *mut libc::sock_filter,
    };

    // SAFETY: both calls take integers and a pointer to a filter that outlives them, and the
    // filter is a well-formed six-statement cBPF program.
    unsafe {
        assert_eq!(
            libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1 as libc::c_ulong, 0, 0, 0),
            0,
            "failed to set no_new_privs"
        );
        assert_eq!(
            libc::prctl(
                libc::PR_SET_SECCOMP,
                SECCOMP_MODE_FILTER,
                &prog as *const libc::sock_fprog,
            ),
            0,
            "failed to install the seccomp filter"
        );
    }
}

/// `VmLck` of this process, in kB, per `/proc/self/status`.
fn vmlck_kb() -> u64 {
    let status = std::fs::read_to_string("/proc/self/status").expect("/proc/self/status");
    let line = status
        .lines()
        .find(|line| line.starts_with("VmLck:"))
        .expect("no VmLck line in /proc/self/status");

    line["VmLck:".len()..]
        .trim()
        .trim_end_matches("kB")
        .trim()
        .parse()
        .expect("VmLck is not a number")
}

fn run_child(test: &str) -> Output {
    Command::new(std::env::current_exe().unwrap())
        .arg(test)
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD, "1")
        .output()
        .expect("failed to execute the test binary")
}

#[test]
fn a_failed_allocation_does_not_keep_its_lock() {
    if std::env::var_os(CHILD).is_some() {
        deny_read_only_mprotect();

        // Positive control: the assertion below is only meaningful when a lock can
        // succeed and move `VmLck`. At `RLIMIT_MEMLOCK=0` (or under a stricter limit) the
        // failing allocations never lock anything, so a leak cannot show up at all.
        let page = secure_alloc::page_size();
        let layout = std::alloc::Layout::from_size_align(page, page).expect("control layout");
        // SAFETY: the layout is non-zero and this is the matching deallocator below.
        let control = unsafe { std::alloc::alloc(layout) };
        assert!(!control.is_null(), "control allocation failed");

        let before_control = vmlck_kb();
        // SAFETY: `control` is a live page-aligned allocation of at least a page.
        let locked = unsafe { secure_alloc::mlock(control, page) };
        let after_control = vmlck_kb();

        // SAFETY: same allocation, released exactly once here.
        unsafe {
            secure_alloc::munlock(control, page);
            std::alloc::dealloc(control, layout);
        }

        if !locked || after_control == before_control {
            eprintln!(
                "skipping: mlock cannot succeed here (VmLck {before_control} -> {after_control} kB)"
            );
            std::process::exit(EXIT_SKIP);
        }

        let before = vmlck_kb();

        for _ in 0..4 {
            // Every attempt locks its data region and then fails on the metadata page; the
            // release must unlock it again.
            assert!(unsafe { secure_alloc::malloc_sized(4096) }.is_none());
        }

        let after = vmlck_kb();

        eprintln!("VmLck before {before} kB, after {after} kB");

        // One attempted allocation locks at least one page, and `mlock` rounds a range up,
        // so a leak moves `VmLck` off its baseline.
        std::process::exit(if after == before { 0 } else { 3 });
    }

    let output = run_child("a_failed_allocation_does_not_keep_its_lock");

    if output.status.code() == Some(EXIT_SKIP) {
        eprintln!("skipping: mlock cannot succeed in the child here");
        return;
    }

    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();

    assert!(
        output.status.success(),
        "a failed allocation must not keep its pages locked (child exited {:?}): {}",
        output.status,
        stderr
    );
    assert!(
        stderr.contains("secure-alloc: mprotect failed: malloc metadata"),
        "the filter must reject the metadata page, not an earlier change: {}",
        stderr
    );
}
