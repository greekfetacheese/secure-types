//! `mlock` must exclude the caller's bytes from core dumps.
//!
//! `madvise` rejects a range that is not page-aligned with `EINVAL`, while
//! `mlock` accepts one and rounds it itself. So an unaligned `mlock` used to
//! succeed while its dump exclusion silently did nothing.

#![cfg(all(target_os = "linux", feature = "use_os"))]

use std::ptr;

fn page_size() -> usize {
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    assert!(page_size > 0, "sysconf(_SC_PAGESIZE) failed");
    page_size as usize
}

/// The `VmFlags` line of the mapping that contains `addr`, per `/proc/self/smaps`.
fn vm_flags(addr: usize) -> Option<String> {
    let maps = std::fs::read_to_string("/proc/self/smaps").ok()?;
    let mut range = None;

    for line in maps.lines() {
        if let Some((first, _)) = line.split_once(' ') {
            if let Some((start, end)) = first.split_once('-') {
                if let (Ok(start), Ok(end)) = (
                    usize::from_str_radix(start, 16),
                    usize::from_str_radix(end, 16),
                ) {
                    range = Some((start, end));
                    continue;
                }
            }
        }

        if line.starts_with("VmFlags:") {
            if let Some((start, end)) = range {
                if (start..end).contains(&addr) {
                    return Some(line.trim().to_string());
                }
            }
        }
    }

    None
}

fn has_flag(flags: &str, flag: &str) -> bool {
    flags.split_whitespace().any(|it| it == flag)
}

fn anonymous_pages(pages: usize) -> *mut u8 {
    let mem = unsafe {
        libc::mmap(
            ptr::null_mut(),
            page_size() * pages,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
            -1,
            0,
        )
    };
    assert_ne!(mem, libc::MAP_FAILED, "mmap failed");
    mem as *mut u8
}

#[test]
fn unaligned_range_is_excluded_from_core_dumps() {
    let mem = anonymous_pages(1);
    let target = mem as usize + 16;

    let before = vm_flags(target).expect("no smaps entry for the mapping");
    assert!(
        !has_flag(&before, "dd"),
        "already excluded before the call: {}",
        before
    );

    let locked = unsafe { secure_alloc::mlock(mem.add(1), 100) };
    let after = vm_flags(target).expect("no smaps entry for the mapping");

    unsafe {
        secure_alloc::munlock(mem, page_size());
        libc::munmap(mem as *mut libc::c_void, page_size());
    }

    assert!(locked, "mlock of an unaligned range failed");
    assert!(
        has_flag(&after, "dd"),
        "range not excluded from core dumps: {}",
        after
    );
}

#[test]
fn munlock_restores_dumpability() {
    let mem = anonymous_pages(1);
    let target = mem as usize + 16;

    assert!(unsafe { secure_alloc::mlock(mem.add(1), 100) });
    let locked = vm_flags(target).expect("no smaps entry for the mapping");
    assert!(
        has_flag(&locked, "dd"),
        "range not excluded from core dumps: {}",
        locked
    );

    assert!(unsafe { secure_alloc::munlock(mem.add(1), 100) });
    let unlocked = vm_flags(target).expect("no smaps entry for the mapping");

    unsafe { libc::munmap(mem as *mut libc::c_void, page_size()) };

    assert!(
        !has_flag(&unlocked, "dd"),
        "still excluded after munlock: {}",
        unlocked
    );
}
