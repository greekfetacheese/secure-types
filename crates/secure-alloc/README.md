# secure-alloc

Secure memory allocation, locking and zeroing for Rust, in `no_std`.

This crate is a vendored fork of [quininer/memsec](https://github.com/quininer/memsec),
republished as `secure-alloc` so it can evolve on its own release cadence. It provides:

- constant-time memory comparison (`memeq`, `memcmp`);
- volatile-ish memory fill and zeroing (`memset`, `memzero`);
- a cross-platform `mlock` / `munlock` wrapper (`mlock(2)` / `VirtualLock`), with
  `MADV_DONTDUMP` (Linux) or `MADV_NOCORE` (FreeBSD, DragonFly) applied on lock;
- guard-paged allocations with a random canary checked on free
  (`malloc`, `malloc_sized`, `free`, `mprotect`, `Prot`);
- Linux-only allocations backed by `memfd_secret` (`memfd_secret`,
  `memfd_secret_sized`, `free_memfd_secret`).

The crate is `#![no_std]`. The `alloc` feature is what pulls in `std` (for the global
allocator) and `getrandom` (for the canary); with `--no-default-features` only the four
free-standing memory helpers remain, with no dependencies at all.

```toml
[dependencies]
secure-alloc = "0.7.0"
```

## Provenance

- Forked from [`quininer/memsec`](https://github.com/quininer/memsec) by quininer kel.
- Based on the published `memsec` 0.7.0 release, at upstream master commit
  `b4de7b9a` (2025-01-21). Compared with that commit the code carries only the
  changes listed under [Changes from upstream](#changes-from-upstream); the four
  `#[allow(static_mut_refs)]` attributes in it are upstream's, added after 0.7.0
  was published. `LICENSE` is copied verbatim.
- Upstream has been unmaintained since that release. This fork keeps the source
  close to upstream, so upstream fixes can still be carried over.
- Licensed MIT, the same as upstream (see [LICENSE](https://github.com/greekfetacheese/secure-types/blob/master/crates/secure-alloc/LICENSE)).

## Changes from upstream

Deliberately few; anything not listed here is upstream 0.7.0 code.

- `src/lib.rs` — `#![doc = include_str!("../README.md")]`, so this README is the
  crate front page and its examples are doctests.
- `src/alloc/mod.rs`, `src/alloc/allocext/linux.rs` — `::core::usize::MAX` is
  written `usize::MAX`. Identical value; the deprecated spelling is gone.
- `src/alloc/mod.rs` — the canary is filled with `getrandom::fill`, the 0.3+
  spelling of `getrandom()`, because the dependency moved to `getrandom` 0.4.
- `Cargo.toml` — `getrandom` 0.4 and `windows-sys` 0.61 (were 0.2 and 0.45), and
  docs.rs builds with `alloc_ext` instead of `--all-features`.
- `src/lib.rs`, `src/mlock.rs`, `src/alloc/mod.rs`, `src/alloc/allocext/linux.rs` —
  every public `unsafe fn` documents its contract in a `# Safety` section, and the
  crate-wide `#![allow(clippy::missing_safety_doc)]` is gone. Documentation only.
- `src/alloc/allocext/linux.rs` — the `memfd_secret` backing descriptor is opened
  close-on-exec (`MFD_CLOEXEC`, falling back to `fcntl` on kernels that reject the
  flag), and it is closed rather than leaked when `ftruncate` or `mmap` fails.
  Upstream: [memsec#22](https://github.com/quininer/memsec/issues/22).
- `tests/memfd_secret_cloexec.rs` — new; regression test for the descriptor above.

## API

All functions are `unsafe` unless noted. "Gate" is the cargo feature (or platform)
the item is compiled under.

### Memory comparison — no feature gate

| Item | Signature | Notes |
| --- | --- | --- |
| `memeq` | `unsafe fn memeq(b1: *const u8, b2: *const u8, len: usize) -> bool` | Reads both buffers with `read_volatile` and folds every byte into one accumulator, so the loop does not exit early. `#[inline(never)]`. |
| `memcmp` | `unsafe fn memcmp(b1: *const u8, b2: *const u8, len: usize) -> i32` | Same shape; returns the usual `<0` / `0` / `>0` ordering without an early return. |

### Memory fill and zeroing — no feature gate

| Item | Signature | Notes |
| --- | --- | --- |
| `memset` | `unsafe fn memset(s: *mut u8, c: u8, n: usize)` | Byte-at-a-time fill. With the `nightly` feature it calls `core::intrinsics::volatile_set_memory` instead. |
| `memzero` | `unsafe fn memzero(dest: *mut u8, n: usize)` | `memset(dest, 0, n)`. |

```rust
use secure_alloc::{memeq, memset};

let mut a = [0u8; 32];
let mut b = [0u8; 32];

unsafe {
    memset(a.as_mut_ptr(), 0x42, a.len());
    memset(b.as_mut_ptr(), 0x42, b.len());

    assert!(memeq(a.as_ptr(), b.as_ptr(), a.len()));

    b[31] = 0;
    assert!(!memeq(a.as_ptr(), b.as_ptr(), a.len()));
}
```

### Locking — gate `use_os` (on by default)

| Item | Signature | Notes |
| --- | --- | --- |
| `mlock` | `unsafe fn mlock(addr: *mut u8, len: usize) -> bool` | Unix: `mlock(2)`, plus `madvise(MADV_DONTDUMP)` on Linux or `MADV_NOCORE` on FreeBSD/DragonFly. Windows: `VirtualLock`. |
| `munlock` | `unsafe fn munlock(addr: *mut u8, len: usize) -> bool` | Zeroes the range first, then unlocks and reverses the core-dump exclusion (`MADV_DODUMP` / `MADV_CORE` / `VirtualUnlock`). |

### Guard-paged allocation — gate `alloc` (on by default; pulls in `getrandom`)

| Item | Signature | Notes |
| --- | --- | --- |
| `malloc` | `unsafe fn malloc<T>() -> Option<NonNull<T>>` | Allocates one `T`, fills it with `0xd0`, returns `None` on allocation failure. |
| `malloc_sized` | `unsafe fn malloc_sized(size: usize) -> Option<NonNull<[u8]>>` | Same for a byte slice of `size` bytes. |
| `free` | `unsafe fn free<T: ?Sized>(memptr: NonNull<T>)` | Checks the canary, restores read/write protection, zeroes through `munlock`, and releases the mapping. Accepts the pointer from `malloc` or `malloc_sized`. |
| `mprotect` | `unsafe fn mprotect<T: ?Sized>(memptr: NonNull<T>, prot: Prot::Ty) -> bool` | Re-protects the whole allocation's data region. |
| `Prot` | module of constants | Unix: `NoAccess`, `ReadOnly`, `WriteOnly`, `ReadWrite`, `Execute`, `ReadExec`, `WriteExec`, `ReadWriteExec` (raw `libc::c_int`). Windows: `NoAccess`, `ReadOnly`, `ReadWrite`, `WriteCopy`, `Execute`, `ReadExec`, `ReadWriteExec`, `WriteCopyExec`, `Guard`, `NoCache`, `WriteCombine`, and the `PAGE_TARGETS_*` flags (`PAGE_PROTECTION_FLAGS`). |

```rust
use secure_alloc::{free, malloc};

unsafe {
    let mem = malloc::<[u8; 32]>().expect("allocation failed");

    for i in 0..32 {
        mem.as_ptr().cast::<u8>().add(i).write(0x11);
    }

    free(mem);
}
```

### Linux `memfd_secret` allocation — gates `alloc_ext` **and** `target_os = "linux"`

```text
memfd_secret::<T>()                  -> Option<NonNull<T>>
memfd_secret_sized(size: usize)      -> Option<NonNull<[u8]>>
free_memfd_secret(memptr: NonNull<T>)
```

These are backed by file descriptors from `memfd_secret(2)` (Linux 5.14+, and the
kernel must not be booted with `secretmem_enable=off`) and are unmapped with `munmap`
plus `close` on free. They are only compiled on Linux: on any other target the
`alloc_ext` feature adds nothing.

## Feature flags

| Feature | Default | Effect |
| --- | --- | --- |
| `use_os` | yes | Enables `mlock` / `munlock`; pulls in `libc` on Unix and `windows-sys` on Windows. |
| `alloc` | yes | Enables `malloc`, `malloc_sized`, `free`, `mprotect`, `Prot`; implies `use_os` and adds the optional `getrandom` dependency. |
| `alloc_ext` | no | Implies `alloc`; adds the `memfd_secret` family on Linux only. |
| `nightly` | no | Uses `core::intrinsics::volatile_set_memory` in `memset`; requires a nightly compiler. |
| `default` | `["use_os", "alloc"]` | |

`--no-default-features` builds a dependency-free `no_std` crate with only
`memeq`, `memcmp`, `memset` and `memzero`.

## Security notes

- **Layout.** An allocation is four page-aligned regions: a read-only metadata page
  holding the allocation's data-region length, an `PROT_NONE` guard page, the data
  region (page-rounded, `mlock`ed, filled with `0xd0` for `malloc`/`malloc_sized`),
  and a trailing `PROT_NONE` guard page. The 16-byte canary sits at the very end of
  the data region, immediately below the returned pointer, and the caller's bytes run
  to the page boundary; an overrun therefore faults on the trailing guard page instead
  of silently corrupting adjacent memory, and an underrun hits the canary.
- **Canary.** The canary is `getrandom` bytes, generated once per process on the first
  allocation (`Once`). `free` and `free_memfd_secret` compare it with the constant-time
  `memeq` and call `abort()` on a mismatch; a pointer whose page-aligned base is not a
  plausible allocation also aborts. A corrupted or foreign pointer therefore kills the
  process, it does not return an error.
- **`mlock` failure is ignored.** `malloc`/`malloc_sized` call `mlock` and discard its
  return value: the allocation succeeds even when the page could not be locked (for
  example when `RLIMIT_MEMLOCK` is exhausted). Call `mlock` yourself, or check
  `/proc/self/status`'s `VmLck`, if the guarantee matters. The `memfd_secret` path
  does not lock memory at all — `secretmem` pages are already unswappable.
- **Zeroization happens in `munlock`.** `free` never zeroes the buffer itself; it
  delegates to `munlock`, which `memzero`s the whole data region before unlocking.
  On stable Rust `memset` protects against dead-store elimination only by re-reading
  its arguments and the destination pointer with `read_volatile`; the stores
  themselves are ordinary writes. `nightly` swaps in the real
  `volatile_set_memory`.
- **`nightly` needs a nightly compiler.** It enables `core_intrinsics` and will fail to
  build on stable.
- **`alloc` pulls in `getrandom`.** With the default features the dependency tree gains
  `getrandom` (and through it `cfg-if` / `libc`); `--no-default-features` has none.
- **Comparison cost is independent of the compared bytes, not of the length**, and
  `memeq`/`memcmp` do not protect against every microarchitectural side channel
  (page faults, speculation) — they only remove the data-dependent early exit.
- **`mprotect` is a sharp tool.** Dropping `Prot::NoAccess` on a live allocation and
  touching it faults the process; the protection is restored before the memory is
  released, so a misuse is not recoverable.
- **The `memfd_secret` descriptor is close-on-exec, but not fork-safe.** A child
  started with `exec` does not inherit the backing descriptor; a `fork` child still
  does, although it already shares the mapping, so `fork` is not a containment
  boundary for these allocations.

## License

MIT — see [LICENSE](https://github.com/greekfetacheese/secure-types/blob/master/crates/secure-alloc/LICENSE). The license text is upstream's, copied verbatim
from `quininer/memsec` 0.7.0 (see [Provenance](#provenance)); the MIT copyright
notice is "Copyright (c) 2016 quininer@live.com".
