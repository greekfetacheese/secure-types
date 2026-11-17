# secure-alloc

Secure memory allocation, locking and zeroing for Rust, in `no_std` apart from the
default `alloc` feature's global allocator.

This crate is a vendored fork of [quininer/memsec](https://github.com/quininer/memsec),
republished as `secure-alloc` so it can evolve on its own release cadence. It provides:

- constant-time memory comparison (`memeq`, `memcmp`);
- volatile-ish memory fill and zeroing (`memset`, `memzero`);
- a cross-platform `mlock` / `munlock` wrapper (`mlock(2)` / `VirtualLock`), with
  `MADV_DONTDUMP` (Linux) or `MADV_NOCORE` (FreeBSD, DragonFly) applied on lock;
- guard-paged allocations with an allocator tag and a random canary checked on
  free (`malloc`, `malloc_sized`, `free`, `mprotect`, `Prot`);
- Linux-only allocations backed by `memfd_secret` (`memfd_secret`,
  `memfd_secret_sized`, `free_memfd_secret`).

The crate carries `#![no_std]`; the default `alloc` feature is what pulls in `std` (for
the global allocator) and `getrandom` (for the canary). With `--no-default-features`
only the four free-standing memory helpers remain, with no dependencies at all.

```toml
[dependencies]
secure-alloc = "0.7.0"
```

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
| `munlock` | `unsafe fn munlock(addr: *mut u8, len: usize) -> bool` | Zeroes the range first, then unlocks; on Unix it also reverses the core-dump exclusion (`MADV_DODUMP` / `MADV_CORE`). Windows uses `VirtualUnlock`. |

### Guard-paged allocation — gate `alloc` (on by default; pulls in `getrandom`)

| Item | Signature | Notes |
| --- | --- | --- |
| `malloc` | `unsafe fn malloc<T>() -> Option<NonNull<T>>` | Allocates one `T`, fills it with `0xd0`, returns `None` on allocation failure. |
| `malloc_sized` | `unsafe fn malloc_sized(size: usize) -> Option<NonNull<[u8]>>` | Same for a byte slice of `size` bytes. |
| `free` | `unsafe fn free<T: ?Sized>(memptr: NonNull<T>)` | Checks the allocator tag, restores read/write protection, checks the canary, zeroes through `munlock`, and releases the allocation (`dealloc`; the block returns to the global allocator, which decides whether the pages go back to the OS). Accepts the pointer from `malloc` or `malloc_sized`; a pointer from `free_memfd_secret` aborts on the tag. |
| `mprotect` | `unsafe fn mprotect<T: ?Sized>(memptr: NonNull<T>, prot: Prot::Ty) -> bool` | Re-protects the whole allocation's data region. Aborts unless the metadata page carries an allocator tag: it is checked before the length is read, and both `malloc` and `memfd_secret` allocations are accepted. |
| `page_size` | `fn page_size() -> usize` | Safe, but the first call can panic while initialising (see [Security notes](#security-notes)). The page size the regions above are laid out with: guard-page and `mprotect` granularity, and the unit the data region is rounded up to. It is not a guarantee of the returned pointer's alignment (see *Layout* under [Security notes](#security-notes)). |
| `Prot` | module of constants | Unix: `NoAccess`, `ReadOnly`, `WriteOnly`, `ReadWrite`, `Execute`, `ReadExec`, `WriteExec`, `ReadWriteExec` (raw `libc::c_int`). Windows: `NoAccess`, `ReadOnly`, `ReadWrite`, `WriteCopy`, `Execute`, `ReadExec`, `ReadWriteExec`, `WriteCopyExec`, `Guard`, `NoCache`, `WriteCombine`, `RevertToFileMap`, and the `PAGE_TARGETS_*` flags; the constants have the type `PAGE_PROTECTION_FLAGS`. |

```rust
# #[cfg(feature = "alloc")]
# {
use secure_alloc::{free, malloc};

unsafe {
    let mem = malloc::<[u8; 32]>().expect("allocation failed");

    for i in 0..32 {
        mem.as_ptr().cast::<u8>().add(i).write(0x11);
    }

    free(mem);
}
# }
```

### Linux `memfd_secret` allocation — gates `alloc_ext` **and** `target_os = "linux"`

```text
memfd_secret::<T>()                  -> Option<NonNull<T>>
memfd_secret_sized(size: usize)      -> Option<NonNull<[u8]>>
free_memfd_secret(memptr: NonNull<T>)
```

These are backed by file descriptors from `memfd_secret(2)` (Linux 5.14+, and the
kernel must not be booted with `secretmem_enable=off`) and are unmapped with `munmap`
plus `close` on free. `free_memfd_secret` checks the allocator tag before it reads the
descriptor, so a `malloc`/`malloc_sized` pointer aborts instead of closing an
unrelated descriptor. They are only compiled on Linux: on any other target the
`alloc_ext` feature adds nothing.

`memfd_secret_sized(size)` fills the region with `0xd0` as part of the allocation, and a
`secretmem` page is only backed when it is first touched. A `size` larger than the pages
the system can commit therefore dies with `SIGBUS` inside that fill instead of returning
`None`; bound the request before calling it. (The `malloc` path allocates real memory
first, so its fill cannot run out from under it.)

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
  region (page-rounded, `mlock`ed and dump-excluded on the `malloc` path; the
  caller's `size` bytes are filled with `0xd0` by `malloc`/`malloc_sized`, while the
  canary and the slack below it are not), and a trailing `PROT_NONE` guard page. The
  16-byte canary sits immediately below the returned pointer, and the caller's bytes
  run from there to the end of the data region; an overrun therefore faults on the
  trailing guard page instead of silently corrupting adjacent memory. An underrun
  reaches the canary only for its first 16 bytes: below the canary the region has up to
  a page of writable slack, so a deeper underrun passes the canary undetected until it
  leaves the region. The regions are page-aligned, but the **returned pointer is not necessarily**:
  it sits `size` bytes below the end of the data region, so only a page-multiple
  `size` lands on a page boundary. `malloc::<T>` is aligned for `T` while
  `align_of::<T>() <= page_size()`, because its size is `size_of::<T>()`, a multiple of
  `align_of::<T>()` — and the offset above is a multiple of the alignment only when the
  alignment divides the page. An over-aligned `T` is still page-aligned (its size is
  a page multiple) but not promised its own alignment, so `malloc_sized`'s result
  carries no alignment guarantee beyond a byte buffer's, and a strengthened `T`
  carries no guarantee of `T`'s alignment. A zero-byte allocation (`malloc_sized(0)`,
  `memfd_secret_sized(0)`, a zero-sized `T`) places the returned pointer one byte past
  the data region, at the start of the trailing guard page: it is a valid zero-length
  pointer, `free`/`mprotect` accept it, and nothing may be read or written through it.
- **Canary and allocator tag.** The metadata page holds the data-region length at
  offset 0 and, next to it, an allocator tag: `MALL` for `malloc`/`malloc_sized`, and
  `MFDS` one `usize` further along for `memfd_secret` (that slot holds its descriptor).
  A `malloc` header's spare tag slot is written with a defined non-`MFDS` value, so
  neither check ever reads uninitialised metadata. `free`, `free_memfd_secret` and
  `mprotect` check the tag first and `abort()` on a mismatch, so a pointer released
  through the wrong allocator never reaches `dealloc`, `munmap` or `close`; `mprotect`
  accepts either tag. The canary is `getrandom` bytes, generated once per process on
  the first allocation (`Once`). `free` and `free_memfd_secret` compare it with the
  constant-time `memeq` and call `abort()` on a mismatch; a pointer whose page-aligned
  base is not a plausible allocation also aborts. A corrupted or foreign pointer
  therefore kills the process, it does not return an error. A protection change the
  allocator cannot make follows the channel the call already has: the allocation paths
  give the region back and return `None`, because a failure there is recoverable —
  `mprotect` answers `ENOMEM` when the change would split the region past
  `vm.max_map_count` — while `free` and `free_memfd_secret` abort, because they return
  no error and the restore is a precondition for the canary check and the zeroization
  that follow. A region that cannot even be restored to `ReadWrite` is abandoned instead
  of handed back to the global allocator, which may write into a freed block.
- **`page_size` can panic while initialising.** The first call runs `alloc_init`: it panics
  if `sysconf` fails or reports a page size too small for the region layout (or, in debug
  builds, one that is not a power of two — a `debug_assert!` no supported target trips),
  and `getrandom`'s failure is unwrapped; the failed `Once` is poisoned, so every later
  call (and every allocation) panics too.
- **`mlock` failure is ignored.** `malloc`/`malloc_sized` call `mlock` and discard its
  return value: the allocation succeeds even when the page could not be locked (for
  example when `RLIMIT_MEMLOCK` is exhausted). Call `mlock` yourself, or check
  `/proc/self/status`'s `VmLck`, if the guarantee matters. The `memfd_secret` path
  does not lock memory at all — `secretmem` pages are already unswappable.
  The dump exclusion (`MADV_DONTDUMP` / `MADV_NOCORE`) is best-effort as well: it
  is applied to the page-aligned range covering the caller's bytes, and a failure
  is not reported.
- **Zeroization happens in `munlock`.** On the success path `free` does not zero the buffer
  itself; it delegates to `munlock`, which `memzero`s the whole data region before unlocking.
  The canary-mismatch path is the exception: it `memzero`s the data region too, before
  aborting, so the plaintext does not outlive the process.
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

## Provenance

Forked from [quininer/memsec](https://github.com/quininer/memsec) by quininer kel. The base is
upstream master commit `b4de7b9a` (2025-01-21), the lint commit immediately after the published
`memsec` 0.7.0 release, which was cut from `7fae500` (2024-06-06).
`LICENSE` is copied verbatim; the four `#[allow(static_mut_refs)]` attributes this fork
still carries are upstream's, added after 0.7.0 was published. (Upstream master has five:
the one on the `getrandom` call in `alloc_init` went away when that call stopped borrowing
the static.) Upstream has been unmaintained since that release. This fork keeps the source close to upstream, so upstream fixes can still be
carried over. The layout is upstream's; the only public API this fork adds is `page_size`.

## Changes from upstream

Deliberately few; anything not listed here is upstream 0.7.0 code. These deviations are
deliberate and have to survive any future sync:

- every allocation carries an allocator tag in the metadata page (`MALL` / `MFDS`, with a
  defined spare slot so neither check reads uninitialised metadata), and `free`,
  `free_memfd_secret` and `mprotect` abort on a mismatch before they trust the length —
  upstream aborts on the canary only;
- the region total is computed with checked arithmetic and an `isize::MAX` ceiling, so a
  size near `usize::MAX` is an allocation failure instead of a wrapped layout;
- the free paths check the total they derive from the metadata page too, and abort with a
  diagnostic when the data-region length cannot produce one, instead of `mprotect`ing a
  short range, reading the canary through a page it did not restore, and `dealloc`ing a
  layout the allocation never had. Only the overflow is caught: a corrupted length that
  is merely *shorter* or *longer* than the real one is still trusted, because that page
  is read-only for the life of the allocation and closing it needs a value `free` can
  verify rather than re-derive from the length itself. A longer length is the sharper
  direction: `free` then zeroes past the end of the data region and hands `dealloc` a
  layout the allocation never had. Reaching either needs a writer that first re-protects
  the metadata page, which is outside this crate's contract;
- `alloc_init` validates the page size and generates the canary before it publishes
  `PAGE_SIZE`, `PAGE_MASK` and `CANARY`, so an init that panics leaves every static
  untouched instead of a page size that failed validation, a mask of 0 and an all-zero
  canary that would make every comparison pass;
- every `mprotect` result is checked. A guard page, the read-only metadata page or the
  restore before `munlock`/`munmap` that the platform rejects is an allocation failure
  (`None`) on the allocation paths and fatal on the free paths; upstream discards every
  result and carries on with the old protection. The page size is validated the same way:
  a failed `sysconf` panics instead of becoming `usize::MAX`, and the floor covers the
  metadata header rather than one word;
- a region whose metadata page is rejected after the data region was already locked is
  `munlock`ed before it is released, so the pages do not stay locked and dump-excluded
  inside the global allocator's heap;
- the canary is checked *after* the data region is restored to `ReadWrite` in `free` and
  `free_memfd_secret`, so an allocation the caller left protected is freeable; upstream
  checks it first and faults (SIGSEGV) instead;
- a canary mismatch wipes the data region before it aborts, so the plaintext does not
  outlive the process; upstream aborts with the region still readable;
- `src/lib.rs` — `#![doc = include_str!("../README.md")]`, so this README is the crate
  front page and its examples are doctests;
- `src/alloc/mod.rs`, `src/alloc/allocext/linux.rs` — the `::core::usize::MAX` size
  guards are gone with the checked arithmetic above (`usize::MAX` survives only in the
  tests and comments), the canary uses `getrandom::fill` (the 0.4 spelling), both
  allocation functions return their slice through `core::ptr::slice_from_raw_parts_mut`
  instead of building a reference to it with `core::slice::from_raw_parts_mut`, and
  `alloc_init` carries a `debug_assert!` that the page size is a power of two;
- `Cargo.toml` — `getrandom` 0.4 and `windows-sys` 0.61 (were 0.2 and 0.45), and docs.rs
  builds with `alloc_ext` instead of `--all-features`;
- `src/lib.rs`, `src/mlock.rs`, `src/alloc/mod.rs`, `src/alloc/allocext/linux.rs` —
  every public `unsafe fn` documents its contract in a `# Safety` section, and the
  crate-wide `#![allow(clippy::missing_safety_doc)]` is gone (documentation only);
- `memfd_secret` is created with `O_CLOEXEC`, which sets `FD_CLOEXEC` at creation;
  upstream created the descriptor with no flag at all, so every `exec` child inherited a
  handle to the secret memory (memsec#22). `memfd_create`'s `MFD_CLOEXEC` is a different
  value and this syscall rejects it with `EINVAL`, so a call that passed it would fall
  back to `memfd_secret(0)` followed by `fcntl(F_SETFD, FD_CLOEXEC)`, narrowing the
  window to those two calls; on the kernels this has been tried on the flagged call
  succeeds and the fallback is not reached. The descriptor is closed rather than leaked
  when `ftruncate` or `mmap` fails. Upstream: memsec#22;
- `madvise` is given the page-aligned range covering the caller's bytes, so a direct
  `mlock`/`munlock` call on an unaligned range is not silently `EINVAL`ed, and the page
  size is read once with `sysconf` and cached in `src/mlock.rs`. Upstream: memsec#19.
  The cache is local to `mlock.rs`, so `use_os` still builds without `alloc`, as it did
  upstream;
- `page_size()` is public, and `mprotect` accepts either tag;
- `tests/memfd_secret_cloexec.rs`, `tests/mlock_dump_exclusion.rs`,
  `tests/mlock_release_leak.rs`, `tests/free_locked_allocation.rs`,
  `tests/wrong_free_aborts.rs`, `tests/protect_failure.rs`,
  `tests/free_corrupt_length_aborts.rs` and the header-tag unit tests are new regression
  tests for the deviations above; `protect_failure.rs` forces `mprotect` to fail with a
  seccomp filter and with a punched-out guard page; `free_corrupt_length_aborts.rs`
  overwrites a live allocation's data-region length and requires the free to abort;
  `mlock_release_leak.rs` rejects the metadata-page change and reads `VmLck` back; and
  `free_locked_allocation.rs` frees an allocation the caller left `NoAccess`.

## License

MIT