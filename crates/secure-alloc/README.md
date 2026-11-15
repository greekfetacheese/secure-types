# secure-alloc

Secure memory allocation, locking and zeroing for Rust, in `no_std`.

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

The crate is `#![no_std]`. The `alloc` feature is what pulls in `std` (for the global
allocator) and `getrandom` (for the canary); with `--no-default-features` only the four
free-standing memory helpers remain, with no dependencies at all.

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
| `munlock` | `unsafe fn munlock(addr: *mut u8, len: usize) -> bool` | Zeroes the range first, then unlocks and reverses the core-dump exclusion (`MADV_DODUMP` / `MADV_CORE` / `VirtualUnlock`). |

### Guard-paged allocation — gate `alloc` (on by default; pulls in `getrandom`)

| Item | Signature | Notes |
| --- | --- | --- |
| `malloc` | `unsafe fn malloc<T>() -> Option<NonNull<T>>` | Allocates one `T`, fills it with `0xd0`, returns `None` on allocation failure. |
| `malloc_sized` | `unsafe fn malloc_sized(size: usize) -> Option<NonNull<[u8]>>` | Same for a byte slice of `size` bytes. |
| `free` | `unsafe fn free<T: ?Sized>(memptr: NonNull<T>)` | Checks the allocator tag and the canary, restores read/write protection, zeroes through `munlock`, and releases the mapping. Accepts the pointer from `malloc` or `malloc_sized`; a pointer from `free_memfd_secret` aborts on the tag. |
| `mprotect` | `unsafe fn mprotect<T: ?Sized>(memptr: NonNull<T>, prot: Prot::Ty) -> bool` | Re-protects the whole allocation's data region. Aborts unless the metadata page carries an allocator tag: it is checked before the length is read, and both `malloc` and `memfd_secret` allocations are accepted. |
| `page_size` | `fn page_size() -> usize` | Safe. The page size the regions above are laid out with: guard-page and `mprotect` granularity, and the unit the data region is rounded up to. It is not the alignment of the returned pointer (see *Layout* under [Security notes](#security-notes)). The first call initialises the allocator's page size and canary. |
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
plus `close` on free. `free_memfd_secret` checks the allocator tag before it reads the
descriptor, so a `malloc`/`malloc_sized` pointer aborts instead of closing an
unrelated descriptor. They are only compiled on Linux: on any other target the
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
  and a trailing `PROT_NONE` guard page. The 16-byte canary sits immediately below
  the returned pointer, and the caller's bytes run from there to the end of the data
  region; an overrun therefore faults on the trailing guard page instead of silently
  corrupting adjacent memory, and an underrun hits the canary. The regions are
  page-aligned, but the **returned pointer is not**: it sits `size` bytes below the
  end of the data region, so only a page-multiple `size` lands on a page boundary.
  `malloc::<T>` is aligned for `T` for that reason (its size is `size_of::<T>()`, a
  multiple of `align_of::<T>()`); `malloc_sized`'s result carries no alignment
  guarantee beyond a byte buffer's.
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
  therefore kills the process, it does not return an error.
- **`mlock` failure is ignored.** `malloc`/`malloc_sized` call `mlock` and discard its
  return value: the allocation succeeds even when the page could not be locked (for
  example when `RLIMIT_MEMLOCK` is exhausted). Call `mlock` yourself, or check
  `/proc/self/status`'s `VmLck`, if the guarantee matters. The `memfd_secret` path
  does not lock memory at all — `secretmem` pages are already unswappable.
  The dump exclusion (`MADV_DONTDUMP` / `MADV_NOCORE`) is best-effort as well: it
  is applied to the page-aligned range covering the caller's bytes, and a failure
  is not reported.
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

MIT