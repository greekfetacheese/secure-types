# secure-alloc

Secure memory allocation, locking and zeroing for Rust, in `no_std` apart from the
default `alloc` feature's global allocator.

This crate is a fork of [quininer/memsec](https://github.com/quininer/memsec),
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

## License

MIT