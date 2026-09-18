# Secure Types

The goal of this crate is to provide a simple way to properly handle sensitive data in memory (eg. passwords, private keys, etc).

Currently there are 3 types:

- `SecureString`: For working with strings.
- `SecureVec`: For working with `Vec<T>`.
- `SecureArray`: For working with `&[T; LENGTH]`.

## Features

- **Zeroization on Drop**: Memory is wiped when dropped.
- **Memory Locking**: (OS-only) The allocation is `mlock`ed (Windows: `VirtualLock`) and excluded from core dumps (`MADV_DONTDUMP`), so it cannot be swapped out or captured in a crash dump. While no `unlock*` scope is active the pages are also `mprotect`ed `PROT_NONE`, which is what keeps the contents away from other processes. On Linux the allocation is backed by `memfd_secret` when the kernel supports it.
- **Safe Scoped Access**: Direct access on these types is not possible, data is protected by default and only accessible within safe blocks.
- **Send, not Sync**: Values can be moved to another thread. Sharing one instance across threads requires an explicit lock (`Arc<Mutex<_>>`). Concurrent `unlock` would race on page protection.
- **`no_std` Support**: For embedded and Web environments (with zeroization only). Select it by turning off the default features — see [Feature Flags](#feature-flags).
- **Serde Support**: Optional serialization/deserialization for `SecureString`, `SecureVec<u8> ` and `SecureArray<u8, LENGTH>`.

## How memory is locked

- **Windows**: Using [VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect) & [VirtualLock](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock).

- **Linux**: Using [mlock](https://man.archlinux.org/man/mlock.2) & [madvise](https://man.archlinux.org/man/madvise.2).
  If the kernel supports it, it will allocate with [memfd_secret](https://man.archlinux.org/man/memfd_secret.2.en).

Locking is best-effort in one respect: `memsec` discards the return value of `mlock`, so
exhausting `RLIMIT_MEMLOCK` does not fail construction — the allocation is still
`mprotect`ed. The constructors return `Error::LockFailed` when that `mprotect` fails, and a
failed re-lock after an `unlock*` scope panics in every profile rather than silently
leaving the memory readable.

## Usage

### SecureString

```rust
use secure_types::SecureString;

 // Create a SecureString
let mut secret = SecureString::from("my_super_secret");

// The memory is locked here

// Safely append more data.
secret.push_str("_password");

// The memory is locked here.

// Use a scope to safely access the content as a &str.
secret.unlock_str(|exposed_str| {
     assert_eq!(exposed_str, "my_super_secret_password");
 });

 // When `secret` is dropped, its data zeroized.
```

### SecureVec

```rust
use secure_types::SecureVec;

// Create a new, empty secure vector.
let mut secret_key: SecureVec<u8> = SecureVec::new().unwrap();

// Push some sensitive data into it.
secret_key.push(0);
secret_key.push(1);
secret_key.push(2);

// The memory is locked here.

// Use a scope to safely access the contents as a slice.
secret_key.unlock_slice(|unlocked_slice| {
     assert_eq!(unlocked_slice, &[0, 1, 2]);
 });
```

### SecureArray

```rust
use secure_types::SecureArray;

let exposed_array: &mut [u8; 3] = &mut [1, 2, 3];
let mut secure_array = SecureArray::from_slice_mut(exposed_array).unwrap();


secure_array.unlock_mut(|unlocked_slice| {
    assert_eq!(unlocked_slice, &[1, 2, 3]);
});
```


## See also the [examples](/examples/).


## Feature Flags

- `use_os` (default): Enables all OS-level security features.
- `no_os`: No-op, kept for backwards compatibility. `no_std` is selected by disabling the default features (`--no-default-features`), which leaves only the zeroize-on-drop guarantee.
- `serde`: Enables serialization/deserialization.
- `expose-ptr`: For testing purposes. Exposes the locked memory region pointer.

## Security notes

- **Serialization writes plaintext.** `Serialize` hands the contents straight to the
  serializer, which builds an ordinary, unprotected buffer (`serde_json::to_string`
  returns a plain `String`). Zeroize that buffer as soon as you are done with it.
- **Leaking a `Drain` still skips drops.** `SecureVec::drain` unlocks the memory only while
  an item is read and while the iterator compacts the vector, so a `core::mem::forget`ped
  iterator leaves the memory locked but the elements left in the drained range are never
  dropped or zeroized, and the length stays at the drain start. Consume or drop the iterator.
- **`clear()` does not wipe.** `SecureVec::clear` only sets the length to zero the bytes
  are still there. Use `erase()` to zeroize the contents.
- **`SecureArray::empty()` has a strict contract.** Only the elements that were actually
  written are tracked as initialized, so dropping a partially-filled array never reads the
  unwritten slots. Those slots are not valid `T`s though: fill the whole array (for example
  via `unlock_mut`) before reading it.

## Running tests

```bash
cargo test --features serde,expose-ptr
```

## License
Licensed under the [MIT license](LICENSE-MIT).


## Credits
- [zeroize](https://github.com/RustCrypto/utils/tree/master/zeroize)
- [memsec](https://github.com/quininer/memsec)