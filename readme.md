# Secure Types

The goal of this crate is to provide a simple way to properly handle sensitive data in memory (eg. passwords, private keys, etc).

Currently there are 3 types:

- `SecureString`: For working with strings.
- `SecureVec`: For working with `Vec<T>`.
- `SecureArray`: For working with `&[T; LENGTH]`.

## Features

- **Zeroization on Drop**: Memory is wiped when dropped.
- **Memory Locking**: (OS-only) On Linux/Windows the memory is locked to prevent memory swapping or unauthorized access.
- **Safe Scoped Access**: Direct access on these types is not possible, data is protected by default and only accessible within safe blocks.
- **`no_std` Support**: For embedded and Web environments (with zeroization only).
- **Serde Support**: Optional serialization/deserialization.

## How memory is locked

- **Windows**: Using [VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect) & [VirtualLock](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock).

- **Linux**: Using [mlock](https://man.archlinux.org/man/mlock.2) & [madvise](https://man.archlinux.org/man/madvise.2)
If the kernel supports it, it will allocate with [memfd_secret](https://man.archlinux.org/man/memfd_secret.2.en)

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
- `no_os`: For `no_std` environments. Only provides the Zeroize on Drop.
- `serde`: Enables serialization/deserialization.


## Credits
- [zeroize](https://github.com/RustCrypto/utils/tree/master/zeroize)
- [memsec](https://github.com/quininer/memsec)