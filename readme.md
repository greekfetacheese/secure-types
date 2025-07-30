# Secure Types

This crate provides data structures (`SecureVec`, `SecureArray`, `SecureString`) designed to handle sensitive information in memory with enhanced security.

The goal is to protect secret data (like passwords, private keys, or credentials) from being exposed through common vulnerabilities.

## Key Features

- **Zeroization on Drop**: Memory is wiped when dropped.
- **Memory Locking**: (std-only) OS-level protection against being swapped to disk.
- **Memory Encryption**: (Windows-only) `CryptProtectMemory` for in-memory encryption.
- **Scoped Access**: Data is protected by default and only accessible within safe blocks.
- **`no_std` Support**: For embedded and Web environments (with zeroization only).
- **Serde Support**: Optional serialization/deserialization.

## Usage

```rust
use secure_types::SecureString;

// Create a string from a sensitive literal.
let mut secret = SecureString::from("my_super_secret_password");

// Use a scope to safely access the content as a &str.
secret.str_scope(|unlocked_str| {
    assert_eq!(unlocked_str, "my_super_secret_password");
});
```

For a `SecureVec`:

```rust
use secure_types::SecureVec;

let secret_vec = SecureVec::from_vec(vec![1, 2, 3]).unwrap();

secret_vec.slice_scope(|slice| {
   assert_eq!(slice, &[1, 2, 3]);
});
```

## Security Model

This crate is designed to mitigate certain risks but is not a perfect solution. It primarily protects secrets in program memory against:

- **Disk Swapping**: The OS writing secrets to a page file.
- **Malicious Memory Reads**: Malware that can steal data by reading a process's memory.
- **Process Memory Dumps**: Data being exposed in a core dump.

It **does not** protect against an attacker who can directly read your programs's memory (e.g., via admin rights or a kernel-level exploit, especially on Unix where we dont encrypt the memory, On Windows this shouldn't be an issue since the memory is first encrypted and then locked).

## Feature Flags

- `std` (default): Enables all OS-level security features.
- `no_std`: For `no_std` environments. Only provides the Zeroize on Drop guarantee.
- `serde`: Enables serialization/deserialization for `SecureString` and `SecureBytes`.


## Credits
- [zeroize](https://github.com/RustCrypto/utils/tree/master/zeroize)
- [memsec](https://github.com/quininer/memsec)