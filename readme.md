## Secure Types

This crate provides types to handle sensitive data more securely.

## Types

### SecureVec

Similar to `Vec` from the standard library, but with additional security features.
- [Zeroizes](https://github.com/RustCrypto/utils/tree/master/zeroize) its contents when it is dropped
- Allocated memory is protected using `VirtualLock` & `VirtualProtect` on Windows and `mlock` & `mprotect` on Unix.
- Uses `CryptProtectMemory` & `CryptUnprotectMemory` on Windows to encrypt/decrypt the memory
- Does not leave copies of the data on the heap during reallocation

### SecureString

Similar to `String` from the standard library. It is a wrapper around `SecureVec<u8>` so it has the same security features.

These types are not perfect and still need work but the chances of of leaking data through one of the below reasons are greatly reduced:
- Disk swaps (eg. due to insufficient RAM)
- Reads/writes by other processes (eg. malware)
- Core dumps

## Usage

### SecureString
```rust
use secure_types::SecureString;

// obviously this is an example, do not hardcode any important data
let secret_string = SecureString::from("My sensitive data");

// access the secure_string as a &str
secret_string.str_scope(|str| {
   assert_eq!(str, "My sensitive data");
});
```

### SecureVec
```rust
use secure_types::SecureVec;

let secret_vec = SecureVec::from(vec![1, 2, 3, 4, 5]);

// access the secure_vec as a &[u8]
secret_vec.slice_scope(|slice| {
   assert_eq!(slice, [1, 2, 3, 4, 5]);
});

```


### Feature Flags
- `serde`: Enables serialization and deserialization of `SecureString` and `SecureVec<u8>`


## Credits
[zeroize](https://github.com/RustCrypto/utils/tree/master/zeroize)

[secure-string](https://github.com/ISibboI/secure-string)

[memsec](https://github.com/quininer/memsec)