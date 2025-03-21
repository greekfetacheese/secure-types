# This is a fork of [secure-string](https://github.com/ISibboI/secure-string) with some slight adjustments

## Features
- Types that [zeroize](https://github.com/RustCrypto/utils/tree/master/zeroize) its contents when it is dropped
- Masks the contents when it is displayed or debugged
- For `Windows` calls `VirtualLock` to protect the contents from being swapped out to disk
- For `Unix` calls `mlock` to prevent the contents from being swapped to disk and memory dumped

### Note on `Windows` is not possible to prevent memory dumping

### This crate does not guarantee that any data is completely erased from memory

## Usage

### SecureString
```rust
use secure_types::SecureString;

let secret_string = SecureString::from("My sensitive data");
let borrowed_string = secret_string.borrow();
assert_eq!(borrowed_string, "My sensitive data");
```

### SecureVec
```rust
use secure_types::{SecureVec, SecureBytes};

let secret_vec = SecureVec::from(vec![1, 2, 3, 4, 5]);
let borrowed_vec = secret_vec.borrow();
assert_eq!(borrowed_vec, [1, 2, 3, 4, 5]);

// there is also a SecureBytes type alias for convenience
let secret_bytes = SecureBytes::from(vec![1, 2, 3, 4, 5]);
let borrowed_bytes = secret_bytes.borrow();
assert_eq!(borrowed_bytes, [1, 2, 3, 4, 5]);
```

### SecureArray
```rust
use secure_types::SecureArray;

let secret_array = SecureArray::from([1, 2, 3, 4, 5]);
let borrowed_array = secret_array.borrow();
assert_eq!(borrowed_array, [1, 2, 3, 4, 5]);
```

### Feature Flags
- `serde`: Enables serialization and deserialization of `SecureString` and `SecureVec`
- `egui`: Allows the direct usage of `SecureString` for `egui` text editing, see [egui-test](src/bin/egui_test.rs) for an example


## Credits
[secure-string](https://github.com/ISibboI/secure-string)

[memsec](https://github.com/quininer/memsec)