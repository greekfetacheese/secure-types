# Secure Types

The goal of this crate is to provide a simple way to properly handle sensitive data in memory (e.g. passwords, private keys, etc).

Currently there are 3 types:

- `SecureString`: For working with strings.
- `SecureVec`: For working with `Vec<T>`.
- `SecureArray`: For working with `&[T; LENGTH]`.

## Features

- **Zeroization on Drop**: Memory is wiped when dropped.
- **Memory locking** (OS only): Pages are `mprotect`ed `PROT_NONE` except during an `unlock*` scope. That stops accidental reads, including from this process; it is not a defence against `ptrace` or a debugger. On the malloc path the allocation is also mlocked (Windows: `VirtualLock`) and, where the OS allows it, excluded from core dumps. Linux uses `memfd_secret` when the kernel supports it. See [How memory is locked](#how-memory-is-locked).
- **Scoped access**: No `Index`/`Deref` — `secret[0]` does not compile. Contents are only reachable through the `unlock*` closures (the `expose-ptr` testing feature aside). Memory is unprotected only for that closure.
- **Send, not Sync**: Values can move to another thread. Sharing one instance needs an explicit lock (`Arc<Mutex<_>>`); concurrent `unlock` races on page protection.
- **`no_std`**: Zeroization only. Disable the default features — see [Feature Flags](#feature-flags).
- **Serde**: Optional serialization for `SecureString`, `SecureVec<T>`, and `SecureArray<T, LENGTH>`. A `u8` container serializes as a byte buffer; other element types as a sequence (`SeqElement`).
- **Binary codec** (feature `codec`): A `serde` Serializer/Deserializer that encodes into locked memory and decodes out of it. No extra dependency beyond `serde`.

## How memory is locked

- **Windows**: [VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect) and [VirtualLock](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock).
- **Linux**: [memfd_secret](https://man.archlinux.org/man/memfd_secret.2.en) when the kernel supports it. Otherwise [mlock](https://man.archlinux.org/man/mlock.2) and [madvise](https://man.archlinux.org/man/madvise.2) (`MADV_DONTDUMP`) on the malloc path. A `memfd_secret` allocation is not `mlock`ed and is not marked `MADV_DONTDUMP` by `memsec`. Every path still uses `mprotect(PROT_NONE)` between unlocks.
- **Other Unix** (macOS, FreeBSD, …): [mlock](https://man.archlinux.org/man/mlock.2) plus `mprotect(PROT_NONE)`. FreeBSD/DragonFly also use `madvise(MADV_NOCORE)`. No `memfd_secret`.

`mlock` is best-effort: `memsec` ignores its return value, so hitting `RLIMIT_MEMLOCK` still constructs. `mprotect` failure is `Error::LockFailed`. A failed re-lock after an `unlock*` scope panics in every profile.

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

### Binary codec

The `codec` feature is a small binary `serde` format. Encode goes into locked memory; decode reads out of it. `#[derive(Serialize, Deserialize)]` and `#[serde(...)]` work as usual. No extra dependency beyond `serde`.

```rust
# #[cfg(feature = "codec")] {
use secure_types::{decode, encode, encode_into_vec};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct VaultData {
    label: String,

    #[serde(default)]
    wallet_state_key: Option<u32>,

    #[serde(default, skip_serializing)]
    contacts: Vec<String>,
}

let vault = VaultData {
    label: "main".to_owned(),
    wallet_state_key: Some(7),
    contacts: vec!["not persisted".to_owned()],
};

// The encoded document is the only copy, and it lives in locked memory that is
// zeroized on drop.
let encoded = encode(&vault)?;
let decoded = decode::<VaultData>(&encoded)?;

assert_eq!(decoded.wallet_state_key, Some(7));
assert!(decoded.contacts.is_empty()); // `skip_serializing` -> `default`

// When the caller is going to hold the document in a `Vec<u8>` anyway,
// `encode_into_vec` appends it straight into that buffer — a codec tag first,
// the document after it — so there is no `SecureBytes` to allocate and nothing
// copied twice. `encode_to_vec` is the same into a fresh buffer.
//
// That buffer is ordinary memory: not locked, and not wiped on drop.
let mut payload = vec![0x07];
encode_into_vec(&mut payload, &vault)?;
assert_eq!(payload[0], 0x07);
# }
# Ok::<(), Box<dyn std::error::Error>>(())
```

`encode` returns a `SecureBytes`. `encode_to_vec` / `encode_into_vec` produce the same document into a plain `Vec<u8>` the caller owns: not locked, and not zeroized on drop, but a *failed* encoding erases everything it appended rather than leaving a partial document behind. `decode` unlocks only for the parse and re-locks afterwards, including on error. Types are raw binary — a `SecureArray<u8, 32>` is 32 bytes — and strings are not escaped, so there is no scratch copy of an unescaped string.

**Format evolution.** `FORMAT_VERSION` is the first byte. An unknown version is refused. Adding a field with `#[serde(default)]` does not need a bump: fields are named and length-prefixed, so unknown fields are skipped and missing ones take their default. Changing a field's type does need a bump.

**Not supported.** No type tags, so `deserialize_any` is unimplemented. `#[serde(flatten)]`, `#[serde(untagged)]`, and `Value`-shaped fields fail with `DecodeError::Unsupported`. Untagged enums can still serialize; they cannot be read back.

## See also the [examples](/examples/).


## Feature Flags

- `use_os` (default): Enables all OS-level security features. Supported on Linux, Windows, and other Unix (macOS, FreeBSD, …); the `memfd_secret` backing (and core-dump exclusion via `MADV_DONTDUMP`) is Linux-only.
- `no_os`: No-op, kept for backwards compatibility. `no_std` is selected by disabling the default features (`--no-default-features`), which leaves only the zeroize-on-drop guarantee.
- `serde`: Enables serialization/deserialization.
- `codec`: Adds `encode` / `encode_with_capacity` / `encode_to_vec` / `encode_to_vec_with_capacity` / `encode_into_vec` / `decode` / `decode_slice`, a binary format written into locked memory (or, for the `_vec` pair, into a `Vec<u8>` you own) and read out of it. Implies `serde`, works in `no_std` + `alloc`, and adds no dependency.
- `expose-ptr`: For testing purposes. Exposes the locked memory region pointer.

## Security notes

- **Serialization writes plaintext.** `serde_json::to_string`/`to_vec` leave the document in an ordinary `String`/`Vec` that nothing wipes. Zeroize that buffer yourself, write through `SecureBytesWriter`, or use the [binary codec](#binary-codec).
- **Deserialization reads a buffer you own.** `serde_json::from_str`/`from_slice` take a plain `&str`/`&[u8]`. Parse from inside locked memory (`locked.unlock_slice(|json| serde_json::from_slice::<Vault>(json))`) so the input is unlocked only for the parse. Escaped JSON strings still land in `serde_json`'s own scratch buffer, which this crate cannot wipe. The codec decoder has no such scratch.

## Running tests

Public-API tests live in `tests/` (one integration crate per module). Internals, memory-protection checks, and crash tests that spawn a child stay in `src/` — a fault on locked memory kills the process, so they run in a child. Shared fixtures are in `tests/common/`.

```bash
cargo test                                          # default features
cargo test --all-features
cargo test --features serde,expose-ptr
cargo test --no-default-features --features codec    # no_std + alloc, codec only
```

## License
Licensed under the [MIT license](LICENSE-MIT).


## Credits
- [zeroize](https://github.com/RustCrypto/utils/tree/master/zeroize)
- [memsec](https://github.com/quininer/memsec)