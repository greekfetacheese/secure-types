# Secure Types

The goal of this crate is to provide a simple way to properly handle sensitive data in memory (eg. passwords, private keys, etc).

Currently there are 3 types:

- `SecureString`: For working with strings.
- `SecureVec`: For working with `Vec<T>`.
- `SecureArray`: For working with `&[T; LENGTH]`.

## Features

- **Zeroization on Drop**: Memory is wiped when dropped.
- **Memory Locking**: (OS-only) While no `unlock*` scope is active the pages are `mprotect`ed `PROT_NONE`, which is what keeps the contents away from other processes. On the `malloc_sized` path the allocation is also `mlock`ed (Windows: `VirtualLock`) and, where the OS provides it, excluded from core dumps (`MADV_DONTDUMP` on Linux, `MADV_NOCORE` on FreeBSD/DragonFly; macOS has no equivalent), so it cannot be swapped out or captured in a crash dump. On Linux, when the kernel supports it, the allocation is backed by `memfd_secret` instead: `memsec` issues no `mlock` or `madvise` on that path, and the pages come from kernel secret memory. See [How memory is locked](#how-memory-is-locked).
- **Safe Scoped Access**: Direct access on these types is not possible, data is protected by default and only accessible within safe blocks.
- **Send, not Sync**: Values can be moved to another thread. Sharing one instance across threads requires an explicit lock (`Arc<Mutex<_>>`). Concurrent `unlock` would race on page protection.
- **`no_std` Support**: For embedded and Web environments (with zeroization only). Select it by turning off the default features — see [Feature Flags](#feature-flags).
- **Serde Support**: Optional serialization/deserialization for `SecureString`, plus `SecureVec<T>` and `SecureArray<T, LENGTH>`. A `u8` container is a byte string and serializes as one bulk byte buffer; any other element type is serialized as a sequence of values, and more element types can opt in through the `SeqElement` trait.
- **Binary Codec**: (feature `codec`) A self-owned binary format implemented as a `serde::Serializer`/`serde::Deserializer`, which encodes straight into locked memory and decodes straight out of it, so serialization does not have to leave plaintext in a buffer nothing can wipe. Adds no dependency beyond `serde`.

## How memory is locked

- **Windows**: Using [VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect) & [VirtualLock](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock).

- **Linux**: Using [mlock](https://man.archlinux.org/man/mlock.2) & [madvise](https://man.archlinux.org/man/madvise.2).
  If the kernel supports it, it will allocate with [memfd_secret](https://man.archlinux.org/man/memfd_secret.2.en).
  Note that the `mlock`/`madvise` pair belongs to the `malloc_sized` path: a `memfd_secret`
  allocation is **not** `mlock`ed and is **not** marked `MADV_DONTDUMP` by `memsec`, so on that
  path core-dump exclusion is not requested and swappability is whatever the kernel's secret
  memory provides. This crate's own contribution on every path is the `mprotect(PROT_NONE)`
  window discipline.

- **Other Unix (macOS, FreeBSD, …)**: Using [mlock](https://man.archlinux.org/man/mlock.2) & [mprotect](https://man.archlinux.org/man/mprotect.2), with
  `madvise(MADV_NOCORE)` on FreeBSD/DragonFly. `memfd_secret` and `MADV_DONTDUMP` are Linux-only, so `supports_memfd_secret()`
  returns `false` here and the allocation uses `malloc_sized` — the same path Linux takes when the kernel lacks `memfd_secret`.

Locking is best-effort in one respect: on the `malloc_sized` path `memsec` discards the return
value of `mlock`, so exhausting `RLIMIT_MEMLOCK` does not fail construction — the allocation is
still `mprotect`ed (and a `memfd_secret` allocation is never `mlock`ed at all, see above). The
constructors return `Error::LockFailed` when that `mprotect` fails, and a failed re-lock after
an `unlock*` scope panics in every profile rather than silently leaving the memory readable.

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

`serde_json` cannot be made to leave no traces, and the parts that leak belong to the format
rather than to serde: its `Deserializer` keeps a private `scratch: Vec<u8>` that it reuses for
every escaped string and never zeroizes, `from_reader` copies *every* string into that scratch,
`Value` deserializes a whole document into plain `String`s, and its error formatting renders
`string "…the plaintext…"` into the message.

The `codec` feature adds a small binary format implemented as a `serde::Serializer` and a
`serde::Deserializer`. Your `#[derive(Serialize, Deserialize)]` and `#[serde(...)]` attributes
work unchanged, and no dependency is added beyond `serde` itself:

```rust
# #[cfg(feature = "codec")] {
use secure_types::{decode, encode};
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
# }
# Ok::<(), Box<dyn std::error::Error>>(())
```

`encode` returns a `SecureBytes`, so the result is locked while unused and wiped on drop;
`decode` unlocks it only for the duration of the decode and re-locks it afterwards, even on
the error path. Types are written as raw binary — a `SecureArray<u8, 32>` is 32 bytes, not
64 hex characters — and strings carry no escaping pass, so there is no scratch copy of an
unescaped string to survive anywhere.

**Evolving a stored format.** `FORMAT_VERSION` is the first byte of every document, and a
reader refuses a version it does not recognise rather than guessing. Adding a field with
`#[serde(default)]` does *not* need a version bump: struct fields are tagged by name and each
one carries its own length, so a reader that does not know a field skips it whole and a field
the writer omitted falls back to its default. Changing a field's *type* does need one.

**Not supported.** The format carries no type tags, so `deserialize_any` cannot be
implemented and anything built on it fails with `DecodeError::Unsupported` rather than
guessing: `#[serde(flatten)]`, `#[serde(untagged)]`, and `Value`-shaped fields. Note the
asymmetry for untagged enums — an untagged variant *serializes* fine (writing one needs no
tag) but cannot be read back, so a successful `encode` is not on its own a promise that the
value is decodable.

**Cost.** Decoding locks memory per secure allocation, which measured ~0.5 ms for a small
vault-shaped payload in a release build with `use_os`, against ~0.03 ms with locking disabled.
Irrelevant for a one-shot unlock, worth knowing before decoding in a loop.

## See also the [examples](/examples/).


## Feature Flags

- `use_os` (default): Enables all OS-level security features. Supported on Linux, Windows, and other Unix (macOS, FreeBSD, …); the `memfd_secret` backing (and core-dump exclusion via `MADV_DONTDUMP`) is Linux-only.
- `no_os`: No-op, kept for backwards compatibility. `no_std` is selected by disabling the default features (`--no-default-features`), which leaves only the zeroize-on-drop guarantee.
- `serde`: Enables serialization/deserialization.
- `codec`: Adds `encode` / `encode_with_capacity` / `decode` / `decode_slice`, a binary format written into locked memory and read out of it. Implies `serde`, works in `no_std` + `alloc`, and adds no dependency.
- `expose-ptr`: For testing purposes. Exposes the locked memory region pointer.

## Security notes

- **Serialization writes plaintext.** `Serialize` cannot wipe the buffer the serializer
  builds for it: `serde_json::to_string`/`to_vec` leave the plaintext in an ordinary
  `String`/`Vec` that nothing zeroizes, so zeroize that buffer yourself if you call them, or
  wire the serializer around `SecureBytesWriter` so the plaintext only ever lives in locked
  memory that is zeroized on drop. Better still, use the [binary codec](#binary-codec)
  (feature `codec`), which has no such gap to begin with.
- **Deserializing reads from a buffer you own.** `serde_json::from_str`/`from_slice` take a
  plain `&str`/`&[u8]`, and nothing can wipe that input for you. Parse from inside the locked
  buffer instead — `locked.unlock_slice(|json| serde_json::from_slice::<Vault>(json))` — so
  the plaintext is unlocked only for the duration of the parse. Note that when a JSON string
  contains escape sequences, `serde_json` unescapes it into an internal scratch buffer of its
  own before handing it over; that copy is not ours to erase (strings without escapes are read
  straight out of your input). The `codec` decoder has no such scratch: it hands over borrowed
  slices with `visit_str`/`visit_bytes` and never `visit_borrowed_*`, so nothing it produces
  can outlive the unlock window.
- **The codec never puts payload bytes in an error.** Every `DecodeError` and `EncodeError` is
  built from a length, an index or a `&'static str`, and the one variant of each that an impl
  can steer — `DecodeError::Custom` and `EncodeError::Custom` — carries no message at all.
  serde's own `unknown_variant` / `unknown_field` helpers, and any `Serialize`/`Deserialize`
  impl calling `Error::custom`, build that text by formatting data that came out of the document
  or out of the value being written, so discarding it is what keeps a name — or a secret — from
  reaching a log. That is deliberately unlike serde's `Unexpected::Str(s)`, which renders
  `string "…the value…"` — exactly the sort of thing that ends up in a log or a crash report.
- **Deserializing into plain fields re-opens the hole.** The codec removes the format's own
  leaks; it cannot remove yours. A struct holding `String`/`Vec<u8>` fields deserializes those
  fields into unprotected memory that nothing wipes. Make the persisted fields the secure
  types (`SecureString`, `SecureVec<u8>`, `SecureArray<u8, LENGTH>`); they implement
  `Deserialize`, so the derives work unchanged.
- **Owned buffers a deserializer hands over are wiped.** When a format gives up ownership of a
  `String`/`Vec<u8>` (`visit_string`/`visit_byte_buf`), the contents are copied into locked
  memory and the buffer is zeroized before it is released, instead of being dropped with the
  plaintext still inside.
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

The suite lives in `tests/`, one integration crate per source module — `tests/vec.rs`, `tests/array.rs`,
`tests/string.rs`, `tests/writer.rs`, `tests/crate_level.rs`, and `tests/codec.rs` plus
`tests/codec_encoder.rs` / `tests/codec_decoder.rs` / `tests/codec_format.rs` for the binary codec.
Because each file is its own crate, those tests see only the **public API**, which doubles as a check
that nothing internal leaked into it.

The tests that cannot work that way stay in `tests` modules inside `src/`: the `patch_at` internals, the
memory-protection checks, the varint helpers, and the crash tests that spawn a child process to
reproduce a re-lock failure — they read `pub(crate)` state or a private field. Shared fixtures and the
owned-input deserializers live in `tests/common/`.

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
