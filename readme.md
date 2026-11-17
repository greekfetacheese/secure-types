# Secure Types

The goal of this crate is to provide a simple way to properly handle sensitive data in memory (e.g. passwords, private keys, etc).

Currently there are three core types:

- `SecureString`: For working with strings.
- `SecureVec`: For working with `Vec<T>`.
- `SecureArray`: For working with `&[T; LENGTH]`.

`SecureBytes` is an alias for `SecureVec<u8>`, `SecureBytesWriter` (with `use_os`) adapts
`io::Write` onto one, and `Drain` (in the `vec` module, not at the crate root) is the
iterator `SecureVec::drain` returns.

## Features

- **Zeroization on Drop**: Memory is wiped when dropped.
- **Memory locking** (OS only): Pages are `mprotect`ed `PROT_NONE` while the value is idle. They are unprotected only while an operation that needs them runs — an `unlock*` call; an internal read (`char_len`/`char_len_unchecked`, `Clone`, the `SecureArray`↔`SecureVec` conversions and `TryFrom<SecureVec<u8>> for SecureString`, serde `Serialize`, `encode*`/`encoded_len`); the codec's `decode` (which unlocks the buffer for the parse) and serde `Deserialize` of a `SecureVec` (which unprotects the destination one append block at a time — up to 4096 elements — instead of once per element); one of the type's own mutations (`push`, `push_str`, `insert_text_at_char_idx`, `delete_text_char_range`, `clear`/`erase`, iterating or dropping a `drain`, `reserve` when it has to grow, `Drop`); or a write through `SecureBytesWriter` (`write`/`write_all`, which append via `extend_from_slice`). `SecureString::drain` also unlocks on the call itself, to check that the range lies on char boundaries. That stops accidental reads, including from this process; it is not a defence against `ptrace` or a debugger. On the malloc path the allocation is also `mlock`ed on a best-effort basis (the call's result is discarded, so hitting `RLIMIT_MEMLOCK` still constructs; Windows: `VirtualLock`) and, where the OS allows it, excluded from core dumps. Linux uses `memfd_secret` when the kernel supports it. See [How memory is locked](#how-memory-is-locked).
- **Scoped access**: No `Index`/`Deref` — `secret[0]` does not compile. The contents are read through the `unlock*` closures (the `expose-ptr` testing feature aside). They can still leave the type as an ordinary copy — `drain` yields owned elements, `Clone` duplicates them, and the conversions move them out — so treat those like any other copy of the secret.
- **Send, not Sync**: Values can move to another thread. Sharing one instance needs an explicit lock (`Arc<Mutex<_>>`); concurrent `unlock` races on page protection.
- **`no_std`**: Zeroization only. Disable the default features — see [Feature Flags](#feature-flags).
- **Serde**: Optional serialization for `SecureString`, `SecureVec<T>`, and `SecureArray<T, LENGTH>`. A `u8` container serializes as a byte buffer; other element types as a sequence (`SeqElement`) — or, for `SecureArray`, as a tuple, matching serde's own `[T; N]` convention.
- **Binary codec** (feature `codec`): A `serde` Serializer/Deserializer that encodes into a `SecureBytes` — locked while idle with `use_os`, zeroized on drop either way — and decodes out of it. No extra dependency beyond `serde`.

## How memory is locked

- **Windows**: [VirtualProtect](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect) and [VirtualLock](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock).
- **Linux**: [memfd_secret](https://man.archlinux.org/man/memfd_secret.2.en) when the kernel supports it. Otherwise [mlock](https://man.archlinux.org/man/mlock.2) and [madvise](https://man.archlinux.org/man/madvise.2) (`MADV_DONTDUMP`) on the malloc path. A `memfd_secret` allocation is not `mlock`ed and is not marked `MADV_DONTDUMP` by `secure-alloc`. Every path still uses `mprotect(PROT_NONE)` whenever the value is idle. The tier is chosen per allocation: a probe failure the kernel attributes to the platform (`ENOSYS`, `EINVAL`, `EPERM`) is cached, while one that describes the attempt (`EMFILE`, `ENFILE`, `ENOMEM`, `EINTR`) is not, so the next allocation probes again — and the allocation whose probe failed takes the malloc path, inside the kernel's direct map rather than outside it.
- **Other Unix** (macOS, FreeBSD, …): [mlock](https://man.archlinux.org/man/mlock.2) plus `mprotect(PROT_NONE)`. FreeBSD/DragonFly also use `madvise(MADV_NOCORE)`. No `memfd_secret`.

`mlock` is best-effort: `secure-alloc` ignores its return value, so hitting `RLIMIT_MEMLOCK` still constructs. `mprotect` failure is `Error::LockFailed` where a constructor can still report it. Every other protection call — unlock, re-lock, the re-lock after a buffer grows, and `Drop` — aborts the process with a diagnostic instead of touching a page in an unknown protection state, because none of those paths can report an error and continuing would leave a live value readable. The abort is unconditional; the diagnostic is best-effort, because it is a blocking write to stderr and a stopped reader postpones it.

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

 // When `secret` is dropped, its data is zeroized.
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

The `codec` feature is a small binary `serde` format. Encode goes into a `SecureBytes` — locked while idle with `use_os`, zeroized on drop in every build — and decode reads out of it. `#[derive(Serialize, Deserialize)]` and `#[serde(...)]` work as usual. No extra dependency beyond `serde`.

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

// The encoded document is the only copy, and it lives in a SecureBytes that is
// locked while idle when use_os is on, and zeroized on drop either way.
let encoded = encode(&vault)?;
let decoded = decode::<VaultData>(&encoded)?;

assert_eq!(decoded.wallet_state_key, Some(7));
assert!(decoded.contacts.is_empty()); // `skip_serializing` -> `default`

// When the caller is going to hold the document in a `Vec<u8>` anyway,
// `encode_into_vec` appends the document after whatever the buffer already holds,
// so there is no `SecureBytes` to allocate and nothing copied twice. The `0x07`
// below is the caller's own byte, pushed before the call; `encode_to_vec` is the
// same document into a fresh buffer.
//
// That buffer is ordinary memory: not locked, and not wiped on drop.
let mut payload = vec![0x07];
encode_into_vec(&mut payload, &vault)?;
assert_eq!(payload[0], 0x07);
# }
# Ok::<(), Box<dyn std::error::Error>>(())
```

`encode` returns a `SecureBytes`. `encode_to_vec` / `encode_into_vec` produce the same document into a plain `Vec<u8>` the caller owns: not locked, and not zeroized on drop, but a *failed* encoding erases everything it appended, so no partial document survives in that buffer; growth can still leave a copy in an allocation the `Vec` abandons. `encoded_len` reports how many bytes a document takes — measured by the same serializer, so a destination can be sized exactly and never grow. `decode` unlocks only for the parse and re-locks afterwards, including on error. Types are raw binary — a `SecureArray<u8, 32>` is 32 payload bytes behind a one-byte length prefix — and strings are not escaped, so there is no scratch copy of an unescaped string.

**Format evolution.** `FORMAT_VERSION` is the first byte. An unknown version is refused. Adding a field with `#[serde(default)]` does not need a bump: fields are named and length-prefixed, so unknown fields are skipped and missing ones take their default. Changing a field's type does need a bump.

**Not supported.** No type tags, so `deserialize_any` is unimplemented. `#[serde(flatten)]`, `#[serde(untagged)]`, and `Value`-shaped fields fail with `DecodeError::Unsupported`. Untagged enums can still serialize; they cannot be read back.

**Nesting depth.** A recursive type is bounded at 128 depth units: a document nested deeper is refused with `DecodeError::DepthLimit` rather than overflowing the stack. A struct field is framed by its own sub-decoder and an `Option` adds a level of its own, so a recursive struct costs two units per level: a chain of 64 `struct Node { next: Option<Box<Node>> }` nodes decodes and 65 is refused, measured. A chain that costs one unit per level, such as `enum Chain { Nil, Next(Box<Chain>) }`, reaches 128 (129 is refused). The bound is on the reader: `encode` does not refuse a value for its depth, so a recursive value nested past it produces a document `decode` rejects. A value that has to be read back has to stay inside the bound.

**Element visits.** Decoding also bounds the total element visits a document may drive to a small multiple of its own byte length, so a compact document built from zero-byte element types (`Vec<Vec<()>>`) is refused with `DecodeError::InvalidLength` instead of taking quadratic time to be rejected.

## See also the [examples](https://github.com/greekfetacheese/secure-types/tree/master/examples).


## Feature Flags

- `use_os` (default): Enables all OS-level security features. Supported on Linux, Windows, and other Unix (macOS, FreeBSD, …); the `memfd_secret` backing (and core-dump exclusion via `MADV_DONTDUMP`) is Linux-only.
- `no_os`: No-op, kept for backwards compatibility. `no_std` is selected by disabling the default features (`--no-default-features`), which leaves only the zeroize-on-drop guarantee.
- `serde`: Enables serialization/deserialization.
- `codec`: Adds `encode` / `encode_with_capacity` / `encode_to_vec` / `encode_to_vec_with_capacity` / `encode_into_vec` / `encoded_len` / `decode` / `decode_slice`, a binary format written into a `SecureBytes` (locked while idle with `use_os`, zeroized on drop either way) or, for the `_vec` pair, into a `Vec<u8>` you own, and read out of it. Implies `serde`, works in `no_std` + `alloc` (zeroization only there, like the rest of the crate), and adds no dependency.
- `expose-ptr`: For testing purposes. Exposes the locked memory region pointer.

## Security notes

- **Only the container's own allocation is protected.** `secure-alloc` guards the region a `SecureVec`/`SecureArray` owns. For an element type that owns heap memory (`String`, a struct with a `String` field) that memory lives in the ordinary allocator: not locked, and not excluded from a core dump. It *is* zeroized when the container discards the element: `Drop`, `clear` and a completed `drain` zeroize before dropping, and `SecureArray::erase` zeroizes in place. A value you moved out of the container is yours to wipe; one stranded by a forgotten `Drain` is leaked, and its owned buffers keep their plaintext (the allocator's wipe at `free` covers only the container's own bytes). Keep byte secrets in a `u8` container.
- **Alignment is capped at the page size.** `secure-alloc` returns a pointer inside a page-rounded region, so the strongest alignment the allocation can carry is one page: the returned pointer is not guaranteed to be page-aligned, and the crate's own padding cannot express more than a page. A `T` whose `align_of` exceeds the platform page size is therefore rejected with `Error::AlignmentFailed` instead of being written through a misaligned pointer. `SecureVec::from_vec` is the exception: it reports every failure to allocate as `Error::AllocationFailed`.
- **Serialization writes plaintext.** `serde_json::to_string`/`to_vec` leave the document in an ordinary `String`/`Vec` that nothing wipes. Zeroize that buffer yourself, write through `SecureBytesWriter`, or use the [binary codec](#binary-codec).
- **Deserialization reads a buffer you own.** `serde_json::from_str`/`from_slice` take a plain `&str`/`&[u8]`. Parse from inside locked memory (`locked.unlock_slice(|json| serde_json::from_slice::<Vault>(json))`) so the input is unlocked only for the parse. Escaped JSON strings still land in `serde_json`'s own scratch buffer, which this crate cannot wipe. The codec decoder has no such scratch.
- **A rejected framed field is dropped un-wiped.** When a struct field decodes but does not fill its frame, the codec returns `DecodeError::FrameMismatch` and drops the decoded value there: it cannot zeroize an arbitrary `V::Value`, so a field type that owns plaintext in the ordinary allocator (`String`, `Vec<u8>`) leaves that copy behind. Keep a secret field body in a `u8` container, or in a type that zeroizes on drop.

## Running tests

Public-API tests live in `tests/`: one integration crate per public module, plus the codec sub-suites (`decoder`, `encoder`, `format`, `depth`), a crate-level file, the `no_std` suite the Miri section runs, and two allocation suites — `alignment` for the page-size cap and `alloc_limits` for the region sizes near `usize::MAX`. Internals and memory-protection checks live in `src/` unit tests; crash tests that spawn a child live in both `src/` and `tests/` — a fault on locked memory kills the process, so they run in a child. Shared fixtures are in `tests/common/`.

```bash
cargo test                                          # default features
cargo test --all-features
cargo test --features serde,expose-ptr
cargo test --no-default-features --features codec    # no_std + alloc, codec only
```

### Miri

Miri cannot run the default build: it does not execute the `libc` calls the allocator makes (`mmap`, `mlock`, `mprotect`, `memfd_secret`). The `no_std` + `alloc` build keeps the same raw-pointer container code on the plain allocator, and `tests/no_std.rs` is the suite written for it — construction, growth, `clear`/`erase`, `drain`, drop, and (with `codec`) a small encode/decode round trip, all through the public API and with an element type that owns heap memory, so a mishandled move shows up as a leak rather than as a slot that still reads back. Strict provenance is on, so a pointer that goes through `usize` and back is a finding rather than a warning.

The codec integration suites run on that build too, but they are sized for native throughput — a 10 000-element round trip, a 2 000-mutation corruption sweep, a two-second wall-clock bound — and measured they do not finish in minutes under Miri, so they are not part of the default run.

```bash
scripts/miri.sh                            # the container suite, alloc-only then with codec
cargo test --no-default-features           # the same suite, natively
cargo test --no-default-features --features codec
```

Needs `rustup component add --toolchain nightly miri`.

### Fuzzing

`fuzz/` is a `cargo-fuzz` package: its own workspace, built against `no_std` + `codec` so one case costs a plain allocation rather than an `mlock`/`mprotect` pair. Five targets — three on the codec reader (`SecureString`, `SecureBytes`, and a struct/enum shape that checks decode → encode → decode is stable on a document it builds from the input, so that check runs on every case) and two differential ones that drive `SecureVec` and `SecureString` through an arbitrary op sequence against a plain `Vec`/`String` model.

```bash
scripts/fuzz.sh          # smoke: 10 000 runs per target
scripts/fuzz.sh vec_ops  # one target, unbounded
scripts/fuzz.sh --list
```

A crash lands in `fuzz/artifacts/<target>/`; hand it back to `scripts/fuzz.sh <target>` to reproduce it. Needs `cargo install cargo-fuzz`.

## License
Licensed under the [MIT license](LICENSE-MIT).


## Credits
- [zeroize](https://github.com/RustCrypto/utils/tree/master/zeroize)
- The memory layer is the vendored `secure-alloc` fork of [memsec](https://github.com/quininer/memsec) by quininer, maintained in this repository at `crates/secure-alloc`.