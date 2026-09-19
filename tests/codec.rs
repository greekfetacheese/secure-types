//! Integration tests for the binary codec, driven through the public API only.
//!
//! These pin the properties that justified implementing `serde::Serializer` /
//! `serde::Deserializer` rather than a bespoke trait pair:
//!
//! - `#[derive]`, `#[serde(default)]`, `#[serde(skip_serializing)]` and
//!   `#[serde(skip_serializing_if)]` behave as they do with any other format;
//! - a document written by a newer struct still reads on an older one, because
//!   unknown fields are skipped through their length frame;
//! - a corrupt document is always an error, never a panic, and the error never
//!   carries payload bytes;
//! - the things the format deliberately does not support fail loudly.
//!
//! The fixture mirrors the shape of Zeus's vault so the tests exercise the
//! attribute combinations that motivated the codec in the first place.
#![cfg(feature = "codec")]

mod common;

use std::collections::BTreeMap;

use common::{decode_bytes, encoded_bytes};
use secure_types::{
   DecodeError, FORMAT_VERSION, SecureArray, SecureBytes, SecureString, SecureVec, decode,
   decode_slice, encode, encode_with_capacity,
};

use serde::Serialize;
use serde::de::DeserializeOwned;

/// Planted in the seed phrase, so a document can be searched for plaintext.
const SEED_MARKER: &str = "SEED-PHRASE-MARKER-2B7E";
/// Planted in a contact, which `skip_serializing` must keep off the wire.
const CONTACT_MARKER: &str = "CONTACT-MARKER-9F3A";

// ---------------------------------------------------------------- the fixture

#[derive(Serialize, serde::Deserialize)]
struct VaultData {
   hd_wallet: SecureHDWallet,
   imported_wallets: Vec<Wallet>,

   #[serde(default)]
   wallet_state_key: Option<WalletStateKey>,

   #[serde(default, skip_serializing)]
   contacts: Vec<Contact>,

   #[serde(default, skip_serializing_if = "Vec::is_empty")]
   tags: Vec<SecureString>,
}

#[derive(Serialize, serde::Deserialize)]
struct SecureHDWallet {
   seed_phrase: SecureString,
   entropy: SecureVec<u8>,
   xpriv_key: SecureArray<u8, 32>,
   chain_code: SecureArray<u8, 32>,
   next_index: u32,
}

#[derive(Serialize, serde::Deserialize)]
struct Wallet {
   label: SecureString,
   address: SecureArray<u8, 20>,
   balance: u128,
   watch_only: bool,
}

#[derive(Serialize, serde::Deserialize)]
struct WalletStateKey(SecureArray<u8, 32>);

#[derive(Serialize, serde::Deserialize)]
struct Contact {
   name: SecureString,
   address: SecureArray<u8, 20>,
}

fn hd_wallet() -> SecureHDWallet {
   SecureHDWallet {
      seed_phrase: SecureString::from(SEED_MARKER),
      entropy: SecureVec::from_slice(&[0x5A; 16]).unwrap(),
      xpriv_key: SecureArray::from_slice(&[0x11; 32]).unwrap(),
      chain_code: SecureArray::from_slice(&[0x22; 32]).unwrap(),
      next_index: 7,
   }
}

fn imported_wallets() -> Vec<Wallet> {
   vec![
      Wallet {
         label: SecureString::from("savings"),
         address: SecureArray::from_slice(&[0xAA; 20]).unwrap(),
         balance: 1_000_000_000_000_000_000,
         watch_only: false,
      },
      Wallet {
         label: SecureString::from("cold"),
         address: SecureArray::from_slice(&[0xBB; 20]).unwrap(),
         balance: 0,
         watch_only: true,
      },
   ]
}

fn vault() -> VaultData {
   VaultData {
      hd_wallet: hd_wallet(),
      imported_wallets: imported_wallets(),
      wallet_state_key: Some(WalletStateKey(
         SecureArray::from_slice(&[0x33; 32]).unwrap(),
      )),
      contacts: vec![Contact {
         name: SecureString::from(CONTACT_MARKER),
         address: SecureArray::from_slice(&[0xCC; 20]).unwrap(),
      }],
      tags: vec![SecureString::from("main"), SecureString::from("hardware")],
   }
}

// ------------------------------------------------------------------- helpers

/// Round-trips `value` and requires the re-encoding to be byte-identical, which
/// catches a field that was dropped, reordered, or silently defaulted.
fn assert_round_trips<T>(value: &T)
where
   T: Serialize + DeserializeOwned,
{
   let decoded = decode_bytes::<T>(&encoded_bytes(value)).expect("first decode failed");
   let reencoded = encoded_bytes(&decoded);

   assert_eq!(
      reencoded,
      encoded_bytes(value),
      "re-encoding the decoded value produced different bytes"
   );
}

/// Whether `haystack` contains `needle` as a contiguous run of bytes.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
   !needle.is_empty()
      && haystack
         .windows(needle.len())
         .any(|window| window == needle)
}

fn assert_string_eq(actual: &SecureString, expected: &str) {
   actual.unlock_str(|value| assert_eq!(value, expected));
}

fn assert_array_eq<const N: usize>(actual: &SecureArray<u8, N>, expected: &[u8; N]) {
   actual.unlock(|value| assert_eq!(value, expected));
}

fn assert_vec_eq(actual: &SecureVec<u8>, expected: &[u8]) {
   actual.unlock_slice(|value| assert_eq!(value, expected));
}

/// A tiny deterministic generator (xorshift64), so the corruption sweep is
/// reproducible and needs no dependency.
fn next_random(state: &mut u64) -> u64 {
   let mut value = *state;
   value ^= value << 13;
   value ^= value >> 7;
   value ^= value << 17;
   *state = value;
   value
}

// --------------------------------------------------------------------- tests

#[test]
fn test_the_vault_round_trips() {
   assert_round_trips(&vault());

   let decoded = decode_bytes::<VaultData>(&encoded_bytes(&vault())).expect("decode failed");

   assert_string_eq(&decoded.hd_wallet.seed_phrase, SEED_MARKER);
   assert_vec_eq(&decoded.hd_wallet.entropy, &[0x5A; 16]);
   assert_array_eq(&decoded.hd_wallet.xpriv_key, &[0x11; 32]);
   assert_array_eq(&decoded.hd_wallet.chain_code, &[0x22; 32]);
   assert_eq!(decoded.hd_wallet.next_index, 7);

   assert_eq!(decoded.imported_wallets.len(), 2);
   assert_string_eq(&decoded.imported_wallets[0].label, "savings");
   assert_array_eq(&decoded.imported_wallets[0].address, &[0xAA; 20]);
   assert_eq!(
      decoded.imported_wallets[0].balance,
      1_000_000_000_000_000_000
   );
   assert!(!decoded.imported_wallets[0].watch_only);
   assert_string_eq(&decoded.imported_wallets[1].label, "cold");
   assert!(decoded.imported_wallets[1].watch_only);

   assert!(decoded.wallet_state_key.is_some());
   assert_eq!(decoded.tags.len(), 2);
}

/// `skip_serializing` must keep the field off the wire entirely, and the reader
/// must fall back to `default`.
#[test]
fn test_skip_serializing_keeps_the_field_off_the_wire() {
   let document = encoded_bytes(&vault());

   assert!(
      contains(&document, SEED_MARKER.as_bytes()),
      "the seed phrase should be in the document"
   );
   assert!(
      !contains(&document, b"contacts"),
      "a `skip_serializing` field name reached the wire"
   );
   assert!(
      !contains(&document, CONTACT_MARKER.as_bytes()),
      "a `skip_serializing` field's value reached the wire"
   );

   let decoded = decode_bytes::<VaultData>(&document).expect("decode failed");
   assert!(
      decoded.contacts.is_empty(),
      "the default should have applied"
   );
}

/// `skip_serializing_if` omits the field when the predicate holds, and the field
/// name must not appear either.
#[test]
fn test_skip_serializing_if_omits_empty_fields() {
   let mut empty = vault();
   empty.tags.clear();

   let document = encoded_bytes(&empty);
   assert!(
      !contains(&document, b"tags"),
      "an empty `skip_serializing_if` field reached the wire"
   );

   assert_round_trips(&empty);

   // And with a value present it round-trips as usual.
   let populated = vault();
   assert!(!populated.tags.is_empty());
   assert!(contains(&encoded_bytes(&populated), b"tags"));
   assert_round_trips(&populated);
}

/// A `#[serde(default)]`-less field is not required to be present: a shorter
/// document from an older writer must still decode.
#[derive(Serialize)]
struct VaultDataWithoutStateKey {
   hd_wallet: SecureHDWallet,
   imported_wallets: Vec<Wallet>,
}

#[test]
fn test_a_field_the_writer_omitted_takes_its_default() {
   let document = encoded_bytes(&VaultDataWithoutStateKey {
      hd_wallet: hd_wallet(),
      imported_wallets: imported_wallets(),
   });

   let decoded = decode_bytes::<VaultData>(&document).expect("decode failed");

   assert!(
      decoded.wallet_state_key.is_none(),
      "the default should have applied"
   );
   assert!(decoded.contacts.is_empty());
   assert!(decoded.tags.is_empty());
   assert_eq!(decoded.imported_wallets.len(), 2);
   assert_string_eq(&decoded.hd_wallet.seed_phrase, SEED_MARKER);
}

/// The other direction: a field a newer writer added must be skipped through its
/// length frame, leaving the fields the reader knows intact. This is what makes
/// adding a field a compatible change.
#[derive(Serialize)]
struct VaultDataWithExtraField {
   hd_wallet: SecureHDWallet,
   imported_wallets: Vec<Wallet>,
   #[serde(skip_serializing_if = "Option::is_none")]
   wallet_state_key: Option<WalletStateKey>,
   #[serde(skip_serializing_if = "Vec::is_empty")]
   tags: Vec<SecureString>,
   /// Added later; an older reader does not know it exists.
   hardware_wallet: Option<SecureArray<u8, 64>>,
}

#[test]
fn test_a_field_the_reader_does_not_know_is_skipped() {
   let document = encoded_bytes(&VaultDataWithExtraField {
      hd_wallet: hd_wallet(),
      imported_wallets: imported_wallets(),
      wallet_state_key: Some(WalletStateKey(
         SecureArray::from_slice(&[0x33; 32]).unwrap(),
      )),
      tags: vec![SecureString::from("main")],
      hardware_wallet: Some(SecureArray::from_slice(&[0x77; 64]).unwrap()),
   });

   let decoded = decode_bytes::<VaultData>(&document).expect("decode failed");

   // Everything the reader does know survived, including the fields that came
   // *after* the unknown one.
   assert_string_eq(&decoded.hd_wallet.seed_phrase, SEED_MARKER);
   assert_eq!(decoded.imported_wallets.len(), 2);
   assert!(decoded.wallet_state_key.is_some());
   assert_eq!(decoded.tags.len(), 1);
   assert_string_eq(&decoded.tags[0], "main");
}

/// The case a positional encoding gets wrong: a skipped field in the *middle*
/// must not shift the fields after it.
#[derive(Serialize, serde::Deserialize)]
struct MiddleSkipped {
   before: u32,
   #[serde(default, skip_serializing_if = "Option::is_none")]
   middle: Option<SecureArray<u8, 32>>,
   after: u32,
}

#[test]
fn test_a_field_skipped_in_the_middle_does_not_shift_the_tail() {
   assert_round_trips(&MiddleSkipped {
      before: 1,
      middle: None,
      after: 2,
   });

   let decoded = decode_bytes::<MiddleSkipped>(&encoded_bytes(&MiddleSkipped {
      before: 1,
      middle: None,
      after: 2,
   }))
   .expect("decode failed");

   assert_eq!(decoded.before, 1);
   assert!(decoded.middle.is_none());
   assert_eq!(
      decoded.after, 2,
      "the field after the skipped one was shifted"
   );

   // With the middle field present, both tails still line up.
   let decoded = decode_bytes::<MiddleSkipped>(&encoded_bytes(&MiddleSkipped {
      before: 0xDEAD_BEEF,
      middle: Some(SecureArray::from_slice(&[0x99; 32]).unwrap()),
      after: 0xFEED_FACE,
   }))
   .expect("decode failed");

   assert_eq!(decoded.before, 0xDEAD_BEEF);
   assert_array_eq(
      decoded.middle.as_ref().expect("middle should be present"),
      &[0x99; 32],
   );
   assert_eq!(decoded.after, 0xFEED_FACE);
}

#[test]
fn test_every_truncation_is_an_error() {
   let document = encoded_bytes(&vault());

   for len in 0..document.len() {
      assert!(
         decode_bytes::<VaultData>(&document[..len]).is_err(),
         "a {len}-byte prefix decoded successfully"
      );
   }

   assert!(decode_bytes::<VaultData>(&document).is_ok());
}

/// A corrupt document must produce an error rather than a panic, and must not be
/// able to make the decoder do unbounded work.
#[test]
fn test_corruption_never_panics() {
   let original = encoded_bytes(&vault());
   let mut state = 0x2545_F491_4F6C_DD1D_u64;

   for _ in 0..2_000 {
      let mut mutated = original.clone();

      let mutations = 1 + (next_random(&mut state) % 3) as usize;
      for _ in 0..mutations {
         let index = (next_random(&mut state) as usize) % mutated.len();
         mutated[index] ^= (next_random(&mut state) & 0xFF) as u8;
      }

      // Either an error or a different value: never a panic, never a hang.
      let _ = decode_bytes::<VaultData>(&mutated);
   }
}

/// A length or count that cannot be satisfied is rejected before it reaches a
/// visitor's `size_hint`, which `SecureVec` would otherwise turn into a huge
/// locked allocation, or drives a loop.
///
/// The two container families take different paths and so report differently:
/// sequences read a *count* through the guarded counter, while byte blobs read a
/// *length* and hit the bounds check in `take`.
#[test]
fn test_a_corrupt_length_is_rejected_before_it_allocates() {
   // 1000 elements declared, nothing to fill them. Kept small enough to fit a
   // `usize` on every target, so the assertion does not depend on pointer width.
   let count_beyond_the_input = [secure_types::FORMAT_VERSION, 0xE8, 0x07];

   assert!(matches!(
      decode_bytes::<Vec<u8>>(&count_beyond_the_input),
      Err(DecodeError::InvalidLength)
   ));

   assert!(matches!(
      decode_bytes::<SecureVec<u8>>(&count_beyond_the_input),
      Err(DecodeError::UnexpectedEnd)
   ));

   assert!(matches!(
      decode_bytes::<SecureString>(&count_beyond_the_input),
      Err(DecodeError::UnexpectedEnd)
   ));

   // A length that does not even fit the remaining address space must also fail
   // cleanly rather than attempt the allocation. The exact variant depends on
   // pointer width, so only the failure is asserted.
   let absurd_length = [
      secure_types::FORMAT_VERSION,
      0xFF,
      0xFF,
      0xFF,
      0xFF,
      0xFF,
      0xFF,
      0xFF,
      0xFF,
      0xFF,
      0x01,
   ];

   assert!(decode_bytes::<SecureVec<u8>>(&absurd_length).is_err());
   assert!(decode_bytes::<SecureString>(&absurd_length).is_err());
   assert!(decode_bytes::<Vec<u8>>(&absurd_length).is_err());
}

/// The `serde_json`-specific hole this format exists to close: an error must
/// never carry payload bytes, in either `Display` or `Debug`, on any path.
#[test]
fn test_no_error_ever_echoes_payload_bytes() {
   let document = encoded_bytes(&vault());

   // The canary really is in the document, so the assertion below can fail.
   assert!(contains(&document, SEED_MARKER.as_bytes()));

   let mut checked = 0usize;

   let mut inspect = |bytes: &[u8]| {
      if let Err(error) = decode_bytes::<VaultData>(bytes) {
         checked += 1;

         for form in [error.to_string(), format!("{error:?}")] {
            assert!(
               !form.contains(SEED_MARKER),
               "an error echoed the seed phrase: {form}"
            );
            assert!(
               !form.contains(CONTACT_MARKER),
               "an error echoed a contact: {form}"
            );
         }
      }
   };

   // Every truncation, and every single-byte corruption.
   for len in 0..document.len() {
      inspect(&document[..len]);
   }
   for index in 0..document.len() {
      for bit in 0..8 {
         let mut mutated = document.clone();
         mutated[index] ^= 1 << bit;
         inspect(&mutated);
      }
   }

   assert!(checked > 0, "no error path was exercised");
}

/// `#[serde(untagged)]` needs `deserialize_any` to choose a variant, so it can
/// be written but not read back. It is documented as unsupported, and it fails
/// loudly instead of guessing at a variant.
#[derive(Serialize, serde::Deserialize)]
#[serde(untagged)]
enum Untagged {
   Number(u8),
   Text(SecureString),
}

#[test]
fn test_untagged_can_be_written_but_not_read_back() {
   let document = encoded_bytes(&Untagged::Number(9));

   assert!(matches!(
      decode_bytes::<Untagged>(&document),
      Err(DecodeError::Unsupported(_))
   ));
}

/// `SecureVec<T>` / `SecureArray<T, N>` for non-byte element types encode as a
/// sequence of values. For fixed-width scalars that is the same bytes a bulk
/// buffer would have produced, so nothing surprising lands on the wire.
#[test]
fn test_non_byte_element_containers_round_trip() {
   let words = SecureVec::from_slice(&[0x0102u16, 0x0304]).unwrap();

   assert_eq!(
      encoded_bytes(&words),
      [FORMAT_VERSION, 0x02, 0x02, 0x01, 0x04, 0x03]
   );

   let decoded: SecureVec<u16> = decode_bytes(&encoded_bytes(&words)).unwrap();
   decoded.unlock_slice(|slice| assert_eq!(slice, &[0x0102u16, 0x0304]));

   // A fixed-size array follows serde's own `[T; N]` convention: a tuple of elements.
   let block = SecureArray::<u32, 3>::from_slice(&[1, 2, u32::MAX]).unwrap();

   assert_eq!(
      encoded_bytes(&block),
      [
         FORMAT_VERSION,
         0x03,
         0x01,
         0x00,
         0x00,
         0x00,
         0x02,
         0x00,
         0x00,
         0x00,
         0xFF,
         0xFF,
         0xFF,
         0xFF,
      ]
   );

   let decoded: SecureArray<u32, 3> = decode_bytes(&encoded_bytes(&block)).unwrap();
   decoded.unlock(|slice| assert_eq!(slice, &[1u32, 2, u32::MAX]));
}

/// A container's declared count is part of the wire format, so a mismatch with the
/// destination type is rejected rather than silently truncated or padded.
#[test]
fn test_array_element_count_mismatch_is_rejected() {
   // Three `u32` elements where the destination wants four.
   let document = [
      FORMAT_VERSION,
      0x03,
      0x01,
      0x00,
      0x00,
      0x00,
      0x02,
      0x00,
      0x00,
      0x00,
      0x03,
      0x00,
      0x00,
      0x00,
   ];

   assert!(matches!(
      decode_bytes::<SecureArray<u32, 4>>(&document),
      Err(DecodeError::InvalidLength)
   ));
}

/// These containers go out as JSON arrays, not as strings: only the `u8` byte-buffer
/// impl accepts a JSON string for its contents.
#[test]
fn test_non_byte_element_containers_use_json_arrays() {
   let words = SecureVec::from_slice(&[1u16, 2]).unwrap();
   assert_eq!(serde_json::to_string(&words).unwrap(), "[1,2]");

   let block = SecureArray::<u16, 2>::from_slice(&[7, 8]).unwrap();
   assert_eq!(serde_json::to_string(&block).unwrap(), "[7,8]");

   // And the JSON string form is not accepted for them.
   assert!(serde_json::from_str::<SecureVec<u16>>("\"ab\"").is_err());
}

/// `#[serde(flatten)]` buffers unknown fields through `deserialize_any` too.
#[derive(serde::Deserialize)]
struct Flattened {
   #[serde(flatten)]
   #[allow(dead_code)] // never populated: decoding always fails first.
   rest: BTreeMap<String, u8>,
}

#[test]
fn test_flatten_is_reported_as_unsupported() {
   let mut map = BTreeMap::new();
   map.insert("a".to_owned(), 1u8);
   let document = encoded_bytes(&map);

   assert!(matches!(
      decode_bytes::<Flattened>(&document),
      Err(DecodeError::Unsupported(_))
   ));
}

/// `decode` unlocks the buffer for the decode and re-protects it afterwards.
#[test]
fn test_the_locked_buffer_path_works_and_survives() {
   let locked = encode(&vault()).expect("encode failed");

   let first = decode::<VaultData>(&locked).expect("decode failed");
   let second = decode::<VaultData>(&locked).expect("decode failed");

   assert_string_eq(&first.hd_wallet.seed_phrase, SEED_MARKER);
   assert_string_eq(&second.hd_wallet.seed_phrase, SEED_MARKER);

   // The document is still intact and readable.
   locked.unlock_slice(|bytes| {
      assert!(contains(bytes, SEED_MARKER.as_bytes()));
   });
}

// ---- from `codec::mod`'s test module ----

#[test]
fn test_the_document_starts_with_the_format_version() {
   let encoded = encode(&7u8).unwrap();

   encoded.unlock_slice(|bytes| {
      assert_eq!(bytes, &[FORMAT_VERSION, 0x07]);
   });
}

#[test]
fn test_scalars_round_trip_through_the_public_api() {
   let encoded = encode(&0xDEAD_BEEFu32).unwrap();

   encoded.unlock_slice(|bytes| {
      assert_eq!(bytes, &[FORMAT_VERSION, 0xEF, 0xBE, 0xAD, 0xDE]);
   });

   assert_eq!(decode::<u32>(&encoded).unwrap(), 0xDEAD_BEEF);
}

/// The point of the whole exercise: our own types go in and come back out
/// through the locked buffer.
#[test]
fn test_secure_types_round_trip_through_the_public_api() {
   let secret = SecureString::from("hunter2");
   let encoded = encode(&secret).unwrap();
   decode::<SecureString>(&encoded)
      .unwrap()
      .unlock_str(|value| assert_eq!(value, "hunter2"));

   let key = SecureVec::from_slice(&[1u8, 2, 3]).unwrap();
   let encoded = encode(&key).unwrap();
   decode::<SecureVec<u8>>(&encoded)
      .unwrap()
      .unlock_slice(|value| assert_eq!(value, &[1, 2, 3]));

   let array = SecureArray::<u8, 32>::from_slice(&[0xAB; 32]).unwrap();
   let encoded = encode(&array).unwrap();
   decode::<SecureArray<u8, 32>>(&encoded)
      .unwrap()
      .unlock(|value| assert_eq!(value, &[0xAB; 32]));
}

#[test]
fn test_capacity_changes_nothing_about_the_document() {
   let value = SecureString::from("hunter2");

   let default = encode(&value).unwrap();
   let sized = encode_with_capacity(&value, 4096).unwrap();

   default.unlock_slice(|left| {
      sized.unlock_slice(|right| assert_eq!(left, right));
   });
}

#[test]
fn test_a_zero_capacity_still_works() {
   // `SecureVec::new_with_capacity(0)` bumps to 1 internally, so this must
   // grow rather than fail.
   let encoded = encode_with_capacity(&7u8, 0).unwrap();

   assert_eq!(decode::<u8>(&encoded).unwrap(), 7);
}

/// Decoding must leave the buffer usable and protected: the unlock window is
/// closed again, and nothing about the document was consumed.
#[test]
fn test_the_buffer_survives_decoding() {
   let encoded = encode(&42u8).unwrap();

   assert_eq!(decode::<u8>(&encoded).unwrap(), 42);
   assert_eq!(decode::<u8>(&encoded).unwrap(), 42);

   encoded.unlock_slice(|bytes| assert_eq!(bytes, &[FORMAT_VERSION, 42]));
}

#[test]
fn test_decode_slice_matches_decode() {
   let encoded = encode(&1234u32).unwrap();

   let from_slice = encoded.unlock_slice(|bytes| decode_slice::<u32>(bytes).unwrap());

   assert_eq!(from_slice, decode::<u32>(&encoded).unwrap());
}

#[test]
fn test_errors_are_reported_from_a_locked_buffer_too() {
   // Version byte, then a one-field struct header with nothing after it.
   let mut buffer = SecureBytes::new_with_capacity(4).unwrap();
   buffer.push(FORMAT_VERSION);
   buffer.push(0x01);

   assert!(matches!(
      decode::<SecureString>(&buffer),
      Err(DecodeError::UnexpectedEnd)
   ));
}

#[test]
fn test_header_errors_from_a_slice() {
   assert!(matches!(
      decode_slice::<u8>(&[]),
      Err(DecodeError::UnexpectedEnd)
   ));

   assert!(matches!(
      decode_slice::<u8>(&[0x02, 0x01]),
      Err(DecodeError::UnsupportedVersion(2))
   ));

   assert!(matches!(
      decode_slice::<u8>(&[FORMAT_VERSION, 0x01, 0xFF]),
      Err(DecodeError::TrailingBytes { extra: 1 })
   ));
}
