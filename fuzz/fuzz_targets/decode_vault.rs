//! A struct/enum shape through the codec, plus the round-trip invariant.
//!
//! The type is chosen to reach every branch of the wire format the reader has:
//! length-framed struct fields (known and unknown), named enum variants, sequences, a
//! `char` whose scalar value the reader validates, integers wide enough to exercise the
//! varint and the 16-byte payloads, and floats whose bit patterns include NaN — which is
//! why the comparison is over encoded documents rather than over values.
//!
//! The invariant is driven from a document this target builds out of the input, not only
//! from the raw input. Random bytes essentially never decode as this struct (measured
//! against this repository's own corpus, none did), so a target that only tried the raw
//! path would fuzz the reader and never reach the assertions below. Two paths run per
//! input:
//!
//! 1. the raw bytes as a document — the reader path — and
//! 2. a document encoded from [`sample`], which always decodes and then has to survive
//!    decode → encode → decode unchanged.

#![no_main]

use libfuzzer_sys::fuzz_target;
use secure_types::{decode_slice, encode_to_vec};

#[derive(serde::Deserialize, serde::Serialize)]
struct Vault {
   label: String,
   key: Option<u32>,
   #[serde(default)]
   contacts: Vec<String>,
   entries: Vec<Entry>,
   flag: bool,
   weight: f64,
   letter: char,
   wide: u128,
   signed: i64,
   #[serde(default)]
   counts: Vec<u64>,
}

#[derive(serde::Deserialize, serde::Serialize)]
enum Entry {
   Name(String),
   Count(u64),
   Nested { depth: u8, tags: Vec<u8> },
}

/// The input byte at `at`, or `fallback` past the end.
fn byte(data: &[u8], at: usize, fallback: u8) -> u8 {
   data.get(at).copied().unwrap_or(fallback)
}

/// Eight little-endian bytes of the input from `at` on, zero-padded.
fn word(data: &[u8], at: usize) -> u64 {
   let mut bytes = [0u8; 8];
   for (index, slot) in bytes.iter_mut().enumerate() {
      *slot = byte(data, at + index, 0);
   }
   u64::from_le_bytes(bytes)
}

/// A string of printable ASCII, so the value is valid UTF-8 whatever the input is.
fn ascii(data: &[u8], at: usize, length: usize) -> String {
   data.iter()
      .skip(at)
      .take(length)
      .map(|&b| char::from(b % 95 + 0x20))
      .collect()
}

/// A value built from arbitrary bytes.
///
/// Every field is derived from the input, so the document the invariant runs over is
/// free to vary in length, element count and scalar width. Characters come from a fixed
/// set (the reader validates the scalar value) and the float is finite, so
/// [`assert_stable`] only ever compares encoder output and never a NaN.
fn sample(data: &[u8]) -> Vault {
   let mut entries = Vec::new();
   for index in 0..usize::from(byte(data, 0, 0) % 4) {
      let at = 1 + index * 3;
      entries.push(match byte(data, at, 0) % 3 {
         0 => Entry::Name(ascii(data, at + 1, 1 + usize::from(byte(data, at + 1, 0) % 8))),
         1 => Entry::Count(word(data, at + 1)),
         _ => Entry::Nested {
            depth: byte(data, at + 1, 0),
            tags: data.iter().skip(at + 2).take(4).copied().collect(),
         },
      });
   }

   Vault {
      label: ascii(data, 1, 8),
      key: match byte(data, 0, 0) % 3 {
         0 => None,
         _ => Some(word(data, 9) as u32),
      },
      contacts: (0..usize::from(byte(data, 2, 0) % 3))
         .map(|index| ascii(data, 20 + index * 4, 4))
         .collect(),
      entries,
      flag: byte(data, 3, 0) & 1 == 1,
      weight: f64::from(u16::from_le_bytes([byte(data, 4, 0), byte(data, 5, 0)])) / 7.0,
      letter: ['a', 'λ', '\u{10FFFF}']
         .get(usize::from(byte(data, 6, 0) % 3))
         .copied()
         .unwrap_or('a'),
      wide: u128::from(word(data, 10)) << 64 | u128::from(word(data, 18)),
      signed: word(data, 26) as i64,
      counts: (0..usize::from(byte(data, 7, 0) % 4))
         .map(|index| word(data, 30 + index * 8))
         .collect(),
   }
}

/// decode → encode → decode on a document this target produced.
///
/// Anything the reader accepts has to be something the writer can express, and the
/// document the writer produces has to read back as the same value: an encoder and a
/// decoder that disagree show up here instead of as a vault that cannot be reopened.
fn assert_stable(document: &[u8]) {
   let value = decode_slice::<Vault>(document).expect("a document this target built must decode");
   let encoded = encode_to_vec(&value).expect("a decoded value must encode");
   let round_tripped = decode_slice::<Vault>(&encoded).expect("an encoded value must decode");
   let re_encoded = encode_to_vec(&round_tripped).expect("a re-decoded value must encode");

   assert_eq!(encoded, re_encoded, "decode/encode is not stable");
}

fuzz_target!(|data: &[u8]| {
   // The reader path: a document the reader accepts is a value the writer must express.
   if let Ok(vault) = decode_slice::<Vault>(data) {
      let document = encode_to_vec(&vault).expect("a value the reader accepted must encode");
      assert_stable(&document);
   }

   // The invariant path, reached by every input.
   let document = encode_to_vec(&sample(data)).expect("a sample value must encode");
   assert_stable(&document);
});
