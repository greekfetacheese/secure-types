//! A struct/enum shape through the codec, plus the round-trip invariant.
//!
//! The type is chosen to reach every branch of the wire format the reader has:
//! length-framed struct fields (known and unknown), named enum variants, sequences, a
//! `char` whose scalar value the reader validates, integers wide enough to exercise the
//! varint and the 16-byte payloads, and floats whose bit patterns include NaN — which is
//! why the comparison is over encoded documents rather than over values.

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

fuzz_target!(|data: &[u8]| {
   let Ok(vault) = decode_slice::<Vault>(data) else {
      return;
   };

   // Anything the reader accepts has to be something the writer can express, and the
   // document the writer produces has to read back as the same value: an encoder and a
   // decoder that disagree show up here instead of as a vault that cannot be reopened.
   // Both documents compared below were written by the encoder, so both are minimal and
   // NaN never reaches the comparison.
   let document = encode_to_vec(&vault).expect("a value the reader accepted must encode");
   let round_tripped = decode_slice::<Vault>(&document).expect("an encoded value must decode");
   let re_encoded = encode_to_vec(&round_tripped).expect("a re-decoded value must encode");

   assert_eq!(
      document, re_encoded,
      "decode/encode is not stable"
   );
});
