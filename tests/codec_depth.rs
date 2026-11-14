//! The decoder's nesting-depth limit.

#![cfg(feature = "codec")]

use secure_types::DecodeError;
use serde::Deserialize;

/// One nesting level per `0x01` byte, terminated by a `0x00`.
#[derive(Deserialize)]
struct Node(Option<Box<Node>>);

fn document(depth: usize) -> Vec<u8> {
   let mut bytes = vec![secure_types::FORMAT_VERSION];
   bytes.resize(depth + 1, 0x01);
   bytes.push(0x00);
   bytes
}

#[test]
fn deep_nesting_is_rejected() {
   match secure_types::decode_slice::<Node>(&document(100)) {
      Ok(_) => panic!("got Ok: 100 levels were accepted"),
      Err(DecodeError::DepthLimit) => {}
      Err(other) => panic!("got {other:?}"),
   }
}

#[test]
fn shallow_nesting_still_decodes() {
   let mut node = secure_types::decode_slice::<Node>(&document(8)).expect("8 levels fit");

   let mut levels = 0;
   while let Some(inner) = node.0 {
      levels += 1;
      node = *inner;
   }

   assert_eq!(levels, 8);
}

#[test]
fn wide_documents_still_decode() {
   let value: Vec<u16> = (0..1000).collect();
   let document = secure_types::encode(&value).unwrap();
   let decoded: Vec<u16> = secure_types::decode(&document).unwrap();

   assert_eq!(decoded, value);
}

#[test]
fn very_deep_nesting_does_not_crash() {
   match secure_types::decode_slice::<Node>(&document(200_000)) {
      Ok(_) => panic!("got Ok: 200_000 levels were accepted"),
      Err(DecodeError::DepthLimit) => {}
      Err(other) => panic!("got {other:?}"),
   }
}
