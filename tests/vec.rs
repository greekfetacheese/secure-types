//! `SecureVec` / `SecureBytes`, exercised through the public API.

#![cfg(feature = "use_os")]

#[cfg(feature = "serde")]
mod common;

use std::fmt::Debug;
use std::sync::{Arc, Mutex};

use secure_types::{SecureArray, SecureVec, Zeroize};

/// Mirrors `SecureVec`'s private cap on the memory a format-supplied `size_hint` may
/// reserve up front. Kept in step by hand; the assertion is `<=`, so a tighter internal
/// cap does not break it.
#[cfg(feature = "serde")]
const MAX_PREALLOCATION_FROM_SIZE_HINT: usize = 4096;

#[test]
fn test_creation() {
   let vec: Vec<u8> = vec![1, 2, 3];
   let secure_vec = SecureVec::from_vec(vec).unwrap();

   secure_vec.unlock_slice(|slice| {
      assert_eq!(slice, &[1, 2, 3]);
   });

   let exposed_slice = &mut [1, 2, 3];
   let secure_slice = SecureVec::from_slice_mut(exposed_slice).unwrap();
   assert_eq!(exposed_slice, &[0u8; 3]);

   secure_slice.unlock_slice(|slice| {
      assert_eq!(slice, &[1, 2, 3]);
   });

   let exposed_slice = [1, 2, 3];
   let secure_slice = SecureVec::from_slice(&exposed_slice).unwrap();

   secure_slice.unlock_slice(|slice| {
      assert_eq!(slice, exposed_slice);
   });
}

#[test]
fn test_from_secure_array() {
   let exposed: &mut [u8; 3] = &mut [1, 2, 3];
   let array: SecureArray<u8, 3> = SecureArray::from_slice_mut(exposed).unwrap();
   let vec: SecureVec<u8> = array.into();
   assert_eq!(vec.len(), 3);
   vec.unlock_slice(|slice| {
      assert_eq!(slice, &[1, 2, 3]);
   });
}

#[test]
fn test_from_secure_array_generic() {
   let array: SecureArray<u64, 2> = SecureArray::from_slice(&[100u64, 200]).unwrap();
   let vec: SecureVec<u64> = array.into();
   assert_eq!(vec.len(), 2);
   vec.unlock_slice(|slice| {
      assert_eq!(slice, &[100u64, 200]);
   });
}

#[test]
fn test_thread_safety() {
   let vec: Vec<u8> = vec![];
   let secure = SecureVec::from_vec(vec).unwrap();
   let secure = Arc::new(Mutex::new(secure));

   let mut handles = Vec::new();
   for i in 0..5u8 {
      let secure_clone = secure.clone();
      let handle = std::thread::spawn(move || {
         let mut secure = secure_clone.lock().unwrap();
         secure.push(i);
      });
      handles.push(handle);
   }

   for handle in handles {
      handle.join().unwrap();
   }

   let mut sec = secure.lock().unwrap();
   sec.unlock_slice_mut(|slice| {
      slice.sort();
      assert_eq!(slice.len(), 5);
      assert_eq!(slice, &[0, 1, 2, 3, 4]);
   });
}

#[test]
fn test_clone() {
   let vec: Vec<u8> = vec![1, 2, 3];
   let secure1 = SecureVec::from_vec(vec).unwrap();
   let secure2 = secure1.clone();

   secure1.unlock_slice(|slice| {
      secure2.unlock_slice(|slice2| {
         assert_eq!(slice, slice2);
      });
   });
}

#[test]
fn test_do_not_call_forget_on_drain() {
   let vec: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
   let mut secure = SecureVec::from_vec(vec).unwrap();
   let drain = secure.drain(..3);
   core::mem::forget(drain);
   // we can still use secure vec but its state is unreachable
   secure.unlock_slice(|secure| {
      assert_eq!(secure.len(), 0);
   });
}

#[test]
fn test_drain() {
   let vec: Vec<u8> = vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
   let mut secure = SecureVec::from_vec(vec).unwrap();
   let mut drain = secure.drain(..3);
   assert_eq!(drain.next(), Some(1));
   assert_eq!(drain.next(), Some(2));
   assert_eq!(drain.next(), Some(3));
   assert_eq!(drain.next(), None);
   drop(drain);
   secure.unlock_slice(|secure| {
      assert_eq!(secure.len(), 7);
      assert_eq!(secure, &[4, 5, 6, 7, 8, 9, 10]);
   });
}

/// `Drain::compact` must not `T::zeroize` / `drop_in_place` slots after a move.
/// For `String` that aliases the heap the caller now owns.
#[test]
fn test_drain_does_not_zeroize_moved_drop_elements() {
   let mut secure = SecureVec::from_vec(vec![
      "aa".to_owned(),
      "bb".to_owned(),
      "cc".to_owned(),
      "dd".to_owned(),
      "ee".to_owned(),
   ])
   .unwrap();

   let drained: Vec<String> = secure.drain(0..4).collect();

   assert_eq!(drained, ["aa", "bb", "cc", "dd"]);
   secure.unlock_slice(|remaining| {
      assert_eq!(remaining, &["ee".to_owned()]);
   });

   let mut secure = SecureVec::from_vec(vec![
      "aa".to_owned(),
      "bb".to_owned(),
      "cc".to_owned(),
   ])
   .unwrap();
   {
      let mut drain = secure.drain(0..2);
      assert_eq!(drain.next(), Some("aa".to_owned()));
      // `bb` is unyielded and must be dropped, not zeroized-as-T after a move.
   }
   secure.unlock_slice(|remaining| {
      assert_eq!(remaining, &["cc".to_owned()]);
   });
}

#[cfg(feature = "serde")]
#[test]
fn test_secure_vec_serde() {
   let vec: Vec<u8> = vec![1, 2, 3];
   let secure = SecureVec::from_vec(vec).unwrap();
   let json = serde_json::to_vec(&secure).expect("Serialization failed");
   let deserialized: SecureVec<u8> = serde_json::from_slice(&json).expect("Deserialization failed");
   deserialized.unlock_slice(|slice| {
      assert_eq!(slice, &[1, 2, 3]);
   });
}

#[cfg(feature = "serde")]
#[test]
fn test_deserialize_from_owned_byte_buf() {
   use common::OwnedBytes;
   use serde::Deserialize;

   // `visit_byte_buf`: copied into locked memory, then the owned buffer is wiped.
   let secure = SecureVec::<u8>::deserialize(OwnedBytes(vec![1, 2, 3])).unwrap();

   secure.unlock_slice(|slice| assert_eq!(slice, &[1, 2, 3]));
}

#[cfg(feature = "serde")]
#[test]
fn test_deserialize_from_json_string_as_bytes() {
   // `deserialize_bytes` accepts a JSON string, which reaches `visit_bytes`.
   let secure: SecureVec<u8> = serde_json::from_str(r#""abc""#).unwrap();

   secure.unlock_slice(|slice| assert_eq!(slice, b"abc"));
}

#[cfg(feature = "serde")]
#[test]
fn test_deserialize_from_json_array() {
   // The array form still works after switching the request to `deserialize_bytes`.
   let secure: SecureVec<u8> = serde_json::from_str("[1,2,3]").unwrap();

   secure.unlock_slice(|slice| assert_eq!(slice, &[1, 2, 3]));
}

/// A `size_hint` is a hint, not an allocation size. A format that advertises an absurd
/// one must not make us lock that much memory up front.
///
/// Without the cap this fails outright: `usize::MAX` bytes cannot be allocated.
#[cfg(feature = "serde")]
#[test]
fn test_deserialize_does_not_trust_an_absurd_size_hint() {
   use serde::de::IntoDeserializer;

   struct AbsurdHint;

   impl<'de> serde::Deserializer<'de> for AbsurdHint {
      type Error = serde::de::value::Error;

      fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, Self::Error>
      where
         V: serde::de::Visitor<'de>,
      {
         visitor.visit_seq(AbsurdHintSeq { remaining: 3 })
      }

      serde::forward_to_deserialize_any! {
         bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
         bytes byte_buf option unit unit_struct newtype_struct seq tuple
         tuple_struct map struct enum identifier ignored_any
      }
   }

   struct AbsurdHintSeq {
      remaining: usize,
   }

   impl<'de> serde::de::SeqAccess<'de> for AbsurdHintSeq {
      type Error = serde::de::value::Error;

      fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, Self::Error>
      where
         T: serde::de::DeserializeSeed<'de>,
      {
         if self.remaining == 0 {
            return Ok(None);
         }
         self.remaining -= 1;

         seed.deserialize(1u8.into_deserializer()).map(Some)
      }

      fn size_hint(&self) -> Option<usize> {
         Some(usize::MAX)
      }
   }

   let decoded = <SecureVec<u8> as serde::Deserialize>::deserialize(AbsurdHint).unwrap();

   decoded.unlock(|vec| {
      assert!(
         vec.capacity() <= MAX_PREALLOCATION_FROM_SIZE_HINT,
         "reserved {} bytes from a size hint",
         vec.capacity()
      );
   });
   decoded.unlock_slice(|bytes| assert_eq!(bytes, &[1, 1, 1]));
}

/// The `u8` impls ask for a byte buffer; the generic ones ask for a sequence. A format
/// that offers *only* `deserialize_bytes` is the cheapest way to prove the byte fast path
/// is still wired up — the two are otherwise indistinguishable, because a `u8` sequence
/// encodes to the very same bytes.
#[cfg(feature = "serde")]
#[test]
fn test_byte_containers_still_use_the_byte_buffer_request() {
   struct BytesOnly;

   impl<'de> serde::Deserializer<'de> for BytesOnly {
      type Error = serde::de::value::Error;

      fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value, Self::Error>
      where
         V: serde::de::Visitor<'de>,
      {
         Err(serde::de::Error::custom(
            "only bytes are supported",
         ))
      }

      fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, Self::Error>
      where
         V: serde::de::Visitor<'de>,
      {
         visitor.visit_bytes(&[1, 2, 3])
      }

      // `bytes` is deliberately absent: it is implemented above, and every other
      // request falls through to the error.
      serde::forward_to_deserialize_any! {
         bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
         byte_buf option unit unit_struct newtype_struct seq tuple
         tuple_struct map struct enum identifier ignored_any
      }
   }

   let bytes = <SecureVec<u8> as serde::Deserialize>::deserialize(BytesOnly).unwrap();
   bytes.unlock_slice(|slice| assert_eq!(slice, &[1, 2, 3]));

   // A non-byte container must not be taking that path.
   assert!(<SecureVec<u16> as serde::Deserialize>::deserialize(BytesOnly).is_err());
}

/// Non-byte elements go out as a sequence of values.
#[cfg(feature = "serde")]
#[test]
fn test_non_byte_elements_serialize_as_a_sequence() {
   let words = SecureVec::from_slice(&[0x0102u16, 0x0304]).unwrap();
   assert_eq!(
      serde_json::to_string(&words).unwrap(),
      "[258,772]"
   );

   let back: SecureVec<u16> = serde_json::from_str("[258,772]").unwrap();
   back.unlock_slice(|slice| assert_eq!(slice, &[0x0102u16, 0x0304]));

   let flags = SecureVec::from_slice(&[true, false]).unwrap();
   assert_eq!(
      serde_json::to_string(&flags).unwrap(),
      "[true,false]"
   );

   let letters = SecureVec::from_slice(&['a', 'β']).unwrap();
   assert_eq!(
      serde_json::to_string(&letters).unwrap(),
      "[\"a\",\"β\"]"
   );

   let signed = SecureVec::from_slice(&[-1i32, i32::MIN]).unwrap();
   assert_eq!(
      serde_json::to_string(&signed).unwrap(),
      format!("[-1,{}]", i32::MIN)
   );
}

#[test]
fn test_erase() {
   let mut secure = SecureVec::new_with_capacity(10).unwrap();
   for i in 0..9 {
      secure.push(i);
   }

   secure.erase();

   secure.unlock(|secure| {
      assert_eq!(secure.len(), 0);
      assert_eq!(secure.capacity(), 10);
   });

   // `len == 0`, so `unlock_iter` cannot observe the wipe. Pushing again
   // must not see leftover plaintext in the reused slots.
   for i in 0..3 {
      secure.push(i);
   }
   secure.unlock_slice(|slice| assert_eq!(slice, &[0, 1, 2]));
}

#[test]
fn test_push() {
   let vec: Vec<u8> = Vec::new();
   let mut secure = SecureVec::from_vec(vec).unwrap();
   for i in 0..10 {
      secure.push(i);
   }

   assert_eq!(secure.len(), 10);

   secure.unlock_slice(|slice| {
      assert_eq!(slice, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
   });
}

#[test]
fn test_reserve() {
   let mut secure: SecureVec<u8> = SecureVec::new().unwrap();
   secure.reserve(10);
   assert_eq!(secure.capacity(), 10);
}

#[test]
fn test_reserve_doubling() {
   let mut secure: SecureVec<u8> = SecureVec::new().unwrap();
   secure.reserve(10);

   for i in 0..9 {
      secure.push(i);
   }

   secure.push(9);
   assert_eq!(secure.capacity(), 10);
   assert_eq!(secure.len(), 10);

   secure.push(10);
   assert_eq!(secure.capacity(), 20);
   assert_eq!(secure.len(), 11);
}

#[test]
#[should_panic(expected = "reserve overflow")]
fn test_reserve_overflow_panics() {
   let mut secure: SecureVec<u8> = SecureVec::new().unwrap();
   secure.push(1);

   // `len + additional` overflows `usize`: the documented panic must happen
   // in release too, instead of silently returning without growing.
   secure.reserve(usize::MAX);
}

#[test]
fn test_unlock_gives_access() {
   let vec: Vec<u8> = vec![1, 2, 3];
   let secure = SecureVec::from_vec(vec).unwrap();
   secure.unlock_slice(|slice| {
      assert_eq!(slice[0], 1);
      assert_eq!(slice[1], 2);
      assert_eq!(slice[2], 3);
   });
}

#[test]
fn test_unlock_slice() {
   let vec: Vec<u8> = vec![1, 2, 3];
   let secure = SecureVec::from_vec(vec).unwrap();
   secure.unlock_slice(|slice| {
      assert_eq!(slice, &[1, 2, 3]);
   });
}

#[test]
fn test_unlock_slice_mut() {
   let vec: Vec<u8> = vec![1, 2, 3];
   let mut secure = SecureVec::from_vec(vec).unwrap();

   secure.unlock_slice_mut(|slice| {
      slice[0] = 4;
      assert_eq!(slice, &mut [4, 2, 3]);
   });
}

#[test]
fn test_unlock_iter() {
   let vec: Vec<u8> = vec![1, 2, 3];
   let secure = SecureVec::from_vec(vec).unwrap();
   let sum: u8 = secure.unlock_iter(|iter| iter.copied().sum());

   assert_eq!(sum, 6);

   let secure: SecureVec<u8> = SecureVec::new_with_capacity(3).unwrap();
   let sum: u8 = secure.unlock_iter(|iter| iter.copied().sum());

   assert_eq!(sum, 0);
}

#[test]
fn test_unlock_iter_mut() {
   let vec: Vec<u8> = vec![1, 2, 3];
   let mut secure = SecureVec::from_vec(vec).unwrap();
   secure.unlock_iter_mut(|iter| {
      for elem in iter {
         *elem += 1;
      }
   });

   secure.unlock_slice(|slice| {
      assert_eq!(slice, &[2, 3, 4]);
   });
}

#[test]
fn test_vec_u8_variety() {
   let data: Vec<u8> = vec![1, 2, 3, 4, 5];
   test_vec_generic_basics(&data);
}

#[test]
fn test_vec_u16() {
   let data: Vec<u16> = vec![1000, 2000, 3000];
   test_vec_generic_basics(&data);
}

#[test]
fn test_vec_u64() {
   let data: Vec<u64> = vec![0xDEADBEEF_CAFEBABE, 1, 2, 3, 4];
   test_vec_generic_basics(&data);
}

#[test]
fn test_vec_byte_array() {
   let data: Vec<[u8; 32]> = vec![[0xAB; 32], [0xCD; 32]];
   test_vec_generic_basics(&data);
}

#[test]
fn test_vec_small_struct() {
   let data = vec![
      SmallStruct { a: 10, b: 20 },
      SmallStruct { a: 30, b: 40 },
      SmallStruct { a: 50, b: 60 },
   ];
   test_vec_generic_basics(&data);
}

#[test]
fn test_vec_large_struct() {
   let data = vec![
      LargeStruct {
         data: [1, 2, 3, 4],
         flag: true,
      },
      LargeStruct {
         data: [10, 20, 30, 40],
         flag: false,
      },
   ];
   test_vec_generic_basics(&data);
}

#[test]
fn test_vec_person() {
   let data = vec![
      create_test_person(1),
      create_test_person(42),
      create_test_person(99),
   ];
   // test push which triggers reserve for > initial cap
   let mut pvec = SecureVec::new().unwrap();
   for p in &data {
      pvec.push(p.clone());
   }
   pvec.unlock_slice(|slice| {
      assert_eq!(slice.len(), 3);
      assert_eq!(slice[0].name, "Person1");
      assert_eq!(slice[2].notes, "Some secret notes for person #99");
   });
   println!("person push+realloc ok");
}

#[test]
fn test_vec_aligned_struct() {
   let data = vec![
      AlignedStruct {
         value: 0x1234_5678_9ABC_DEF0,
      },
      AlignedStruct { value: 42 },
   ];
   test_vec_generic_basics(&data);
}

#[test]
fn test_vec_mixed_sizes() {
   // Push many to force multiple reallocs with larger type
   let mut vec: SecureVec<u64> = SecureVec::new().unwrap();
   for i in 0..20u64 {
      vec.push(i * 1000);
   }
   vec.unlock_slice(|slice| {
      assert_eq!(slice.len(), 20);
      assert_eq!(slice[0], 0);
      assert_eq!(slice[19], 19000);
   });
}

// Test helper types for variety (different sizes, alignments, complex data)

#[derive(Clone, Debug, PartialEq)]
struct SmallStruct {
   a: u8,
   b: u16,
}

impl Zeroize for SmallStruct {
   fn zeroize(&mut self) {
      self.a.zeroize();
      self.b.zeroize();
   }
}

#[derive(Clone, Debug, PartialEq)]
struct LargeStruct {
   data: [u64; 4],
   flag: bool,
}

impl Zeroize for LargeStruct {
   fn zeroize(&mut self) {
      self.data.zeroize();
      self.flag.zeroize();
   }
}

#[derive(Clone, Debug, PartialEq)]
#[repr(align(64))]
struct AlignedStruct {
   value: u64,
}

impl Zeroize for AlignedStruct {
   fn zeroize(&mut self) {
      self.value.zeroize();
   }
}

#[derive(Clone, Debug, PartialEq)]
struct Person {
   name: String,
   age: u32,
   notes: String,
}

impl Zeroize for Person {
   fn zeroize(&mut self) {
      self.name.zeroize();
      self.age.zeroize();
      self.notes.zeroize();
   }
}

impl Person {
   fn new(name: impl Into<String>, age: u32, notes: impl Into<String>) -> Self {
      Self {
         name: name.into(),
         age,
         notes: notes.into(),
      }
   }
}

fn create_test_person(id: usize) -> Person {
   Person::new(
      format!("Person{}", id),
      (id % 100) as u32,
      format!("Some secret notes for person #{}", id),
   )
}

fn test_vec_generic_basics<T: Zeroize + Clone + PartialEq + Debug>(initial: &[T]) {
   if initial.is_empty() {
      return;
   }

   // from_slice
   let secure = SecureVec::from_slice(initial).unwrap();
   assert_eq!(secure.len(), initial.len());
   secure.unlock_slice(|slice| {
      assert_eq!(slice, initial);
   });

   // new + push
   let mut secure_push = SecureVec::new().unwrap();
   for item in initial {
      secure_push.push(item.clone());
   }
   secure_push.unlock_slice(|slice| {
      assert_eq!(slice, initial);
   });

   // clone
   let cloned = secure.clone();
   secure.unlock_slice(|s| {
      cloned.unlock_slice(|c| {
         assert_eq!(s, c);
      });
   });

   // reserve + push more
   let mut res = SecureVec::new().unwrap();
   res.reserve(initial.len() + 2);
   for item in initial {
      res.push(item.clone());
   }
   assert!(res.capacity() >= initial.len() + 2 || res.capacity() >= initial.len());
   res.unlock_slice(|slice| {
      assert_eq!(slice, initial);
   });

   // erase
   res.erase();
   res.unlock(|v| {
      assert_eq!(v.len(), 0);
      // capacity should be preserved
      assert!(v.capacity() > 0);
   });

   // from_vec
   let vec_data: Vec<T> = initial.to_vec();
   let from_vec_secure = SecureVec::from_vec(vec_data).unwrap();
   from_vec_secure.unlock_slice(|slice| {
      assert_eq!(slice, initial);
   });
}
