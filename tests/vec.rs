//! `SecureVec` / `SecureBytes`, exercised through the public API.

#![cfg(feature = "use_os")]

#[cfg(feature = "serde")]
mod common;

use std::fmt::Debug;
use std::mem::{ManuallyDrop, needs_drop};
#[cfg(target_os = "linux")]
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
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
   // A forgotten `Drain` never runs `compact`, so `len` stays at the drain start
   // and the drained elements are leaked rather than dropped. The vector is also
   // left locked — `test_forgotten_drain_keeps_memory_locked` pins that.
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
   // `reserve` was asked for room for `initial.len() + 2`, so the capacity must
   // still cover that after every element has been pushed.
   assert!(res.capacity() >= initial.len() + 2);
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

/// Counts every `Tracked::clone` call, so the clone bomb can fire mid-loop.
static CLONES: AtomicUsize = AtomicUsize::new(0);

/// Counts every `Tracked::zeroize` call.
static ZEROIZED: AtomicUsize = AtomicUsize::new(0);

/// Counts every `Tracked::drop` call.
static DROPPED: AtomicUsize = AtomicUsize::new(0);

/// Owns a `String` like a real secret does, but panics on its second clone.
#[derive(Debug)]
struct Tracked(String);

impl Tracked {
   fn new(data: impl Into<String>) -> Self {
      Tracked(data.into())
   }
}

impl Clone for Tracked {
   fn clone(&self) -> Self {
      if CLONES.fetch_add(1, Ordering::SeqCst) == 1 {
         panic!("clone bomb");
      }

      Tracked::new(self.0.clone())
   }
}

impl Zeroize for Tracked {
   fn zeroize(&mut self) {
      ZEROIZED.fetch_add(1, Ordering::SeqCst);
      self.0.zeroize();
   }
}

impl Drop for Tracked {
   fn drop(&mut self) {
      DROPPED.fetch_add(1, Ordering::SeqCst);
   }
}

fn reset_clone_counters() {
   CLONES.store(0, Ordering::SeqCst);
   ZEROIZED.store(0, Ordering::SeqCst);
   DROPPED.store(0, Ordering::SeqCst);
}

/// A panic from `T::clone` mid-loop must zeroize and drop the elements already
/// written instead of leaking them: their heap payloads (a `String`'s buffer)
/// would otherwise outlive the container un-zeroized.
///
/// The bomb fires on the second clone, so exactly one element reached a slot.
#[test]
fn test_init_from_clone_panic_zeroizes_written_prefix() {
   reset_clone_counters();

   let source = vec![Tracked::new("a"), Tracked::new("b"), Tracked::new("c")];
   let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      SecureVec::<Tracked>::from_slice(&source)
   }));

   assert!(
      result.is_err(),
      "the clone bomb must make `SecureVec::from_slice` unwind"
   );
   assert_eq!(
      ZEROIZED.load(Ordering::SeqCst),
      1,
      "the element written before the panic must be zeroized"
   );
   assert_eq!(
      DROPPED.load(Ordering::SeqCst),
      1,
      "the element written before the panic must be dropped"
   );
}

/// `from_slice_mut` promises to zeroize the caller's slice, so its wipe cannot sit
/// after the copy loop: a `T::clone` that panics unwinds straight past it.
///
/// The bound is `T: Clone + DefaultIsZeroes`, i.e. `Copy`, so a hand-written
/// panicking `Clone` is the only way into this path — and it is exactly the path
/// that used to leave the caller's buffer untouched.
#[test]
fn test_from_slice_mut_wipes_the_source_when_a_clone_panics() {
   #[derive(Copy, Debug, Default, PartialEq)]
   struct CopyBomb(u8);

   // Intentionally non-canonical: a `Copy` type whose `Clone` panics is the only
   // way to reach this path without an owning element type.
   #[allow(clippy::non_canonical_clone_impl)]
   impl Clone for CopyBomb {
      fn clone(&self) -> Self {
         panic!("clone bomb");
      }
   }

   impl zeroize::DefaultIsZeroes for CopyBomb {}

   let mut source = [CopyBomb(17), CopyBomb(34)];

   let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      SecureVec::<CopyBomb>::from_slice_mut(&mut source)
   }));

   assert!(
      result.is_err(),
      "the clone bomb must make `SecureVec::from_slice_mut` unwind"
   );
   assert_eq!(
      source,
      [CopyBomb(0), CopyBomb(0)],
      "the source buffer must be wiped even when `T::clone` panics"
   );
}

/// Counts the `/secretmem` mappings the process holds.
///
/// A `memfd_secret` region is the only thing a leaked secure allocation leaves behind
/// (the malloc fallback is ordinary heap), so the count is the observable.
#[cfg(target_os = "linux")]
fn secretmem_mappings() -> usize {
   std::fs::read_to_string("/proc/self/maps")
      .map(|maps| {
         maps
            .lines()
            .filter(|line| line.contains("secretmem"))
            .count()
      })
      .unwrap_or(0)
}

/// A `T` whose destructor panics, holding a payload that must not outlive the vector.
struct PanicOnDrop {
   payload: String,
   boom: bool,
}

impl Zeroize for PanicOnDrop {
   fn zeroize(&mut self) {
      self.payload.zeroize();
   }
}

impl Drop for PanicOnDrop {
   fn drop(&mut self) {
      if self.boom {
         panic!("element destructor panics");
      }
   }
}

/// A panicking element destructor must still release the region.
///
/// `Drop` used to release the allocation *after* the element loop, so the unwind
/// skipped it: the `memfd_secret` region stayed mapped — `rw-s`, outside any
/// `unlock*` scope — with the plaintext of the elements the loop never reached still
/// readable. A child process is the repro because a leaked region is observable only
/// as a mapping-count difference, and because reading the plaintext back is exactly
/// what must no longer be possible.
#[cfg(target_os = "linux")]
#[test]
fn test_a_panicking_destructor_still_frees_the_region() {
   const CHILD: &str = "ST_PANICKING_DESTRUCTOR_REGION";

   if std::env::args().any(|arg| arg == CHILD) {
      if !secure_types::supports_memfd_secret() {
         std::process::exit(77);
      }

      // The destructor's panic is this test's input, not a failure.
      std::panic::set_hook(Box::new(|_| {}));

      let before = secretmem_mappings();

      let mut vec: SecureVec<PanicOnDrop> = SecureVec::new_with_capacity(2).unwrap();
      vec.push(PanicOnDrop {
         payload: "SECRET-ONE".to_owned(),
         boom: true,
      });
      vec.push(PanicOnDrop {
         payload: "SECRET-TWO".to_owned(),
         boom: false,
      });

      let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(vec))).is_err();
      let after = secretmem_mappings();

      std::process::exit(if panicked && after <= before { 0 } else { 3 });
   }

   let child = Command::new(std::env::current_exe().unwrap())
      .arg("test_a_panicking_destructor_still_frees_the_region")
      .arg(CHILD)
      .arg("--nocapture")
      .stdout(Stdio::piped())
      .stderr(Stdio::piped())
      .spawn()
      .expect("Failed to spawn child process");

   let output = child.wait_with_output().expect("Failed to wait on child");

   if output.status.code() == Some(77) {
      eprintln!("skipping: memfd_secret is unavailable on this kernel");
      return;
   }

   assert!(
      output.status.success(),
      "a panicking element destructor must still release the region, but the child exited with {:?}",
      output.status
   );
}

static CLEAR_ZEROIZED: AtomicUsize = AtomicUsize::new(0);
static CLEAR_DROPPED: AtomicUsize = AtomicUsize::new(0);

/// A `T` that records both halves of the discard lifecycle and panics once.
struct ClearBomb {
   index: usize,
}

impl Zeroize for ClearBomb {
   fn zeroize(&mut self) {
      CLEAR_ZEROIZED.fetch_add(1, Ordering::SeqCst);
   }
}

impl Drop for ClearBomb {
   fn drop(&mut self) {
      CLEAR_DROPPED.fetch_add(1, Ordering::SeqCst);

      if self.index == 1 {
         panic!("element destructor panics");
      }
   }
}

/// `clear` must discard the elements it has not reached yet when a destructor panics.
///
/// The length is reset before the loop, so an unwound `clear` leaves the vector
/// claiming nothing. Without a guard the untouched elements would be neither zeroized
/// nor dropped, and the buffers they own would keep their plaintext forever.
#[test]
fn test_clear_discards_the_rest_when_a_destructor_panics() {
   CLEAR_ZEROIZED.store(0, Ordering::SeqCst);
   CLEAR_DROPPED.store(0, Ordering::SeqCst);

   let mut vec: SecureVec<ClearBomb> = SecureVec::new_with_capacity(3).unwrap();

   for index in 0..3 {
      vec.push(ClearBomb { index });
   }

   let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| vec.clear())).is_err();

   assert!(panicked, "the destructor was supposed to panic");
   assert_eq!(
      CLEAR_ZEROIZED.load(Ordering::SeqCst),
      3,
      "every element must be zeroized, including the ones the panic skipped"
   );
   assert_eq!(
      CLEAR_DROPPED.load(Ordering::SeqCst),
      3,
      "every element must be dropped, including the ones the panic skipped"
   );
}

static DRAIN_ZEROIZED: AtomicUsize = AtomicUsize::new(0);
static DRAIN_DROPPED: AtomicUsize = AtomicUsize::new(0);

/// A `T` that records both halves of the discard lifecycle and panics once.
struct DrainBomb {
   index: usize,
}

impl Zeroize for DrainBomb {
   fn zeroize(&mut self) {
      DRAIN_ZEROIZED.fetch_add(1, Ordering::SeqCst);
   }
}

impl Drop for DrainBomb {
   fn drop(&mut self) {
      DRAIN_DROPPED.fetch_add(1, Ordering::SeqCst);

      if self.index == 1 {
         panic!("element destructor panics");
      }
   }
}

/// `Drain::compact` must discard the unyielded elements a panic skips.
///
/// `drain` lowers the length before anything is compacted, so an unwound `Drop` leaves
/// those elements outside it: nothing else would ever zeroize or drop them.
#[test]
fn test_drain_discards_the_rest_when_a_destructor_panics() {
   DRAIN_ZEROIZED.store(0, Ordering::SeqCst);
   DRAIN_DROPPED.store(0, Ordering::SeqCst);

   let mut vec: SecureVec<DrainBomb> = SecureVec::new_with_capacity(3).unwrap();

   for index in 0..3 {
      vec.push(DrainBomb { index });
   }

   let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      drop(vec.drain(0..3));
   }))
   .is_err();

   assert!(panicked, "the destructor was supposed to panic");
   assert_eq!(
      DRAIN_ZEROIZED.load(Ordering::SeqCst),
      3,
      "every unyielded element must be zeroized, including the ones the panic skipped"
   );
   assert_eq!(
      DRAIN_DROPPED.load(Ordering::SeqCst),
      3,
      "every unyielded element must be dropped, including the ones the panic skipped"
   );
}

/// `Drain::compact` must also discard the tail it has not moved yet when the discard
/// loop panics: the copy to the front has not run, so nobody else owns those elements.
///
/// Without a guard the tail's destructor never ran and the buffers it owned kept their
/// plaintext forever — a drain range in front of the tail was enough to trigger it.
#[test]
fn test_drain_discards_the_tail_when_a_destructor_panics() {
   DRAIN_ZEROIZED.store(0, Ordering::SeqCst);
   DRAIN_DROPPED.store(0, Ordering::SeqCst);

   let mut vec: SecureVec<DrainBomb> = SecureVec::new_with_capacity(4).unwrap();

   for index in 0..4 {
      vec.push(DrainBomb { index });
   }

   // Elements 0..2 stay unyielded and element 1's destructor panics; elements 2..4
   // are the tail the compaction had not moved down yet.
   let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      drop(vec.drain(0..2));
   }))
   .is_err();

   assert!(panicked, "the destructor was supposed to panic");
   assert_eq!(
      vec.len(),
      0,
      "the length stays at the drain start"
   );
   assert_eq!(
      DRAIN_ZEROIZED.load(Ordering::SeqCst),
      4,
      "the unyielded range and the tail must both be zeroized"
   );
   assert_eq!(
      DRAIN_DROPPED.load(Ordering::SeqCst),
      4,
      "the unyielded range and the tail must both be dropped"
   );
}

static DROP_ZEROIZED: AtomicUsize = AtomicUsize::new(0);
static DROP_DROPPED: AtomicUsize = AtomicUsize::new(0);

/// A T that records both halves of the discard lifecycle and panics once.
struct DropBomb {
   index: usize,
}

impl Zeroize for DropBomb {
   fn zeroize(&mut self) {
      DROP_ZEROIZED.fetch_add(1, Ordering::SeqCst);
   }
}

impl Drop for DropBomb {
   fn drop(&mut self) {
      DROP_DROPPED.fetch_add(1, Ordering::SeqCst);

      if self.index == 1 {
         panic!("element destructor panics");
      }
   }
}

/// Drop must discard the elements it has not reached when a destructor panics.
///
/// The forward loop used to stop at the panicking element: every later slot was
/// neither zeroized nor dropped, so a String/Vec it owned was freed with its
/// plaintext still in it. The free guard only released the secure region.
#[test]
fn test_drop_discards_the_rest_when_a_destructor_panics() {
   DROP_ZEROIZED.store(0, Ordering::SeqCst);
   DROP_DROPPED.store(0, Ordering::SeqCst);

   let mut vec: SecureVec<DropBomb> = SecureVec::new_with_capacity(3).unwrap();

   for index in 0..3 {
      vec.push(DropBomb { index });
   }

   let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(vec))).is_err();

   assert!(panicked, "the destructor was supposed to panic");
   assert_eq!(
      DROP_ZEROIZED.load(Ordering::SeqCst),
      3,
      "every element must be zeroized, including the ones the panic skipped"
   );
   assert_eq!(
      DROP_DROPPED.load(Ordering::SeqCst),
      3,
      "every element must be dropped, including the ones the panic skipped"
   );
}

static NON_DROP_ZEROIZED: AtomicUsize = AtomicUsize::new(0);

/// A `T` with no destructor that still owns a heap buffer.
///
/// The buffer hides behind `ManuallyDrop`, so `needs_drop` reports `false` for the
/// element and only `Zeroize` can wipe it: a discard path that gates on `needs_drop`
/// skips it silently, and the wipe a `Zeroize` impl performs outside the element's own
/// bytes never happens.
struct NonDropSecret {
   data: ManuallyDrop<Box<[u8]>>,
   zeroized: bool,
}

impl NonDropSecret {
   fn new(data: Box<[u8]>) -> Self {
      Self {
         data: ManuallyDrop::new(data),
         zeroized: false,
      }
   }
}

impl Zeroize for NonDropSecret {
   fn zeroize(&mut self) {
      // Guarded so a second call is a no-op: the counter counts elements, not calls.
      if self.zeroized {
         return;
      }

      self.zeroized = true;

      self.data[..].zeroize();
      NON_DROP_ZEROIZED.fetch_add(1, Ordering::SeqCst);
   }
}

/// `Drain::compact` must zeroize the elements it discards for every `T`, not only for
/// the `needs_drop` ones: a `Zeroize` impl may wipe memory outside the element's own
/// bytes, and `clear` / `Drop` zeroize unconditionally.
#[test]
fn test_drain_zeroizes_discarded_non_drop_elements() {
   NON_DROP_ZEROIZED.store(0, Ordering::SeqCst);

   assert!(
      !needs_drop::<NonDropSecret>(),
      "the element type must have no destructor for this test to mean anything"
   );

   let mut secure: SecureVec<NonDropSecret> = SecureVec::new_with_capacity(4).unwrap();

   for value in 0..4u8 {
      let secret = NonDropSecret::new(vec![value; 8].into_boxed_slice());
      secure.push(secret);
   }

   // Never iterated, so dropping the iterator is the only path that can discard them.
   let drain = secure.drain(0..2);
   drop(drain);

   assert_eq!(secure.len(), 2);
   assert_eq!(
      NON_DROP_ZEROIZED.load(Ordering::SeqCst),
      2,
      "every unyielded drain-range element must be zeroized"
   );

   secure.clear();

   assert_eq!(
      NON_DROP_ZEROIZED.load(Ordering::SeqCst),
      4,
      "clear must zeroize the remaining elements too"
   );
}

/// `from_slice_mut` wipes its source through `SourceWipe`, which needs `Zeroize` and
/// nothing more: a non-`Copy` type must be accepted without `DefaultIsZeroes`.
#[test]
fn test_from_slice_mut_accepts_non_copy_zeroize_types() {
   let mut source = [String::from("first"), String::from("second")];

   let secure = SecureVec::from_slice_mut(&mut source).unwrap();

   secure.unlock_slice(|values| {
      assert_eq!(values, &["first", "second"]);
   });
   assert_eq!(
      source,
      ["", ""],
      "the source strings must be wiped"
   );
}
