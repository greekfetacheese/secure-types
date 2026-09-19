//! `SecureArray`, exercised through the public API.

#![cfg(feature = "use_os")]

#[cfg(feature = "serde")]
mod common;

use std::fmt::Debug;
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use secure_types::{Error, SecureArray, SecureVec, Zeroize};

#[test]
fn test_creation() {
   let exposed_mut = &mut [1, 2, 3];
   let array: SecureArray<u8, 3> = SecureArray::from_slice_mut(exposed_mut).unwrap();
   assert_eq!(array.len(), 3);

   array.unlock(|slice| {
      assert_eq!(slice, &[1, 2, 3]);
   });

   assert_eq!(exposed_mut, &[0u8; 3]);

   let exposed = &[1, 2, 3];
   let array: SecureArray<u8, 3> = SecureArray::from_slice(exposed).unwrap();
   assert_eq!(array.len(), 3);

   array.unlock(|slice| {
      assert_eq!(slice, &[1, 2, 3]);
   });

   assert_eq!(exposed, &[1, 2, 3]);
}

#[test]
fn test_from_secure_vec() {
   let vec: SecureVec<u8> = SecureVec::from_slice(&[1, 2, 3]).unwrap();
   let array: SecureArray<u8, 3> = vec.try_into().unwrap();
   assert_eq!(array.len(), 3);
   array.unlock(|slice| {
      assert_eq!(slice, &[1, 2, 3]);
   });
}

#[test]
fn test_from_vec() {
   let vec = vec![1u8, 2, 3];
   let array: SecureArray<u8, 3> = SecureArray::try_from(vec).unwrap();
   assert_eq!(array.len(), 3);
   array.unlock(|slice| {
      assert_eq!(slice, &[1, 2, 3]);
   });
}

#[test]
fn test_from_secure_vec_generic() {
   let vec: SecureVec<u64> = SecureVec::from_slice(&[100u64, 200]).unwrap();
   let array: SecureArray<u64, 2> = vec.try_into().unwrap();
   array.unlock(|slice| {
      assert_eq!(slice, &[100u64, 200]);
   });
}

#[test]
fn test_try_from_length_mismatch() {
   let vec: SecureVec<u8> = SecureVec::from_slice(&[1, 2, 3]).unwrap();
   let result: Result<SecureArray<u8, 4>, _> = SecureArray::try_from(vec);
   assert!(matches!(result, Err(Error::LengthMismatch)));

   let result: Result<SecureArray<u8, 2>, _> = SecureArray::try_from(vec![1u8, 2, 3]);
   assert!(matches!(result, Err(Error::LengthMismatch)));
}

/// Regression test: dropping an array that was never initialized must not
/// interpret the allocator's poison bytes as a `T`.
#[test]
fn test_drop_without_initialization_is_sound() {
   let arg = "CRASH_TEST_ARRAY_EMPTY_DROP";

   if std::env::args().any(|a| a == arg) {
      // `String` owns a pointer, so zeroizing an uninitialized slot as a
      // `String` would dereference the allocator's poison bytes.
      let array: SecureArray<String, 4> = SecureArray::empty().unwrap();
      drop(array);
      std::process::exit(0);
   }

   let child = Command::new(std::env::current_exe().unwrap())
      .arg("test_drop_without_initialization_is_sound")
      .arg(arg)
      .arg("--nocapture")
      .stdout(Stdio::piped())
      .stderr(Stdio::piped())
      .spawn()
      .expect("Failed to spawn child process");

   let output = child.wait_with_output().expect("Failed to wait on child");

   assert!(
      output.status.success(),
      "Dropping a never-initialized SecureArray must be sound, but the child terminated with {:?}",
      output.status
   );
}

/// Regression test: a panic while filling the array must only leave the
/// already-written elements to be zeroized by `drop`.
#[test]
fn test_panic_during_partial_init_is_sound() {
   let arg = "CRASH_TEST_ARRAY_PANIC_INIT";

   if std::env::args().any(|a| a == arg) {
      let panicked = std::panic::catch_unwind(|| {
         let content: [PanicOnClone; 3] = [
            PanicOnClone::new("a"),
            PanicOnClone::new("b"),
            PanicOnClone::new("c"),
         ];
         let _array = SecureArray::<PanicOnClone, 3>::from_slice(&content).unwrap();
      })
      .is_err();

      std::process::exit(if panicked { 0 } else { 1 });
   }

   let child = Command::new(std::env::current_exe().unwrap())
      .arg("test_panic_during_partial_init_is_sound")
      .arg(arg)
      .arg("--nocapture")
      .stdout(Stdio::piped())
      .stderr(Stdio::piped())
      .spawn()
      .expect("Failed to spawn child process");

   let output = child.wait_with_output().expect("Failed to wait on child");

   assert!(
      output.status.success(),
      "A panic during partial initialization must be sound, but the child terminated with {:?}",
      output.status
   );
}

#[test]
fn test_erase() {
   let exposed: &mut [u8; 3] = &mut [1, 2, 3];
   let mut array: SecureArray<u8, 3> = SecureArray::from_slice_mut(exposed).unwrap();
   array.erase();
   array.unlock(|slice| {
      assert_eq!(slice, &[0u8; 3]);
   });
}

#[test]
#[should_panic]
fn test_length_cannot_be_zero() {
   let secure_vec = SecureVec::new().unwrap();
   let _secure_array: SecureArray<u8, 0> = SecureArray::try_from(secure_vec).unwrap();
}

#[test]
fn test_clone() {
   let mut array1: SecureArray<u8, 3> = SecureArray::empty().unwrap();
   array1.unlock_mut(|slice| {
      slice[0] = 1;
      slice[1] = 2;
      slice[2] = 3;
   });

   let array2 = array1.clone();

   array2.unlock(|slice| {
      assert_eq!(slice, &[1, 2, 3]);
   });

   array1.unlock(|slice| {
      assert_eq!(slice, &[1, 2, 3]);
   });
}

#[test]
fn test_thread_safety() {
   let exposed: &mut [u8; 3] = &mut [1, 2, 3];
   let array: SecureArray<u8, 3> = SecureArray::from_slice_mut(exposed).unwrap();
   let arc_array = Arc::new(Mutex::new(array));
   let mut handles = Vec::new();

   for _ in 0..5u8 {
      let array_clone = Arc::clone(&arc_array);
      let handle = std::thread::spawn(move || {
         let mut guard = array_clone.lock().unwrap();
         guard.unlock_mut(|slice| {
            slice[0] += 1;
         });
      });
      handles.push(handle);
   }

   for handle in handles {
      handle.join().unwrap();
   }

   let final_array = arc_array.lock().unwrap();
   final_array.unlock(|slice| {
      assert_eq!(slice[0], 6);
      assert_eq!(slice[1], 2);
      assert_eq!(slice[2], 3);
   });
}

#[test]
fn test_unlock_mut() {
   let exposed: &mut [u8; 3] = &mut [1, 2, 3];
   let mut array: SecureArray<u8, 3> = SecureArray::from_slice_mut(exposed).unwrap();

   array.unlock_mut(|slice| {
      slice[1] = 100;
   });

   array.unlock(|slice| {
      assert_eq!(slice, &[1, 100, 3]);
   });
}

#[cfg(feature = "serde")]
#[test]
fn test_serde() {
   let exposed: &mut [u8; 3] = &mut [1, 2, 3];
   let array: SecureArray<u8, 3> = SecureArray::from_slice_mut(exposed).unwrap();
   let json_string = serde_json::to_string(&array).expect("Serialization failed");
   let json_bytes = serde_json::to_vec(&array).expect("Serialization failed");

   let deserialized_string: SecureArray<u8, 3> =
      serde_json::from_str(&json_string).expect("Deserialization failed");

   let deserialized_bytes: SecureArray<u8, 3> =
      serde_json::from_slice(&json_bytes).expect("Deserialization failed");

   deserialized_string.unlock(|slice| {
      assert_eq!(slice, &[1, 2, 3]);
   });

   deserialized_bytes.unlock(|slice| {
      assert_eq!(slice, &[1, 2, 3]);
   });
}

#[cfg(feature = "serde")]
#[test]
fn test_deserialize_from_owned_byte_buf() {
   use common::OwnedBytes;
   use serde::Deserialize;

   // `visit_byte_buf`: copied into locked memory, then the owned buffer is wiped.
   let array = SecureArray::<u8, 3>::deserialize(OwnedBytes(vec![1, 2, 3])).unwrap();

   array.unlock(|slice| assert_eq!(slice, &[1, 2, 3]));

   // Wrong length still has to return an error. The owned buffer is wiped on
   // this path too; that wipe is not observable without reading freed memory.
   assert!(SecureArray::<u8, 3>::deserialize(OwnedBytes(vec![1, 2])).is_err());
}

#[cfg(feature = "serde")]
#[test]
fn test_deserialize_from_json_string_as_bytes() {
   // `deserialize_bytes` accepts a JSON string, which reaches `visit_bytes`.
   let array: SecureArray<u8, 3> = serde_json::from_str(r#""abc""#).unwrap();

   array.unlock(|slice| assert_eq!(slice, b"abc"));
}

#[cfg(feature = "serde")]
#[test]
fn test_deserialize_rejects_wrong_length() {
   let from_bytes: Result<SecureArray<u8, 3>, _> = serde_json::from_str(r#""abcd""#);
   assert!(from_bytes.is_err());

   let from_short_seq: Result<SecureArray<u8, 3>, _> = serde_json::from_str("[1,2]");
   assert!(from_short_seq.is_err());
}

#[cfg(feature = "serde")]
#[test]
fn test_deserialize_rejects_overlong_seq_early() {
   // Rejected as soon as it exceeds `LENGTH`, so the locked buffer never grows.
   let result: Result<SecureArray<u8, 2>, _> = serde_json::from_str("[1,2,3]");

   assert!(result.is_err());
}

// === Test helpers for variety of types (bigger than u8, complex) ===
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
impl Person {
   fn new(name: impl Into<String>, age: u32, notes: impl Into<String>) -> Self {
      Self {
         name: name.into(),
         age,
         notes: notes.into(),
      }
   }
}
impl Zeroize for Person {
   fn zeroize(&mut self) {
      self.name.zeroize();
      self.age.zeroize();
      self.notes.zeroize();
   }
}
fn create_test_person(id: usize) -> Person {
   Person::new(
      format!("Person{}", id),
      (id % 100) as u32,
      format!("Notes #{}", id),
   )
}

/// Counts every `clone` call, so `PanicOnClone` can blow up mid-way through
/// an initialization loop.
static CLONE_BOMB: AtomicUsize = AtomicUsize::new(0);

/// Owns a `String` like `Person` does, but panics on its second clone.
#[derive(Debug)]
struct PanicOnClone {
   data: String,
}

impl PanicOnClone {
   fn new(data: impl Into<String>) -> Self {
      Self { data: data.into() }
   }
}

impl Clone for PanicOnClone {
   fn clone(&self) -> Self {
      if CLONE_BOMB.fetch_add(1, Ordering::SeqCst) == 1 {
         panic!("clone bomb");
      }

      Self::new(self.data.clone())
   }
}

impl Zeroize for PanicOnClone {
   fn zeroize(&mut self) {
      self.data.zeroize();
   }
}

fn test_array_generic_basics<T: Zeroize + Clone + PartialEq + Debug, const N: usize>(
   initial: &[T; N],
) {
   let secure: SecureArray<T, N> = SecureArray::from_slice(initial).unwrap();
   assert_eq!(secure.len(), N);
   secure.unlock(|slice| {
      assert_eq!(slice, initial);
   });
   let cloned = secure.clone();
   cloned.unlock(|slice| {
      assert_eq!(slice, initial);
   });
   let mut er = SecureArray::from_slice(initial).unwrap();
   er.erase();
   er.unlock(|slice| {
      assert_eq!(slice.len(), N);
      let mut expected = initial.clone();
      for item in expected.iter_mut() {
         item.zeroize();
      }
      assert_eq!(slice, expected.as_slice());
   });
}

#[test]
fn test_array_u8_variety() {
   let data: [u8; 3] = [1, 2, 3];
   test_array_generic_basics(&data);
}

#[test]
fn test_array_u64() {
   let data: [u64; 2] = [100u64, 200];
   test_array_generic_basics(&data);
}

#[test]
fn test_array_byte_array() {
   let data: [[u8; 16]; 2] = [[1u8; 16], [2u8; 16]];
   test_array_generic_basics(&data);
}

#[test]
fn test_array_small_struct() {
   let data: [SmallStruct; 2] = [SmallStruct { a: 1, b: 2 }, SmallStruct { a: 3, b: 4 }];
   test_array_generic_basics(&data);
}

#[test]
fn test_array_large_struct() {
   let data = [
      LargeStruct {
         data: [1, 2, 3, 4],
         flag: true,
      },
      LargeStruct {
         data: [5, 6, 7, 8],
         flag: false,
      },
   ];
   test_array_generic_basics(&data);
}

#[test]
fn test_array_person() {
   let data = [create_test_person(42), create_test_person(43)];
   test_array_generic_basics(&data);
}

#[test]
fn test_array_aligned() {
   let data = [
      AlignedStruct { value: 0xDEAD_BEEF },
      AlignedStruct { value: 0xCAFE_BABE },
   ];
   test_array_generic_basics(&data);
}
