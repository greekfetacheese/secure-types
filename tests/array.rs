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
      println!("ARRAY-CHILD-OK");
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
   assert!(
      String::from_utf8_lossy(&output.stdout).contains("ARRAY-CHILD-OK"),
      "the child never reported success, so the test filter may have missed: stdout: {}, stderr: {}",
      String::from_utf8_lossy(&output.stdout),
      String::from_utf8_lossy(&output.stderr)
   );
}

/// Regression test: a panic while filling the array must not crash, and the
/// elements cloned before the panic must be zeroized and dropped. `drop` must
/// never interpret the unwritten slots as a `T`.
///
/// The clone bomb fires on its second clone, so exactly one element had reached
/// a slot when the panic started: the initialization guard has to wipe and drop
/// that prefix, because `initialized` is committed only after the whole loop.
#[test]
fn test_panic_during_partial_init_is_sound() {
   let arg = "CRASH_TEST_ARRAY_PANIC_INIT";

   if std::env::args().any(|a| a == arg) {
      ZEROIZED.store(0, Ordering::SeqCst);

      let panicked = std::panic::catch_unwind(|| {
         let content: [PanicOnClone; 3] = [
            PanicOnClone::new("a"),
            PanicOnClone::new("b"),
            PanicOnClone::new("c"),
         ];
         let _array = SecureArray::<PanicOnClone, 3>::from_slice(&content).unwrap();
      })
      .is_err();

      let sound = panicked && ZEROIZED.load(Ordering::SeqCst) == 1;
      if sound {
         println!("ARRAY-CHILD-OK");
      }

      std::process::exit(if sound { 0 } else { 1 });
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
   assert!(
      String::from_utf8_lossy(&output.stdout).contains("ARRAY-CHILD-OK"),
      "the child never reported success, so the test filter may have missed: stdout: {}, stderr: {}",
      String::from_utf8_lossy(&output.stdout),
      String::from_utf8_lossy(&output.stderr)
   );
}

/// The constructors that take a `&mut` source promise to leave it wiped, so the
/// wipe has to run on the panic path too. A `T::clone` that panics must not
/// unwind past it and leave the caller's plaintext behind.
#[test]
fn test_from_slice_mut_wipes_the_source_when_a_clone_panics() {
   struct PanicOnClone(u8);

   impl Clone for PanicOnClone {
      fn clone(&self) -> Self {
         panic!("clone bomb");
      }
   }

   impl Zeroize for PanicOnClone {
      fn zeroize(&mut self) {
         self.0 = 0;
      }
   }

   let mut source: [PanicOnClone; 2] = [PanicOnClone(0x11), PanicOnClone(0x22)];

   let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      let _ = SecureArray::<PanicOnClone, 2>::from_slice_mut(&mut source);
   }))
   .is_err();

   assert!(panicked, "the clone was supposed to panic");
   assert_eq!(
      source.iter().map(|item| item.0).collect::<Vec<_>>(),
      vec![0, 0],
      "the caller's buffer must be wiped even when T::clone panics"
   );
}

/// The same guarantee for the `Vec<T>` conversion. The vector is consumed, so the
/// observable survivor is whether its elements were zeroized before it dropped.
#[test]
fn test_try_from_vec_wipes_the_source_when_a_clone_panics() {
   static ZEROIZED: AtomicUsize = AtomicUsize::new(0);

   struct PanicOnClone(u8);

   impl Clone for PanicOnClone {
      fn clone(&self) -> Self {
         panic!("clone bomb");
      }
   }

   impl Zeroize for PanicOnClone {
      fn zeroize(&mut self) {
         self.0 = 0;
         ZEROIZED.fetch_add(1, Ordering::SeqCst);
      }
   }

   let source: Vec<PanicOnClone> = vec![PanicOnClone(0x11), PanicOnClone(0x22)];

   let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      let _ = SecureArray::<PanicOnClone, 2>::try_from(source);
   }))
   .is_err();

   assert!(panicked, "the clone was supposed to panic");
   assert_eq!(
      ZEROIZED.load(Ordering::SeqCst),
      2,
      "both elements of the consumed vector must be zeroized before it drops"
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

/// A zero-length array is rejected with `LengthCannotBeZero` (a `SecureArray`
/// cannot hold a zero-sized allocation), asserted on the variant rather than on
/// an incidental `unwrap` panic.
#[test]
fn test_length_cannot_be_zero() {
   let secure_vec = SecureVec::new().unwrap();
   let result: Result<SecureArray<u8, 0>, _> = SecureArray::try_from(secure_vec);

   assert!(matches!(result, Err(Error::LengthCannotBeZero)));
}

#[test]
fn test_clone() {
   let array1: SecureArray<u8, 3> = SecureArray::from_fn(|i| i as u8 + 1).unwrap();

   let array2 = array1.clone();

   array2.unlock(|slice| {
      assert_eq!(slice, &[1, 2, 3]);
   });

   array1.unlock(|slice| {
      assert_eq!(slice, &[1, 2, 3]);
   });
}

/// Regression test: `Clone` carries the source's `initialized` count instead of
/// assuming the array is full. Cloning a never-filled array used to trip
/// `init_from_clone`'s `debug_assert_eq!(src.len(), LENGTH)` in every debug build,
/// and in release it silently produced a clone whose `unlock` slice was empty while
/// `len()` still reported `LENGTH`.
#[test]
fn test_clone_of_an_unfilled_array() {
   let empty: SecureArray<u8, 4> = SecureArray::empty().unwrap();
   let cloned = empty.clone();

   assert_eq!(cloned.len(), 4);
   cloned.unlock(|slice| assert!(slice.is_empty()));

   // A fully initialized array still clones every element.
   let full: SecureArray<u8, 4> = SecureArray::from_fn(|i| i as u8).unwrap();
   let cloned = full.clone();

   cloned.unlock(|slice| assert_eq!(slice, &[0, 1, 2, 3]));
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

   // `visit_byte_buf`: copied into locked memory. The owned buffer's wipe runs on
   // this same path, but it is not observable in-process.
   let array = SecureArray::<u8, 3>::deserialize(OwnedBytes(vec![1, 2, 3])).unwrap();

   array.unlock(|slice| assert_eq!(slice, &[1, 2, 3]));

   // Wrong length still has to return an error. This path wipes the owned buffer
   // as well, but the wipe is not observable in-process.
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

/// Rejected as soon as the sequence exceeds `LENGTH`, so the locked buffer never
/// grows. The reported length is what distinguishes that early return from the
/// post-loop check: a five-element document into a two-element array reports
/// `invalid length 3` (the refused third element), not `invalid length 5`.
#[cfg(feature = "serde")]
#[test]
fn test_deserialize_rejects_overlong_seq_early() {
   let result: Result<SecureArray<u8, 2>, _> = serde_json::from_str("[1,2,3,4,5]");
   let error = result
      .err()
      .expect("an over-long byte sequence must be rejected");
   assert!(
      error.to_string().contains("invalid length 3"),
      "the u8 visitor must reject the third element early, got: {error}"
   );

   // The tuple visitor has the same early return, reached through `u16`.
   let result: Result<SecureArray<u16, 2>, _> = serde_json::from_str("[1,2,3,4,5]");
   let error = result.err().expect("an over-long tuple must be rejected");
   assert!(
      error.to_string().contains("invalid length 3"),
      "the tuple visitor must reject the third element early, got: {error}"
   );
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

/// Counts every `zeroize` call, so the partial-init test can prove that the
/// element written before the panic was wiped instead of leaked.
static ZEROIZED: AtomicUsize = AtomicUsize::new(0);

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
      ZEROIZED.fetch_add(1, Ordering::SeqCst);
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

/// A `T` whose destructor panics, holding a payload that must not outlive the array.
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
/// readable.
#[cfg(target_os = "linux")]
#[test]
fn test_a_panicking_destructor_still_frees_the_region() {
   const CHILD: &str = "ST_ARRAY_PANICKING_DESTRUCTOR_REGION";

   if std::env::args().any(|arg| arg == CHILD) {
      if !secure_types::supports_memfd_secret() {
         std::process::exit(77);
      }

      // The destructor's panic is this test's input, not a failure.
      std::panic::set_hook(Box::new(|_| {}));

      let before = secretmem_mappings();

      let array: SecureArray<PanicOnDrop, 2> = SecureArray::from_fn(|index| PanicOnDrop {
         payload: if index == 0 {
            "SECRET-ONE"
         } else {
            "SECRET-TWO"
         }
         .to_owned(),
         boom: index == 0,
      })
      .unwrap();

      let panicked =
         std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(array))).is_err();
      let after = secretmem_mappings();

      let sound = panicked && after <= before;
      if sound {
         println!("ARRAY-CHILD-OK");
      }

      std::process::exit(if sound { 0 } else { 3 });
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
   assert!(
      String::from_utf8_lossy(&output.stdout).contains("ARRAY-CHILD-OK"),
      "the child never reported success, so the test filter may have missed: stdout: {}, stderr: {}",
      String::from_utf8_lossy(&output.stdout),
      String::from_utf8_lossy(&output.stderr)
   );
}

static ARRAY_DROP_ZEROIZED: AtomicUsize = AtomicUsize::new(0);
static ARRAY_DROP_DROPPED: AtomicUsize = AtomicUsize::new(0);

/// A T that records both halves of the discard lifecycle and panics once.
struct ArrayDropBomb {
   index: usize,
}

impl Zeroize for ArrayDropBomb {
   fn zeroize(&mut self) {
      ARRAY_DROP_ZEROIZED.fetch_add(1, Ordering::SeqCst);
   }
}

impl Drop for ArrayDropBomb {
   fn drop(&mut self) {
      ARRAY_DROP_DROPPED.fetch_add(1, Ordering::SeqCst);

      if self.index == 1 {
         panic!("element destructor panics");
      }
   }
}

/// Drop must discard the elements it has not reached when a destructor panics.
///
/// SecureArray's forward loop had the same shape as SecureVec's: the free guard
/// released the region, but every slot after the panicking element was neither
/// zeroized nor dropped, so an owned buffer kept its plaintext.
#[test]
fn test_drop_discards_the_rest_when_a_destructor_panics() {
   ARRAY_DROP_ZEROIZED.store(0, Ordering::SeqCst);
   ARRAY_DROP_DROPPED.store(0, Ordering::SeqCst);

   let array: SecureArray<ArrayDropBomb, 3> =
      SecureArray::from_fn(|index| ArrayDropBomb { index }).unwrap();

   let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| drop(array))).is_err();

   assert!(panicked, "the destructor was supposed to panic");
   assert_eq!(
      ARRAY_DROP_ZEROIZED.load(Ordering::SeqCst),
      3,
      "every element must be zeroized, including the ones the panic skipped"
   );
   assert_eq!(
      ARRAY_DROP_DROPPED.load(Ordering::SeqCst),
      3,
      "every element must be dropped, including the ones the panic skipped"
   );
}
