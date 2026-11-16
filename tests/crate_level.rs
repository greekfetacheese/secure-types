//! Crate-level behavior: the OS capability the locking is built on, and the
//! `SecureArray`/`SecureVec` serde-compatibility contract.

// `memfd_secret` is Linux-only, so this test is gated to Linux as well as to OS
// support; non-Linux Unix gets `test_memfd_secret_is_unavailable_off_linux` instead.

/// Set in the child that allocates and releases the probe alone.
#[cfg(all(target_os = "linux", feature = "use_os"))]
const CHILD: &str = "SECURE_TYPES_MEMFD_PROBE_CHILD";

/// Open descriptors and `secretmem` mappings of this process, per `/proc/self`.
#[cfg(all(target_os = "linux", feature = "use_os"))]
fn secretmem_state() -> (usize, usize) {
   let descriptors = std::fs::read_dir("/proc/self/fd")
      .expect("/proc/self/fd")
      .count();
   let maps = std::fs::read_to_string("/proc/self/maps").expect("/proc/self/maps");
   let mappings = maps
      .lines()
      .filter(|line| line.contains("secretmem"))
      .count();

   (descriptors, mappings)
}

/// Allocates the probe, requires the allocation to move the process state, frees it and
/// requires the state to come back.
#[cfg(all(target_os = "linux", feature = "use_os"))]
fn probe_allocates_and_releases() {
   use secure_types::secure_alloc;

   let before = secretmem_state();
   let size = std::mem::size_of::<u8>();
   let ptr = unsafe { secure_alloc::memfd_secret_sized(size) }.expect("allocation");
   let during = secretmem_state();

   assert!(
      during.1 > before.1,
      "the probe must add a secretmem mapping: {:?} -> {:?}",
      before,
      during
   );
   assert!(
      during.0 > before.0,
      "the probe must open a secretmem descriptor: {:?} -> {:?}",
      before,
      during
   );

   // SAFETY: `ptr` is the allocation made just above, and it is released exactly once here.
   unsafe { secure_alloc::free_memfd_secret(ptr) };

   assert_eq!(
      secretmem_state(),
      before,
      "the probe must not outlive the test"
   );
}

#[cfg(all(target_os = "linux", feature = "use_os"))]
#[test]
fn test_supports_memfd_secret() {
   use secure_types::supports_memfd_secret;

   if !supports_memfd_secret() {
      print!("memfd_secret is not supported");
      return;
   }
   print!("memfd_secret is supported");

   // The probe is a live allocation: release it, or its region and descriptor outlive the
   // test. The release is pinned, not assumed: the counts are taken in a child that runs this
   // test alone, so no sibling test opens a `secretmem` descriptor while they are read.
   if std::env::var_os(CHILD).is_some() {
      probe_allocates_and_releases();
      println!("MEMFD-PROBE-CHILD-OK");
      return;
   }

   let output = std::process::Command::new(std::env::current_exe().unwrap())
      .arg("test_supports_memfd_secret")
      .arg("--exact")
      .arg("--nocapture")
      .env(CHILD, "1")
      .output()
      .expect("failed to execute the test binary");

   assert!(
      output.status.success(),
      "the memfd_secret probe must release its region and descriptor: {}",
      String::from_utf8_lossy(&output.stderr)
   );
   assert!(
      String::from_utf8_lossy(&output.stdout).contains("MEMFD-PROBE-CHILD-OK"),
      "the child never reported success, so the test filter may have missed: stdout: {}, stderr: {}",
      String::from_utf8_lossy(&output.stdout),
      String::from_utf8_lossy(&output.stderr)
   );
}

/// `memfd_secret` is Linux-only, so every other Unix reports it as unavailable
/// rather than probing a syscall that does not exist there.
#[cfg(all(unix, not(target_os = "linux"), feature = "use_os"))]
#[test]
fn test_memfd_secret_is_unavailable_off_linux() {
   assert!(!secure_types::supports_memfd_secret());
}

#[cfg(feature = "serde")]
#[test]
fn test_array_and_secure_vec_serde_compatibility() {
   use secure_types::{SecureArray, SecureVec};

   let exposed_array: &mut [u8; 3] = &mut [1, 2, 3];
   let array: SecureArray<u8, 3> = SecureArray::from_slice_mut(exposed_array).unwrap();
   let vec: SecureVec<u8> = array.clone().into();

   let array_json_string = serde_json::to_string(&array).unwrap();
   let array_json_bytes = serde_json::to_vec(&array).unwrap();
   let vec_json_string = serde_json::to_string(&vec).unwrap();
   let vec_json_bytes = serde_json::to_vec(&vec).unwrap();

   assert_eq!(array_json_string, vec_json_string);
   assert_eq!(array_json_bytes, vec_json_bytes);

   let deserialized_array_from_string: SecureArray<u8, 3> =
      serde_json::from_str(&array_json_string).unwrap();

   let deserialized_array_from_bytes: SecureArray<u8, 3> =
      serde_json::from_slice(&array_json_bytes).unwrap();

   let deserialized_vec_from_string: SecureVec<u8> =
      serde_json::from_str(&vec_json_string).unwrap();

   let deserialized_vec_from_bytes: SecureVec<u8> =
      serde_json::from_slice(&vec_json_bytes).unwrap();

   deserialized_array_from_string.unlock(|slice| {
      deserialized_vec_from_string.unlock_slice(|slice2| {
         assert_eq!(slice, slice2);
      });
   });

   deserialized_array_from_bytes.unlock(|slice| {
      deserialized_vec_from_bytes.unlock_slice(|slice2| {
         assert_eq!(slice, slice2);
      });
   });
}

/// A zero-sized allocation is refused rather than handed out as a dangling pointer.
#[test]
fn test_zero_sized_secure_allocations_are_refused() {
   use secure_types::{Error, SecureArray, SecureVec};

   let error = SecureVec::<()>::new()
      .err()
      .expect("a zero-sized `SecureVec` must be refused");
   assert!(
      matches!(error, Error::SizeCannotBeZero),
      "expected Error::SizeCannotBeZero, got {error:?}"
   );

   let error = SecureArray::<u8, 0>::empty()
      .err()
      .expect("a zero-length `SecureArray` must be refused");
   assert!(
      matches!(error, Error::LengthCannotBeZero),
      "expected Error::LengthCannotBeZero, got {error:?}"
   );
}
