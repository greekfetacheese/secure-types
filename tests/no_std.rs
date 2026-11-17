//! The `no_std` + `alloc` build, exercised through the public API.
//!
//! Every other integration suite is gated on `use_os`, and that build cannot run under
//! Miri: its allocator is an `mmap` / `memfd_secret` region that is `mlock`ed and
//! `mprotect`ed through `libc`, and Miri does not execute foreign functions. This build
//! keeps the same raw-pointer machinery — `try_reserve` moves the elements out and wipes
//! the buffer it abandons, `clear` / `Drop` / `erase` wipe through a `MaybeUninit` view
//! of the whole allocation, `drain` compacts with `ptr::copy`, the string mutations shift
//! bytes inside the buffer — on top of `alloc::alloc`. So what runs here is the code the
//! `use_os` build runs, with only the allocator behind it differing.
//!
//! Run it natively with `cargo test --no-default-features`, or under Miri with
//! `scripts/miri.sh`.

#![cfg(not(feature = "use_os"))]

use secure_types::{Error, SecureArray, SecureBytes, SecureString, SecureVec, Zeroize};

/// An element that owns heap memory.
///
/// A growth or a drop that mishandles ownership shows up as a leak, a double free or a
/// use-after-free, all of which Miri reports; the same bug on a `u8` element keeps the
/// bits in the container and stays invisible.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Secret(String);

impl Secret {
   fn new(text: &str) -> Self {
      Secret(text.to_owned())
   }
}

impl Zeroize for Secret {
   fn zeroize(&mut self) {
      self.0.zeroize();
   }
}

#[test]
fn vec_growth_moves_owned_elements() {
   // Enough pushes to cross several doublings, so the move-out in `try_reserve` runs
   // repeatedly: each element is read out of the old buffer and written into the new
   // one, and the old buffer is wiped through a `MaybeUninit` view before it is freed.
   let mut secret: SecureVec<Secret> = SecureVec::new().unwrap();

   for i in 0..64 {
      secret.push(Secret::new(&format!("secret-{i}")));
   }

   assert_eq!(secret.len(), 64);
   assert!(secret.capacity() >= 64);

   secret.unlock_slice(|slice| {
      assert_eq!(slice.len(), 64);
      for (i, element) in slice.iter().enumerate() {
         assert_eq!(element, &Secret::new(&format!("secret-{i}")));
      }
   });
}

#[test]
fn vec_drop_wipes_capacity_it_never_wrote() {
   // `Drop` zeroes `capacity * size_of::<T>()` bytes, so the wipe covers memory no
   // constructor ever initialized. The `MaybeUninit` view is what makes that sound, and
   // it is the kind of thing only Miri can confirm.
   let empty: SecureBytes = SecureVec::new_with_capacity(64).unwrap();
   assert_eq!(empty.len(), 0);
   drop(empty);

   let mut partly_filled: SecureBytes = SecureVec::new_with_capacity(64).unwrap();
   partly_filled.push(0xAA);
   assert!(partly_filled.capacity() >= 64);
   drop(partly_filled);
}

#[test]
fn vec_clear_and_erase_keep_the_allocation() {
   let mut secret: SecureVec<Secret> = SecureVec::new().unwrap();
   secret.push(Secret::new("first"));
   secret.push(Secret::new("second"));
   let capacity = secret.capacity();

   secret.clear();
   assert_eq!(secret.len(), 0);
   assert_eq!(secret.capacity(), capacity);
   secret.unlock_slice(|slice| assert!(slice.is_empty()));

   secret.push(Secret::new("third"));
   assert_eq!(secret.len(), 1);
   secret.erase();
   assert!(secret.is_empty());
   secret.unlock_slice(|slice| assert!(slice.is_empty()));
}

#[test]
fn vec_from_slice_mut_wipes_the_source() {
   let mut source = [1u8, 2, 3];
   let secret = SecureVec::from_slice_mut(&mut source).unwrap();

   assert_eq!(source, [0u8; 3]);
   secret.unlock_slice(|slice| assert_eq!(slice, &[1, 2, 3]));
}

#[test]
fn vec_reserve_grows_once_and_keeps_the_elements() {
   let mut secret: SecureBytes = SecureVec::from_slice(&[1, 2, 3]).unwrap();
   let capacity = secret.capacity();

   secret.reserve(97);

   assert!(secret.capacity() >= capacity.max(100));
   secret.unlock_slice(|slice| assert_eq!(slice, &[1, 2, 3]));
}

#[test]
#[should_panic(expected = "SecureVec::reserve overflow or allocation failed")]
fn vec_reserve_reports_an_oversized_request() {
   // A request that cannot be represented as a `Layout` is reported, not attempted.
   let mut secret: SecureBytes = SecureVec::new().unwrap();
   secret.reserve(usize::MAX);
}

#[test]
fn vec_drain_of_an_inner_range_compacts_the_tail() {
   let mut secret: SecureBytes = SecureVec::from_slice(&[0, 1, 2, 3, 4]).unwrap();

   let drained: Vec<u8> = secret.drain(1..3).collect();

   assert_eq!(drained, [1, 2]);
   assert_eq!(secret.len(), 3);
   secret.unlock_slice(|slice| assert_eq!(slice, &[0, 3, 4]));
}

#[test]
fn vec_drain_dropped_mid_iteration_compacts() {
   let mut secret: SecureBytes = SecureVec::from_slice(&[0, 1, 2, 3, 4]).unwrap();

   {
      let mut drain = secret.drain(1..4);
      assert_eq!(drain.next(), Some(1));
      // Dropping here discards the two unyielded elements (2 and 3) and moves the
      // tail (4) down into the hole.
   }

   assert_eq!(secret.len(), 2);
   secret.unlock_slice(|slice| assert_eq!(slice, &[0, 4]));
}

#[test]
fn vec_drain_to_the_end_leaves_no_tail() {
   let mut secret: SecureBytes = SecureVec::from_slice(&[0, 1, 2]).unwrap();

   let drained: Vec<u8> = secret.drain(1..).collect();

   assert_eq!(drained, [1, 2]);
   // The prefix before the drained range stays; there is no tail to move.
   assert_eq!(secret.len(), 1);
   secret.unlock_slice(|slice| assert_eq!(slice, &[0]));
}

#[test]
fn vec_drain_of_owned_elements_drops_the_rest() {
   let mut secret: SecureVec<Secret> = SecureVec::new().unwrap();
   for i in 0..8 {
      secret.push(Secret::new(&format!("item-{i}")));
   }

   let drained: Vec<Secret> = secret.drain(2..6).collect();

   assert_eq!(drained.len(), 4);
   assert_eq!(drained[0], Secret::new("item-2"));
   assert_eq!(secret.len(), 4);
   secret.unlock_slice(|slice| {
      let texts: Vec<&str> = slice.iter().map(|element| element.0.as_str()).collect();
      assert_eq!(texts, ["item-0", "item-1", "item-6", "item-7"]);
   });
}

#[test]
fn vec_clone_owns_its_own_elements() {
   let mut secret: SecureVec<Secret> = SecureVec::new().unwrap();
   secret.push(Secret::new("copy me"));

   let cloned = secret.clone();

   assert_eq!(cloned.len(), 1);
   cloned.unlock_slice(|slice| assert_eq!(slice[0], Secret::new("copy me")));
   secret.unlock_slice(|slice| assert_eq!(slice[0], Secret::new("copy me")));
}

#[test]
fn array_from_fn_and_mut_window() {
   let mut array: SecureArray<u8, 4> = SecureArray::from_fn(|i| i as u8 + 1).unwrap();

   assert_eq!(array.len(), 4);
   array.unlock_mut(|slice| {
      slice[0] = 9;
   });
   array.unlock(|slice| assert_eq!(slice, &[9, 2, 3, 4]));
}

#[test]
fn array_dropped_before_it_is_filled() {
   // `empty` writes no slot, and `Drop` still wipes and frees the whole allocation.
   let array: SecureArray<Secret, 3> = SecureArray::empty().unwrap();

   assert!(array.unlock(|slice| slice.is_empty()));
   drop(array);
}

#[test]
fn array_converts_into_a_vec_of_its_elements() {
   let mut source = [1u8, 2, 3];
   let array: SecureArray<u8, 3> = SecureArray::from_slice_mut(&mut source).unwrap();

   let secret: SecureVec<u8> = array.into();

   assert_eq!(secret.len(), 3);
   secret.unlock_slice(|slice| assert_eq!(slice, &[1, 2, 3]));
}

#[test]
#[should_panic(expected = "stop here")]
fn array_from_fn_cleans_up_when_the_source_panics() {
   // The slots written before the panic have to be zeroized and dropped, or the
   // allocator hands back a live allocation holding them: Miri's leak check and its
   // drop tracking are what fail if the guard misses one.
   let _array: SecureArray<Secret, 4> = SecureArray::from_fn(|i| {
      assert!(i != 2, "stop here");
      Secret::new(&format!("slot-{i}"))
   })
   .unwrap();
}

#[test]
fn string_push_str_grows_through_multibyte_text() {
   let mut secret = SecureString::new().unwrap();

   for _ in 0..32 {
      secret.push_str("héllo→");
   }

   assert_eq!(secret.byte_len(), 32 * "héllo→".len());
   assert_eq!(secret.char_len(), 32 * 6);
   secret.unlock_str(|text| assert_eq!(text, "héllo→".repeat(32)));
}

#[test]
fn string_insert_and_delete_shift_inside_the_buffer() {
   let mut secret = SecureString::from("GreekFeta");

   assert_eq!(secret.insert_text_at_char_idx(9, "Cheese"), 6);
   secret.unlock_str(|text| assert_eq!(text, "GreekFetaCheese"));

   // An index past the end appends rather than panicking.
   secret.insert_text_at_char_idx(64, "!");
   secret.unlock_str(|text| assert_eq!(text, "GreekFetaCheese!"));

   secret.delete_text_char_range(9..15);
   secret.unlock_str(|text| assert_eq!(text, "GreekFeta!"));
}

#[test]
fn string_insert_in_the_middle_of_a_multibyte_string() {
   let mut secret = SecureString::from("aé✓z");

   secret.insert_text_at_char_idx(2, "→");

   secret.unlock_str(|text| assert_eq!(text, "aé→✓z"));
   assert_eq!(secret.char_len(), 5);
}

#[test]
fn string_drain_takes_byte_offsets() {
   let mut secret = SecureString::from("héllo");

   // "é" is two bytes, so 1..3 is exactly that character.
   secret.drain(1..3);

   secret.unlock_str(|text| assert_eq!(text, "hllo"));
}

#[test]
fn string_try_from_rejects_invalid_utf8() {
   let bytes: SecureBytes = SecureVec::from_slice(&[0xFF, 0xFE]).unwrap();

   match SecureString::try_from(bytes) {
      Ok(_) => panic!("invalid UTF-8 must not construct a SecureString"),
      Err(Error::InvalidUtf8) => {}
      Err(other) => panic!("unexpected error: {other}"),
   }
}

#[cfg(feature = "codec")]
#[test]
fn codec_round_trips_into_and_out_of_the_containers() {
   use secure_types::{decode, encode};

   // Decoding a sequence appends straight into the container, one unlock window per
   // block, so a length the document chose is what drives `try_reserve` and the
   // `ptr::write` loop underneath it.
   let plain: Vec<u16> = (0..200).collect();
   let value = SecureVec::<u16>::from_slice(&plain).expect("secure sequence");
   let document = encode(&value).expect("encode");

   let decoded = decode::<SecureVec<u16>>(&document).expect("decode");

   assert_eq!(decoded.len(), plain.len());
   decoded.unlock_slice(|slice| assert!(slice.iter().eq(plain.iter())));

   let secret = SecureString::from("hunter2");
   let document = encode(&secret).expect("encode");
   let decoded = decode::<SecureString>(&document).expect("decode");

   decoded.unlock_str(|text| assert_eq!(text, "hunter2"));
}

#[cfg(feature = "codec")]
#[test]
fn codec_refuses_a_truncated_document() {
   use secure_types::{decode_slice, encode_to_vec};

   let document = encode_to_vec("hunter2").expect("encode");
   let truncated = &document[..document.len() - 1];

   assert!(decode_slice::<SecureString>(truncated).is_err());
}

#[test]
fn string_from_utf8_unchecked_on_a_buffer_it_owns() {
   let bytes: SecureBytes = SecureVec::from_slice("héllo".as_bytes()).unwrap();

   // SAFETY: the bytes came from a `&str`, so the buffer holds valid UTF-8.
   let secret = unsafe { SecureString::from_utf8_unchecked(bytes) };

   secret.unlock_str(|text| assert_eq!(text, "héllo"));
   assert_eq!(secret.char_len_unchecked(), 5);
}
