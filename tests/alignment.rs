//! Alignment limits of the `secure-alloc` backing store.
//!
//! `secure-alloc` returns a pointer inside a page-rounded region, so the strongest
//! alignment it can promise is the page size. A stronger `align_of::<T>()` used to be
//! written through a misaligned pointer; `alloc` refuses it with
//! `Error::AlignmentFailed` instead.

#![cfg(feature = "use_os")]

use secure_types::{Error, SecureArray, SecureVec, Zeroize};

#[repr(align(4096))]
#[derive(Clone)]
struct PageAligned([u8; 4096]);

impl Zeroize for PageAligned {
   fn zeroize(&mut self) {
      self.0.zeroize();
   }
}

#[repr(align(8192))]
struct OverAligned([u8; 8192]);

impl Zeroize for OverAligned {
   fn zeroize(&mut self) {
      self.0.zeroize();
   }
}

#[test]
fn page_sized_alignment_is_accepted() {
   let array: SecureArray<PageAligned, 1> =
      SecureArray::from_slice(&[PageAligned([0u8; 4096])]).unwrap();

   array.unlock(|slice| assert_eq!(slice.as_ptr() as usize % 4096, 0));
}

#[test]
fn alignment_above_the_page_size_is_rejected() {
   let page_size = secure_types::secure_alloc::page_size();

   // A page of 8192 bytes or more can satisfy this alignment; the layout is only
   // broken below that, which is where the rejection has to fire.
   if page_size >= 8192 {
      assert!(SecureArray::<OverAligned, 1>::empty().is_ok());
      return;
   }

   // `empty` performs no element write, so the RED run reports the misalignment
   // instead of faulting on it. `mem::forget` keeps the `Ok` arm from building a
   // slice through the same misaligned pointer in `Drop`.
   match SecureArray::<OverAligned, 1>::empty() {
      Ok(array) => {
         std::mem::forget(array);
         panic!("expected Err(AlignmentFailed), got Ok");
      }
      Err(Error::AlignmentFailed) => {}
      Err(other) => panic!("expected AlignmentFailed, got {other:?}"),
   }
}

#[test]
fn secure_vec_rejects_alignment_above_the_page_size() {
   let page_size = secure_types::secure_alloc::page_size();

   if page_size >= 8192 {
      return;
   }

   match SecureVec::<OverAligned>::new() {
      Ok(vec) => {
         std::mem::forget(vec);
         panic!("expected Err(AlignmentFailed), got Ok");
      }
      Err(Error::AlignmentFailed) => {}
      Err(other) => panic!("expected AlignmentFailed, got {other:?}"),
   }
}
