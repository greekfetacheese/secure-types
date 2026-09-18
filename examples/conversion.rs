use secure_types::{SecureArray, SecureVec};

fn main() {
   let normal_vec = vec![1u8, 2, 3];
   let secure_vec = SecureVec::from_slice(&[1u8, 2, 3]).unwrap();

   let from_normal_vec: SecureArray<u8, 3> = SecureArray::try_from(normal_vec).unwrap();
   let from_sec_vec: SecureArray<u8, 3> = SecureArray::try_from(secure_vec).unwrap();

   from_normal_vec.unlock(|slice| {
      assert_eq!(slice, &[1, 2, 3]);
   });
   from_sec_vec.unlock(|slice| {
      assert_eq!(slice, &[1, 2, 3]);
   });
}
