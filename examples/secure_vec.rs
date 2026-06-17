use secure_types::SecureVec;

fn main() {
   // Obviously this is an example, you should not hardcode sensitive data in your code
   let exposed_vec = vec![1, 2, 3];
   let mut secure_vec = SecureVec::from_vec(exposed_vec).unwrap(); // exposed vec is moved into the SecureVec

   // The memory is locked and protected here. Direct access is not possible.

   // Use a scope to safely access the content as a slice.
   secure_vec.unlock_slice(|unlocked_slice| {
      assert_eq!(unlocked_slice, &[1, 2, 3]);
      println!("The secret is: {:?}", unlocked_slice);
   }); // The memory is automatically locked again when the scope ends.

   secure_vec.push(4);

   secure_vec.unlock_slice(|unlocked_slice| {
      assert_eq!(unlocked_slice, &[1, 2, 3, 4]);
      println!("The secret is: {:?}", unlocked_slice);
   });
}
