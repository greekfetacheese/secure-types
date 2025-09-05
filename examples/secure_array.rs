use secure_types::SecureArray;

fn main() {
   // Obviously this is an example, you should not hardcode sensitive data in your code
   // It is better to use the `from_slice_mut` method which takes a mutable slice and zeroizes it afterwards
   let exposed_array: &mut [u8; 3] = &mut [1, 2, 3];
   let mut secure_array = SecureArray::from_slice_mut(exposed_array).unwrap();

   // The memory is locked and protected here. Direct access is not possible.

   secure_array.unlock_mut(|unlocked_slice| {
      unlocked_slice[0] = 1;
      unlocked_slice[1] = 2;
      unlocked_slice[2] = 3;
   });

   // Use a scope to safely access the content as a slice.
   secure_array.unlock(|unlocked_slice| {
      assert_eq!(unlocked_slice, &[1, 2, 3]);
      println!("The secret is: {:?}", unlocked_slice);
   }); // The memory is automatically locked again when the scope ends.

   // Everytime we access the SecureArray we are unlocking the memory and making it accessible.
   // Any operations you do during that time ideally should be very fast so you don't keep the data exposed for too long.

   // Notice, direct indexing is not possible, the OS will terminate the process with an access violation error.
   // try removing the underscore to see what happens
   let _ = secure_array[0];
}
