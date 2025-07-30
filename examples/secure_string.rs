use secure_types::SecureString;

fn main() {
   // Obviously this is an example, you should not hardcode sensitive data in your code
   let exposed_string = String::from("my_secret");
   let mut secure_string = SecureString::from(exposed_string); // exposed string is moved into the SecureString

   // The memory is locked and protected here. Direct access is not possible.

   // Use a scope to safely access the content as a &str.
   secure_string.str_scope(|unlocked_str| {
      assert_eq!(unlocked_str, "my_secret");
      println!("The secret is: {}", unlocked_str);
   }); // The memory is automatically locked again when the scope ends.

   // Use mut scope if you need to pass it as a mutable reference
   secure_string.mut_scope(|mut_string| {
      mutate_secure_string(mut_string);
   });

   secure_string.str_scope(|unlocked_str| {
      assert_eq!(unlocked_str, "my_secret_password");
      println!("The secret is: {}", unlocked_str);
   });

   // Everytime we access the SecureString we are unlocking the memory and making it accessible.
   // Any operations you do during that time ideally should be very fast so you don't keep the data exposed for too long.
}

fn mutate_secure_string(string: &mut SecureString) {
   string.push_str("_password");
}
