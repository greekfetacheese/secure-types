use secure_types::SecureArray;

fn main() {
   let a = SecureArray::<String, 4>::empty().unwrap();
   drop(a); // Segmentation fault (exit 139)
}
