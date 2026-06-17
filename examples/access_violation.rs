use secure_types::SecureArray;

#[allow(deprecated)]

fn main() {
   let sec_array = SecureArray::from_slice(&[1, 2, 3]).unwrap();

   // Direct access to the locked memory region will cause a segfault
   let ptr = sec_array.ptr();
   unsafe {
      core::ptr::read_volatile(ptr.as_ptr());
   }
}
