use core::fmt;
use std::{
    borrow::{Borrow, BorrowMut},
    str::FromStr,
};

use memsec::{mlock, munlock};
use zeroize::Zeroize;

/// Secure array
///
/// - Securely erases the contents when it is dropped
/// - Masks the contents when it is displayed or debugged
/// - For `Windows` calls `VirtualLock` to protect the contents from being swapped out to disk
/// - For `Unix` calls `mlock` to prevent the contents from being swapped to disk and memory dumped
///
/// ### Note on `Windows` is not possible to prevent memory dumping
///
/// ## Usage
///
/// ```rust
/// use secure_types::array::SecureArray;
///
/// let secret_array = SecureArray::from([1, 2, 3, 4, 5]);
/// let borrowed_array = secret_array.borrow();
/// assert_eq!(borrowed_array, [1, 2, 3, 4, 5]);
/// ```
///  When it goes out of scope it will be zeroized
///  If you want to keep a secure array in a struct that lives for the entire lifetime of the program
///  make sure to call erase() when you are done with it
#[derive(Eq, PartialEq, PartialOrd, Ord, Hash)]
pub struct SecureArray<T, const LENGTH: usize>
where
    T: Zeroize,
{
    content: [T; LENGTH],
}

impl<T, const LENGTH: usize> SecureArray<T, LENGTH>
where
    T: Zeroize,
{
    pub fn new(mut content: [T; LENGTH]) -> Self {
        unsafe {
            let ptr = content.as_mut_ptr() as *mut u8;
            mlock(ptr, LENGTH * std::mem::size_of::<T>());
        }
        SecureArray { content }
    }

    /// Borrow the inner array
    pub fn borrow(&self) -> &[T] {
        self.content.borrow()
    }

    /// Mutably borrow the inner array
    pub fn borrow_mut(&mut self) -> &mut [T] {
        self.content.borrow_mut()
    }

    /// Convert to a Vec
    ///
    /// This will consume the SecureArray
    ///
    /// You are responsible for zeroizing the contents of returned Vec
    pub fn into_vec(mut self) -> Vec<T>
    where
        T: Clone,
    {
        unsafe {
            munlock(
                self.content.as_mut_ptr() as *mut u8,
                self.content.len() * std::mem::size_of::<T>(),
            );
        }
        let array = self.content.to_vec();
        std::mem::forget(self);
        array
    }

    /// Erase the inner contents from memory
    pub fn erase(&mut self) {
        self.content.zeroize();
    }
}

impl<T: Clone + Zeroize, const LENGTH: usize> Clone for SecureArray<T, LENGTH> {
    fn clone(&self) -> Self {
        Self::new(self.content.clone())
    }
}

impl<T, const LENGTH: usize> From<[T; LENGTH]> for SecureArray<T, LENGTH>
where
    T: Zeroize,
{
    fn from(s: [T; LENGTH]) -> Self {
        Self::new(s)
    }
}

impl<T, const LENGTH: usize> TryFrom<Vec<T>> for SecureArray<T, LENGTH>
where
    T: Zeroize,
{
    type Error = String;

    fn try_from(s: Vec<T>) -> Result<Self, Self::Error> {
        Ok(Self::new(s.try_into().map_err(|error: Vec<T>| {
            format!(
                "length mismatch: expected {LENGTH}, but got {}",
                error.len()
            )
        })?))
    }
}

impl<const LENGTH: usize> FromStr for SecureArray<u8, LENGTH> {
    type Err = std::array::TryFromSliceError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SecureArray::new(s.as_bytes().try_into()?))
    }
}

impl<T, U, const LENGTH: usize> std::ops::Index<U> for SecureArray<T, LENGTH>
where
    T: Zeroize,
    [T; LENGTH]: std::ops::Index<U>,
{
    type Output = <[T; LENGTH] as std::ops::Index<U>>::Output;

    fn index(&self, index: U) -> &Self::Output {
        std::ops::Index::index(&self.content, index)
    }
}

impl<T, const LENGTH: usize> Borrow<[T]> for SecureArray<T, LENGTH>
where
    T: Zeroize,
{
    fn borrow(&self) -> &[T] {
        self.content.borrow()
    }
}

impl<T, const LENGTH: usize> BorrowMut<[T]> for SecureArray<T, LENGTH>
where
    T: Zeroize,
{
    fn borrow_mut(&mut self) -> &mut [T] {
        self.content.borrow_mut()
    }
}

impl<T, const LENGTH: usize> Drop for SecureArray<T, LENGTH>
where
    T: Zeroize,
{
    fn drop(&mut self) {
        self.erase();
        unsafe {
            munlock(
                self.content.as_mut_ptr() as *mut u8,
                self.content.len() * std::mem::size_of::<T>(),
            );
        }
    }
}

impl<T, const LENGTH: usize> fmt::Debug for SecureArray<T, LENGTH>
where
    T: Zeroize,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

impl<T, const LENGTH: usize> fmt::Display for SecureArray<T, LENGTH>
where
    T: Zeroize,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let array = SecureArray::<u8, 5>::from([1, 2, 3, 4, 5]);
        assert_eq!(array.borrow(), &[1, 2, 3, 4, 5]);
    }

    #[test]
    fn test_into_vec() {
        let secure_array = SecureArray::<u8, 5>::from([1, 2, 3, 4, 5]);
        let array = secure_array.into_vec();
        assert_eq!(array.len(), 5);
    }

    #[test]
    fn test_from_str() {
        let str = "hello";
        let array = SecureArray::<u8, 5>::from_str(str).unwrap();
        assert_eq!(array.borrow(), str.as_bytes());
    }

    #[test]
    fn test_debug() {
        let array = SecureArray::<u8, 5>::from([1, 2, 3, 4, 5]);
        assert_eq!(format!("{:?}", array), "***SECRET***");
    }

    #[test]
    fn test_display() {
        let array = SecureArray::<u8, 5>::from([1, 2, 3, 4, 5]);
        assert_eq!(format!("{}", array), "***SECRET***");
    }

    #[test]
    fn test_index() {
        let array = SecureArray::<u8, 5>::from([1, 2, 3, 4, 5]);
        assert_eq!(array[0], 1);
        assert_eq!(array[1], 2);
        assert_eq!(array[2], 3);
        assert_eq!(array[3], 4);
        assert_eq!(array[4], 5);
    }

    #[test]
    fn test_erase() {
        let mut array = SecureArray::<u8, 5>::from([1, 2, 3, 4, 5]);
        array.erase();
        assert_eq!(array.borrow(), b"\x00\x00\x00\x00\x00");
    }
}
