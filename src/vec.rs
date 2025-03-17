use core::fmt;
use memsec::{mlock, munlock};
use std::borrow::{Borrow, BorrowMut};
use zeroize::Zeroize;

pub type SecureBytes = SecureVec<u8>;

/// Wrapper around a Vec<T>
///
/// - Securely erases the contents of the Vec<T> when it is dropped
/// - Masks the contents of the Vec<T> when it is displayed or debugged
/// - For `Windows` calls `VirtualLock` to protect the contents from being swapped out to disk
/// - For `Unix` calls `mlock` to prevent the contents of the Vec<T> from beign swapped to disk and memory dumped
///
/// ### Note on `Windows` is not possible to prevent memory dumping
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SecureVec<T>
where
    T: Zeroize,
{
    vec: Vec<T>,
}

impl<T> SecureVec<T>
where
    T: Zeroize,
{
    pub fn new(mut vec: Vec<T>) -> Self {
        unsafe {
            let ptr = vec.as_mut_ptr() as *mut u8;
            mlock(ptr, vec.capacity() * std::mem::size_of::<T>());
        }
        SecureVec { vec }
    }

    /// Borrow the inner contents
    pub fn borrow(&self) -> &[T] {
        self.vec.borrow()
    }

    /// Mutably borrow the inner contents
    pub fn borrow_mut(&mut self) -> &mut [T] {
        self.vec.borrow_mut()
    }

    /// Borrow the inner vec
    ///
    /// This is a convenience method to get access to the inner Vec but be careful do not call clone on it
    pub fn borrow_vec(&self) -> &Vec<T> {
        &self.vec
    }

    /// Mutably borrow the inner vec
    ///
    /// This is a convenience method to get access to the inner Vec but be careful do not call clone on it
    pub fn borrow_mut_vec(&mut self) -> &mut Vec<T> {
        &mut self.vec
    }

    /// Erase the inner contents from memory
    pub fn erase(&mut self) {
        self.vec.zeroize();
    }

    /// Convert into a normal Vec
    ///
    /// This will consume the SecureVec
    ///
    /// You are responsible for zeroizing the contents of returned Vec
    pub fn into_vec(mut self) -> Vec<T> {
        unsafe {
            munlock(
                self.vec.as_mut_ptr() as *mut u8,
                self.vec.capacity() * std::mem::size_of::<T>(),
            );
        }
        let vec = std::mem::take(&mut self.vec);
        std::mem::forget(self);
        vec
    }

    /// Push a value onto the SecureVec
    pub fn push(&mut self, value: T) {
        let old_ptr = self.vec.as_mut_ptr() as *mut u8;
        let old_capacity = self.vec.capacity();
        self.vec.push(value);
        if self.vec.capacity() != old_capacity {
            unsafe {
                munlock(old_ptr, old_capacity * std::mem::size_of::<T>());
                let new_ptr = self.vec.as_mut_ptr() as *mut u8;
                mlock(new_ptr, self.vec.capacity() * std::mem::size_of::<T>());
            }
        }
    }
}

impl<T> Borrow<[T]> for SecureVec<T>
where
    T: Zeroize,
{
    fn borrow(&self) -> &[T] {
        self.vec.borrow()
    }
}

impl<T> BorrowMut<[T]> for SecureVec<T>
where
    T: Zeroize,
{
    fn borrow_mut(&mut self) -> &mut [T] {
        self.vec.borrow_mut()
    }
}

impl<T: Clone + Zeroize> Clone for SecureVec<T> {
    fn clone(&self) -> Self {
        Self::new(self.vec.clone())
    }
}

impl<T, U> From<U> for SecureVec<T>
where
    U: Into<Vec<T>>,
    T: Zeroize,
{
    fn from(s: U) -> SecureVec<T> {
        SecureVec::new(s.into())
    }
}

impl<T> Drop for SecureVec<T>
where
    T: Zeroize,
{
    fn drop(&mut self) {
        self.erase();
        unsafe {
            munlock(
                self.vec.as_mut_ptr() as *mut u8,
                self.vec.capacity() * std::mem::size_of::<T>(),
            );
        }
    }
}

impl<T> fmt::Debug for SecureVec<T>
where
    T: Zeroize,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

impl<T> fmt::Display for SecureVec<T>
where
    T: Zeroize,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

impl<T, U> std::ops::Index<U> for SecureVec<T>
where
    T: Zeroize,
    Vec<T>: std::ops::Index<U>,
{
    type Output = <Vec<T> as std::ops::Index<U>>::Output;

    fn index(&self, index: U) -> &Self::Output {
        std::ops::Index::index(&self.vec, index)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SecureVec<u8> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.collect_seq(self.borrow())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SecureVec<u8> {
    fn deserialize<D>(deserializer: D) -> Result<SecureVec<u8>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SecureVecVisitor;
        impl<'de> serde::de::Visitor<'de> for SecureVecVisitor {
            type Value = SecureVec<u8>;
            fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(formatter, "a sequence of bytes")
            }
            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut vec = Vec::new();
                while let Some(byte) = seq.next_element::<u8>()? {
                    vec.push(byte);
                }
                Ok(SecureVec::new(vec))
            }
        }
        deserializer.deserialize_seq(SecureVecVisitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let vec: Vec<u8> = vec![1, 2, 3];
        let secure_vec = SecureVec::new(vec);
        assert_eq!(secure_vec.borrow().len(), 3);
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_secure_vec_serde() {
        use zeroize::Zeroize;

        let vec: Vec<u8> = vec![1, 2, 3];
        let secure_vec = SecureVec::new(vec);
        let mut json = serde_json::to_vec(&secure_vec).expect("Serialization failed");
        let deserialized: SecureVec<u8> =
            serde_json::from_slice(&json).expect("Deserialization failed");
        assert_eq!(deserialized.borrow(), secure_vec.borrow());
        json.zeroize();
    }

    #[test]
    fn test_debug() {
        let vec = vec![1, 2, 3];
        let secure_vec = SecureVec::new(vec);
        assert_eq!(format!("{:?}", secure_vec), "***SECRET***");
    }

    #[test]
    fn test_display() {
        let vec = vec![1, 2, 3];
        let secure_vec = SecureVec::new(vec);
        assert_eq!(format!("{}", secure_vec), "***SECRET***");
    }

    #[test]
    fn test_index() {
        let vec = vec![1, 2, 3];
        let secure_vec = SecureVec::new(vec);
        assert_eq!(secure_vec[0], 1);
        assert_eq!(secure_vec[1], 2);
        assert_eq!(secure_vec[2], 3);
    }

    #[test]
    fn test_erase() {
        let vec = vec![1, 2, 3];
        let mut secure_vec = SecureVec::new(vec);
        secure_vec.erase();
        assert_eq!(secure_vec.borrow().len(), 0);
    }

    #[test]
    fn test_push() {
        let mut secure_vec = SecureVec::new(vec![]);
        for i in 0..100 {
            secure_vec.push(i);
        }
        assert_eq!(secure_vec.borrow().len(), 100);
    }

    #[test]
    fn test_eq() {
        let vec1 = SecureVec::new(vec![1, 2, 3]);
        let vec2 = SecureVec::new(vec![1, 2, 3]);
        assert_eq!(vec1, vec2);
    }

    #[test]
    fn test_into_vec() {
        let vec = vec![1, 2, 3];
        let secure_vec = SecureVec::new(vec);
        let normal_vec = secure_vec.into_vec();
        assert_eq!(normal_vec.len(), 3);
    }
}
