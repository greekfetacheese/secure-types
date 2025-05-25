use core::borrow::{Borrow, BorrowMut};
use core::fmt;
use memsec::{mlock, munlock};
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
            mlock(ptr, vec.capacity() * core::mem::size_of::<T>());
        }
        SecureVec { vec }
    }

    /// Borrow the inner contents
    pub fn borrow(&self) -> &[T] {
        self.vec.borrow()
    }

    /// Borrow the inner vec
    ///
    /// This is a convenience method to get access to the inner Vec but be careful do not call clone on it
    pub fn borrow_vec(&self) -> &Vec<T> {
        &self.vec
    }

    pub fn erase(&mut self) {
        self.vec.zeroize();
    }

    /// Convert into a normal Vec
    ///
    /// This will consume the SecureVec
    ///
    /// ## You are responsible for zeroizing the contents of the returned value
    ///
    ///
    /// #### The most simple way to zero out the Vec is create a SecureVec instance again
    /// ```rust
    /// use secure_types::SecureVec;
    /// let secure_vec = SecureVec::from(vec![1, 2, 3]);
    /// let exposed_vec = secure_vec.into_vec();
    /// //! when you are done just create a new SecureVec instance
    /// //! keep in mind even if you dont clone the exposed_vec the memory allocator may leave a copy of the data in memory depending on the usage
    /// let secure_again = SecureVec::from(exposed_vec);
    /// ```
    pub fn into_vec(mut self) -> Vec<T> {
        unsafe {
            munlock(
                self.vec.as_mut_ptr() as *mut u8,
                self.vec.capacity() * core::mem::size_of::<T>(),
            );
        }
        let vec = core::mem::take(&mut self.vec);
        core::mem::forget(self);
        vec
    }

    /// ## Use with caution
    /// 
    /// If you exceed the capacity of the Vec it will reallocate leaving a copy of any data in the heap that was previously in the Vec.
    pub fn push(&mut self, value: T) {
        self.vec.push(value);
    }

    pub fn secure_mut<F>(&mut self, f: F)
    where
        F: FnOnce(&mut Vec<T>),
    {
        f(&mut self.vec);
    }

    pub fn splice(&mut self, byte_idx: usize, new_bytes: &[u8])
    where
        T: From<u8> + Clone,
    {
        self.secure_mut(|vec| {
            let typed_new_bytes = new_bytes.iter().map(|&b| T::from(b)).collect::<Vec<T>>();
            vec.splice(byte_idx..byte_idx, typed_new_bytes);
        });
    }

    pub fn drain(&mut self, range: core::ops::Range<usize>) {
        // Ensure range is valid to prevent panic
        let current_len = self.vec.len();
        let start = range.start.min(current_len);
        let end = range.end.min(current_len);

        if start >= end {
            return;
        }

        let valid_range_to_drain = start..end;
        let num_elements_to_drain = valid_range_to_drain.len();

        if num_elements_to_drain == 0 {
            return;
        }

        self.vec.drain(valid_range_to_drain.clone());

        let new_len = self.vec.len();

        if num_elements_to_drain > 0 {
            let zero_start_index = new_len;
            let zero_count = num_elements_to_drain;

            if self.vec.capacity() >= zero_start_index + zero_count {
                unsafe {
                    let buffer_ptr = self.vec.as_mut_ptr();
                    let zero_section_ptr = buffer_ptr.add(zero_start_index);
                    core::ptr::write_bytes(zero_section_ptr, 0, zero_count);
                }
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
                self.vec.capacity() * core::mem::size_of::<T>(),
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

impl<T, U> core::ops::Index<U> for SecureVec<T>
where
    T: Zeroize,
    Vec<T>: core::ops::Index<U>,
{
    type Output = <Vec<T> as core::ops::Index<U>>::Output;

    fn index(&self, index: U) -> &Self::Output {
        core::ops::Index::index(&self.vec, index)
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
            fn expecting(&self, formatter: &mut ::core::fmt::Formatter) -> ::core::fmt::Result {
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
