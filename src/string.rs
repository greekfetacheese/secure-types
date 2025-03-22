use super::SecureVec;
use core::fmt;
use std::str::FromStr;

#[cfg(feature = "egui")]
use core::ops::Range;
#[cfg(feature = "egui")]
use egui::{TextBuffer, text_selection::text_cursor_state::byte_index_from_char_index};
#[cfg(feature = "egui")]
use zeroize::Zeroize;

/// #### SecureString
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
/// use secure_types::SecureString;
///
/// let secret_string = SecureString::from("My sensitive data");
/// let borrowed_string = secret_string.borrow();
/// assert_eq!(borrowed_string, "My sensitive data");
/// ```
///  When it goes out of scope it will be zeroized
///  If you want to keep a secure string in a struct that lives for the entire lifetime of the program
///  make sure to call erase() when you are done with it
#[derive(Clone, Eq)]
pub struct SecureString {
    vec: SecureVec<u8>,
}

impl SecureString {
    pub fn new_with_capacity(capacity: usize) -> Self {
        let mut vec = SecureVec::new(Vec::with_capacity(capacity));
        vec.borrow_mut_vec().reserve(capacity);
        SecureString { vec }
    }

    pub fn borrow(&self) -> &str {
        unsafe { core::str::from_utf8_unchecked(self.vec.borrow()) }
    }

    pub fn borrow_mut(&mut self) -> &mut str {
        unsafe { core::str::from_utf8_unchecked_mut(self.vec.borrow_mut()) }
    }

    pub fn erase(&mut self) {
        self.vec.erase();
    }

    /// Convert the SecureString into a String
    ///
    /// This will create a new allocated String you are responsible for zeroizing its contents
    pub fn to_string(&self) -> String {
        self.borrow().to_string()
    }

    #[cfg(feature = "egui")]
    pub fn insert_str(&mut self, byte_idx: usize, text: &str) {
        assert!(self.borrow().is_char_boundary(byte_idx));
        let bytes = text.as_bytes();
        let vec = self.vec.borrow_mut_vec();
        vec.reserve(bytes.len());
        let old_len = vec.len();
        vec.splice(byte_idx..byte_idx, bytes.iter().copied());
        if byte_idx < old_len {
            vec.zeroize();
        }
    }

    /// Mutate the SecureString via a String in a scoped closure.
    ///
    /// After the closure runs, the modified String is securely copied back into the SecureString.
    ///
    /// ## Example
    /// ```rust
    /// use secure_types::SecureString;
    /// let mut secure = SecureString::from("initial");
    /// secure.string_mut(|s| s.push_str(" text"));
    /// assert_eq!(secure.borrow(), "initial text");
    /// ```
    pub fn string_mut<F>(&mut self, f: F)
    where
        F: FnOnce(&mut String),
    {
        let mut temp = self.borrow().to_string();
        f(&mut temp);
        self.vec = SecureVec::new(temp.into_bytes());
    }

    /// Mutate the SecureString directly in a scoped closure.
    pub fn secure_mut<F>(&mut self, f: F)
    where
        F: FnOnce(&mut SecureString),
    {
        let mut temp = SecureString::from("");
        std::mem::swap(self, &mut temp); // Swap out original
        f(&mut temp);
        std::mem::swap(self, &mut temp); // Swap back modified
        temp.erase();
    }
}

impl Default for SecureString {
    fn default() -> Self {
        Self::from(String::new())
    }
}

impl PartialEq for SecureString {
    fn eq(&self, other: &SecureString) -> bool {
        self.vec == other.vec
    }
}

impl fmt::Debug for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

impl fmt::Display for SecureString {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("***SECRET***").map_err(|_| fmt::Error)
    }
}

impl<U> From<U> for SecureString
where
    U: Into<String>,
{
    fn from(s: U) -> SecureString {
        SecureString {
            vec: SecureVec::new(s.into().into_bytes()),
        }
    }
}

impl FromStr for SecureString {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(SecureString {
            vec: SecureVec::new(s.into()),
        })
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for SecureString {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(self.borrow())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SecureString {
    fn deserialize<D>(deserializer: D) -> Result<SecureString, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct SecureStringVisitor;
        impl<'de> serde::de::Visitor<'de> for SecureStringVisitor {
            type Value = SecureString;
            fn expecting(&self, formatter: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
                write!(formatter, "an utf-8 encoded string")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                Ok(SecureString::from(v.to_string()))
            }
        }
        deserializer.deserialize_string(SecureStringVisitor)
    }
}


#[cfg(feature = "egui")]
impl TextBuffer for SecureString {
    fn is_mutable(&self) -> bool {
        true
    }

    fn as_str(&self) -> &str {
        self.borrow()
    }

    fn insert_text(&mut self, text: &str, char_index: usize) -> usize {
        // println!("Inserting {:?} at char {}, ptr {:?}", text, char_index, text.as_ptr());
        let byte_idx = byte_index_from_char_index(self.as_str(), char_index);
        self.insert_str(byte_idx, text);
        text.chars().count()
    }

    fn delete_char_range(&mut self, char_range: Range<usize>) {
        assert!(char_range.start <= char_range.end);
        //println!("Deleting char range {:?}", char_range);
        let byte_start = byte_index_from_char_index(self.as_str(), char_range.start);
        let byte_end = byte_index_from_char_index(self.as_str(), char_range.end);

        let vec = self.vec.borrow_mut_vec();
        vec.drain(byte_start..byte_end).for_each(drop);
        let len = vec.len();
        vec[len..].iter_mut().for_each(|byte| *byte = 0);
    }

    fn clear(&mut self) {
        self.erase();
    }

    fn replace_with(&mut self, text: &str) {
        // println!("Replacing with {:?}", text);
        self.vec = SecureVec::new(text.as_bytes().to_vec());
    }

    fn take(&mut self) -> String {
        let copy = self.borrow().to_string();
        self.erase();
        copy
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let string = SecureString::from("Hello, world!");
        assert_eq!(string.borrow(), "Hello, world!");
    }

    #[test]
    fn test_string_mut() {
        let mut secure = SecureString::from("Hello");
        secure.string_mut(|s| s.push_str(", world!"));
        assert_eq!(secure.borrow(), "Hello, world!");
    }

    #[cfg(feature = "serde")]
    #[test]
    fn test_secure_string_serde() {
        use zeroize::Zeroize;

        let hello_world = "Hello, world!";
        let secure_string = SecureString::from(hello_world);
        let mut json = serde_json::to_string(&secure_string).unwrap();
        let deserialized: SecureString = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.borrow(), hello_world);
        json.zeroize();
    }

    #[test]
    fn test_debug() {
        let string = SecureString::from("Hello, world!");
        assert_eq!(format!("{:?}", string), "***SECRET***");
    }

    #[test]
    fn test_display() {
        let string = SecureString::from("Hello, world!");
        assert_eq!(format!("{}", string), "***SECRET***");
    }

    #[test]
    fn test_eq() {
        let string1 = SecureString::from("Hello, world!");
        let string2 = SecureString::from("Hello, world!");
        assert_eq!(string1, string2);
    }

    #[test]
    fn test_into_string() {
        let hello_world = "Hello, world!";
        let secure_string = SecureString::from(hello_world);
        let exposed_string = secure_string.to_string();
        assert_eq!(exposed_string, hello_world);
        assert_eq!(secure_string.borrow(), exposed_string);
    }
}
