use crate::vec::SecureVec;
use core::fmt;
use std::str::FromStr;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new() {
        let string = SecureString::from("Hello, world!");
        assert_eq!(string.borrow(), "Hello, world!");
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
