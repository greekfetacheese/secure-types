//! Serialize straight into locked memory, so the plaintext never lands in an
//! ordinary `String`/`Vec`.

use core::fmt;

use serde::Serialize;

use crate::{Error, SecureBytes, SecureBytesWriter, SecureString};

/// The initial buffer size used by [`serialize_json_into_secure_string`].
const DEFAULT_JSON_CAPACITY: usize = 1024;

/// Why a JSON serialization into locked memory failed.
#[derive(Debug)]
pub enum JsonError {
   /// The locked buffer could not be allocated or locked.
   Secure(Error),
   /// The value could not be serialized to JSON.
   Serialize(serde_json::Error),
   /// The serialized bytes were not valid UTF-8. Plain JSON always is, so this means
   /// a `Serialize` impl emitted something that is not valid UTF-8.
   NotUtf8,
}

impl fmt::Display for JsonError {
   fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
      match self {
         Self::Secure(error) => write!(f, "Failed to allocate the secure buffer: {error}"),
         Self::Serialize(error) => write!(f, "Failed to serialize to JSON: {error}"),
         Self::NotUtf8 => write!(f, "Serialized bytes are not valid UTF-8"),
      }
   }
}

impl core::error::Error for JsonError {
   fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
      match self {
         Self::Secure(error) => Some(error),
         Self::Serialize(error) => Some(error),
         Self::NotUtf8 => None,
      }
   }
}

/// Serializes `value` to JSON directly into a [`SecureString`].
///
/// `serde_json::to_string`/`to_vec` build the plaintext in an ordinary
/// `String`/`Vec` that nothing zeroizes, and `impl Serialize` cannot wipe that buffer
/// (it only ever sees a generic serializer). This writes through a
/// [`SecureBytesWriter`] instead, so the JSON only ever exists in locked memory that is
/// zeroized on drop — [`SecureString::erase`] wipes it earlier if you want.
///
/// The buffer starts at 1 KiB and grows as needed; use
/// [`serialize_json_into_secure_string_with_capacity`] to size it for your payload and
/// avoid reallocating locked pages.
///
/// # Example
///
/// ```
/// use secure_types::serialize_json_into_secure_string;
/// use serde::Serialize;
///
/// #[derive(Serialize)]
/// struct Vault {
///     password: String,
/// }
///
/// let secure_json = serialize_json_into_secure_string(&Vault {
///     password: "hunter2".to_owned(),
/// })
/// .unwrap();
///
/// secure_json.unlock_str(|json| assert_eq!(json, r#"{"password":"hunter2"}"#));
/// ```
pub fn serialize_json_into_secure_string<T>(value: &T) -> Result<SecureString, JsonError>
where
   T: ?Sized + Serialize,
{
   serialize_json_into_secure_string_with_capacity(value, DEFAULT_JSON_CAPACITY)
}

/// Same as [`serialize_json_into_secure_string`], with an explicit initial buffer size.
///
/// Sizing the buffer to the expected payload avoids growing (and re-locking) it, which
/// keeps both the `mprotect` traffic and the `RLIMIT_MEMLOCK` pressure predictable.
pub fn serialize_json_into_secure_string_with_capacity<T>(
   value: &T,
   capacity: usize,
) -> Result<SecureString, JsonError>
where
   T: ?Sized + Serialize,
{
   let mut buffer = SecureBytes::new_with_capacity(capacity).map_err(JsonError::Secure)?;

   {
      let mut serializer = serde_json::Serializer::new(SecureBytesWriter::new(&mut buffer));
      value
         .serialize(&mut serializer)
         .map_err(JsonError::Serialize)?;
   }

   SecureString::try_from(buffer).map_err(|_| JsonError::NotUtf8)
}

#[cfg(test)]
mod tests {
   use super::*;
   use serde::Deserialize;

   #[derive(Serialize, Deserialize)]
   struct Vault {
      password: String,
      key: Vec<u8>,
      label: Option<String>,
   }

   fn test_vault() -> Vault {
      Vault {
         password: "hunter2".to_owned(),
         key: vec![1, 2, 3, 0xAB],
         label: None,
      }
   }

   #[test]
   fn test_matches_plain_serde_json() {
      let vault = test_vault();
      let secure_json = serialize_json_into_secure_string(&vault).unwrap();

      secure_json.unlock_str(|json| {
         assert_eq!(json, serde_json::to_string(&vault).unwrap());
      });
   }

   #[test]
   fn test_with_capacity_matches() {
      let vault = test_vault();
      let secure_json = serialize_json_into_secure_string_with_capacity(&vault, 4096).unwrap();

      secure_json.unlock_str(|json| {
         assert_eq!(json, serde_json::to_string(&vault).unwrap());
      });
   }

   /// The custom `Serialize` impls write into whichever serializer they are handed, so
   /// driving them through `SecureBytesWriter` keeps their contents out of an ordinary
   /// `String` — this pins that the two compose and produce the same JSON as the plain path.
   #[test]
   fn test_secure_types_serialize_through_the_writer() {
      use crate::{SecureArray, SecureVec};

      let secret_string = SecureString::from("hunter2");
      let secret_vec = SecureVec::from_slice(&[1u8, 2, 3]).unwrap();
      let secret_array = SecureArray::<u8, 3>::from_slice(&[4, 5, 6]).unwrap();

      let pairs = [
         (
            serialize_json_into_secure_string(&secret_string).unwrap(),
            serde_json::to_string(&secret_string).unwrap(),
         ),
         (
            serialize_json_into_secure_string(&secret_vec).unwrap(),
            serde_json::to_string(&secret_vec).unwrap(),
         ),
         (
            serialize_json_into_secure_string(&secret_array).unwrap(),
            serde_json::to_string(&secret_array).unwrap(),
         ),
      ];

      for (secure_json, plain_json) in pairs {
         secure_json.unlock_str(|json| assert_eq!(json, plain_json));
      }
   }

   #[test]
   fn test_empty_and_tiny_capacity() {
      // `new_with_capacity(0)` bumps to 1 internally, so this must still work.
      let secure_json = serialize_json_into_secure_string_with_capacity(&test_vault(), 0).unwrap();

      secure_json.unlock_str(|json| {
         assert_eq!(
            json,
            serde_json::to_string(&test_vault()).unwrap()
         );
      });
   }

   #[test]
   fn test_deserializes_back() {
      let vault = test_vault();
      let secure_json = serialize_json_into_secure_string(&vault).unwrap();

      secure_json.unlock_str(|json| {
         let vault: Vault = serde_json::from_str(json).unwrap();
         assert_eq!(vault.password, "hunter2");
         assert_eq!(vault.key, [1, 2, 3, 0xAB]);
      });
   }

   #[test]
   fn test_serialize_error_is_reported() {
      use std::collections::BTreeMap;

      // JSON object keys must be strings, so this fails inside serde_json.
      let mut map = BTreeMap::new();
      map.insert((1u8, 2u8), 3u8);

      let result = serialize_json_into_secure_string(&map);
      assert!(matches!(result, Err(JsonError::Serialize(_))));
   }
}
