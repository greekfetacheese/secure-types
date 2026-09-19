//! The [`serde::Deserializer`] that reads the codec's wire format.
//!
//! Decoding reads straight out of a `&[u8]` the caller already holds unlocked,
//! and every value it produces is owned: the trait methods call `visit_str` /
//! `visit_bytes`, never `visit_borrowed_str` / `visit_borrowed_bytes`. That is
//! what stops a reference into the buffer from outliving the unlock window, and
//! the public entry point additionally requires `DeserializeOwned`, which
//! forbids such borrowing statically.

// `String` is used for `DecodeError::Custom`; in a `no_std` build it has to come
// from `alloc` (with `use_os` the prelude provides it).
#[cfg(not(feature = "use_os"))]
use alloc::string::String;

use serde::de::{self, DeserializeOwned, DeserializeSeed, Visitor};

use super::format::{DecodeError, FORMAT_VERSION, read_varint};

/// Reads the codec wire format from a borrowed, already-unlocked buffer.
pub(crate) struct Decoder<'de> {
   buf: &'de [u8],
   pos: usize,
   /// True when this decoder is bounded to exactly one length-framed struct
   /// field body.
   ///
   /// It is the only position whose extent is known, so it is the only position
   /// where [`de::Deserializer::deserialize_ignored_any`] can skip a value it
   /// has no type for. It is also what lets a field body be checked for being
   /// consumed exactly.
   framed: bool,
}

/// Decodes a whole document from `bytes`.
///
/// `bytes` must be the complete input: trailing bytes are an error, because a
/// document that decodes and still has bytes left means the reader and the
/// writer disagree about the layout.
///
/// # Errors
///
/// Fails if the input is truncated, malformed, carries an unsupported format
/// version, or does not match `T`.
pub(crate) fn decode_from<T>(bytes: &[u8]) -> Result<T, DecodeError>
where
   T: DeserializeOwned,
{
   let mut decoder = Decoder::new(bytes);

   let version = decoder.read_u8()?;
   if version != FORMAT_VERSION {
      return Err(DecodeError::UnsupportedVersion(version));
   }

   let value = T::deserialize(&mut decoder)?;

   if decoder.remaining() != 0 {
      return Err(DecodeError::TrailingBytes {
         extra: decoder.remaining(),
      });
   }

   Ok(value)
}

impl<'de> Decoder<'de> {
   fn new(buf: &'de [u8]) -> Self {
      Self {
         buf,
         pos: 0,
         framed: false,
      }
   }

   fn remaining(&self) -> usize {
      self.buf.len() - self.pos
   }

   fn take(&mut self, len: usize) -> Result<&'de [u8], DecodeError> {
      let end = self
         .pos
         .checked_add(len)
         .ok_or(DecodeError::InvalidLength)?;
      if end > self.buf.len() {
         return Err(DecodeError::UnexpectedEnd);
      }

      let slice = &self.buf[self.pos..end];
      self.pos = end;

      Ok(slice)
   }

   fn read_u8(&mut self) -> Result<u8, DecodeError> {
      Ok(self.take(1)?[0])
   }

   fn read_array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
      let mut array = [0u8; N];
      array.copy_from_slice(self.take(N)?);

      Ok(array)
   }

   fn read_varint(&mut self) -> Result<usize, DecodeError> {
      read_varint(self.buf, &mut self.pos)
   }

   fn read_len_prefixed(&mut self) -> Result<&'de [u8], DecodeError> {
      let len = self.read_varint()?;
      self.take(len)
   }

   fn read_str(&mut self) -> Result<&'de str, DecodeError> {
      core::str::from_utf8(self.read_len_prefixed()?).map_err(|_| DecodeError::InvalidUtf8)
   }

   /// Reads a container's element count.
   ///
   /// A count larger than the bytes left cannot be satisfied by any element type
   /// that occupies at least one byte, so it is rejected before it is handed to
   /// a visitor as a `size_hint` or used to drive a loop. Without that, a
   /// corrupt count could pre-allocate a huge locked buffer or spin through
   /// zero-sized elements.
   fn read_count(&mut self) -> Result<usize, DecodeError> {
      let count = self.read_varint()?;
      if count > self.remaining() {
         return Err(DecodeError::InvalidLength);
      }

      Ok(count)
   }
}

impl<'de> de::Deserializer<'de> for &mut Decoder<'de> {
   type Error = DecodeError;

   /// Not implementable: the format carries no type tags, so there is nothing to
   /// dispatch on. Reached by `#[serde(flatten)]`, `#[serde(untagged)]` and
   /// `Value`-shaped fields, which are documented as unsupported.
   fn deserialize_any<V>(self, _visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      Err(DecodeError::Unsupported(
         "deserialize_any, which #[serde(flatten)], #[serde(untagged)] and Value-shaped fields need",
      ))
   }

   /// Only possible inside a length-framed struct field: that is the one place
   /// where the extent of the value is known without knowing its type. This is
   /// what lets a reader skip a field a newer writer added.
   fn deserialize_ignored_any<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      if !self.framed {
         return Err(DecodeError::Unsupported(
            "deserialize_ignored_any outside a length-framed struct field",
         ));
      }

      self.pos = self.buf.len();
      visitor.visit_unit()
   }

   fn deserialize_bool<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      match self.read_u8()? {
         0x00 => visitor.visit_bool(false),
         0x01 => visitor.visit_bool(true),
         _ => Err(DecodeError::InvalidBool),
      }
   }

   fn deserialize_i8<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      visitor.visit_i8(i8::from_le_bytes(self.read_array::<1>()?))
   }

   fn deserialize_i16<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      visitor.visit_i16(i16::from_le_bytes(self.read_array::<2>()?))
   }

   fn deserialize_i32<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      visitor.visit_i32(i32::from_le_bytes(self.read_array::<4>()?))
   }

   fn deserialize_i64<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      visitor.visit_i64(i64::from_le_bytes(self.read_array::<8>()?))
   }

   fn deserialize_i128<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      visitor.visit_i128(i128::from_le_bytes(self.read_array::<16>()?))
   }

   fn deserialize_u8<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      visitor.visit_u8(u8::from_le_bytes(self.read_array::<1>()?))
   }

   fn deserialize_u16<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      visitor.visit_u16(u16::from_le_bytes(self.read_array::<2>()?))
   }

   fn deserialize_u32<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      visitor.visit_u32(u32::from_le_bytes(self.read_array::<4>()?))
   }

   fn deserialize_u64<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      visitor.visit_u64(u64::from_le_bytes(self.read_array::<8>()?))
   }

   fn deserialize_u128<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      visitor.visit_u128(u128::from_le_bytes(self.read_array::<16>()?))
   }

   fn deserialize_f32<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      visitor.visit_f32(f32::from_bits(u32::from_le_bytes(
         self.read_array::<4>()?,
      )))
   }

   fn deserialize_f64<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      visitor.visit_f64(f64::from_bits(u64::from_le_bytes(
         self.read_array::<8>()?,
      )))
   }

   fn deserialize_char<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      match char::from_u32(u32::from_le_bytes(self.read_array::<4>()?)) {
         Some(value) => visitor.visit_char(value),
         None => Err(DecodeError::InvalidChar),
      }
   }

   /// Always `visit_str`, never `visit_borrowed_str`: the visitor gets the borrow
   /// only for the duration of the call, so nothing can retain a reference into
   /// the buffer after it is re-locked.
   fn deserialize_str<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      visitor.visit_str(self.read_str()?)
   }

   fn deserialize_string<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      self.deserialize_str(visitor)
   }

   fn deserialize_bytes<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      visitor.visit_bytes(self.read_len_prefixed()?)
   }

   fn deserialize_byte_buf<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      self.deserialize_bytes(visitor)
   }

   fn deserialize_option<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      match self.read_u8()? {
         0x00 => visitor.visit_none(),
         0x01 => visitor.visit_some(self),
         _ => Err(DecodeError::InvalidOptionTag),
      }
   }

   fn deserialize_unit<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      visitor.visit_unit()
   }

   fn deserialize_unit_struct<V>(
      self,
      _name: &'static str,
      visitor: V,
   ) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      visitor.visit_unit()
   }

   fn deserialize_newtype_struct<V>(
      self,
      _name: &'static str,
      visitor: V,
   ) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      visitor.visit_newtype_struct(self)
   }

   fn deserialize_seq<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      let count = self.read_count()?;
      visitor.visit_seq(SeqAccess::new(self, count))
   }

   fn deserialize_tuple<V>(self, len: usize, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      let count = self.read_count()?;
      if count != len {
         return Err(DecodeError::InvalidLength);
      }

      visitor.visit_seq(SeqAccess::new(self, count))
   }

   fn deserialize_tuple_struct<V>(
      self,
      _name: &'static str,
      len: usize,
      visitor: V,
   ) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      self.deserialize_tuple(len, visitor)
   }

   fn deserialize_map<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      let count = self.read_count()?;
      visitor.visit_map(MapAccess::new(self, count))
   }

   /// Structs are handed over as a *map*, keyed by field name, rather than as a
   /// positional sequence. That is what makes `#[serde(default)]` and
   /// `#[serde(skip_serializing)]` work in any position: a field that was not
   /// written takes its default, and a field the reader does not know is skipped
   /// through its length frame.
   fn deserialize_struct<V>(
      self,
      _name: &'static str,
      _fields: &'static [&'static str],
      visitor: V,
   ) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      let count = self.read_count()?;
      visitor.visit_map(StructMapAccess::new(self, count))
   }

   fn deserialize_enum<V>(
      self,
      _name: &'static str,
      _variants: &'static [&'static str],
      visitor: V,
   ) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      let variant = self.read_str()?;
      visitor.visit_enum(EnumAccess {
         decoder: self,
         variant,
      })
   }

   fn deserialize_identifier<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      self.deserialize_str(visitor)
   }

   /// The format is binary, and this must agree with the encoder's answer.
   /// A type that branches on it, as `uuid` and `chrono` do, would otherwise
   /// write its compact form and then read back expecting the textual one.
   fn is_human_readable(&self) -> bool {
      false
   }
}

/// The element source for sequences, tuples and tuple variants.
pub(crate) struct SeqAccess<'de, 'a> {
   decoder: &'a mut Decoder<'de>,
   remaining: usize,
}

impl<'de, 'a> SeqAccess<'de, 'a> {
   fn new(decoder: &'a mut Decoder<'de>, count: usize) -> Self {
      Self {
         decoder,
         remaining: count,
      }
   }
}

impl<'de> de::SeqAccess<'de> for SeqAccess<'de, '_> {
   type Error = DecodeError;

   fn next_element_seed<T>(&mut self, seed: T) -> Result<Option<T::Value>, DecodeError>
   where
      T: DeserializeSeed<'de>,
   {
      if self.remaining == 0 {
         return Ok(None);
      }
      self.remaining -= 1;

      seed.deserialize(&mut *self.decoder).map(Some)
   }

   /// Safe to trust: [`Decoder::read_count`] already rejected a count larger
   /// than the input can hold, so a pre-allocation based on this stays bounded.
   fn size_hint(&self) -> Option<usize> {
      Some(self.remaining)
   }
}

/// The entry source for plain maps, whose keys are values of their own type.
pub(crate) struct MapAccess<'de, 'a> {
   decoder: &'a mut Decoder<'de>,
   remaining: usize,
}

impl<'de, 'a> MapAccess<'de, 'a> {
   fn new(decoder: &'a mut Decoder<'de>, count: usize) -> Self {
      Self {
         decoder,
         remaining: count,
      }
   }
}

impl<'de> de::MapAccess<'de> for MapAccess<'de, '_> {
   type Error = DecodeError;

   fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, DecodeError>
   where
      K: DeserializeSeed<'de>,
   {
      if self.remaining == 0 {
         return Ok(None);
      }
      self.remaining -= 1;

      seed.deserialize(&mut *self.decoder).map(Some)
   }

   fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, DecodeError>
   where
      V: DeserializeSeed<'de>,
   {
      seed.deserialize(&mut *self.decoder)
   }

   fn size_hint(&self) -> Option<usize> {
      Some(self.remaining)
   }
}

/// The entry source for structs, where each field carries a name and a `u32`
/// length frame around its body.
pub(crate) struct StructMapAccess<'de, 'a> {
   decoder: &'a mut Decoder<'de>,
   remaining: usize,
   /// End of the frame of the field whose key was just handed out.
   value_end: usize,
   /// Whether a key is handed out and waiting for its value.
   value_pending: bool,
}

impl<'de, 'a> StructMapAccess<'de, 'a> {
   fn new(decoder: &'a mut Decoder<'de>, count: usize) -> Self {
      Self {
         decoder,
         remaining: count,
         value_end: 0,
         value_pending: false,
      }
   }
}

impl<'de> de::MapAccess<'de> for StructMapAccess<'de, '_> {
   type Error = DecodeError;

   fn next_key_seed<K>(&mut self, seed: K) -> Result<Option<K::Value>, DecodeError>
   where
      K: DeserializeSeed<'de>,
   {
      if self.remaining == 0 {
         return Ok(None);
      }

      let name = self.decoder.read_str()?;
      let frame_len = u32::from_le_bytes(self.decoder.read_array::<4>()?) as usize;

      let value_end = self
         .decoder
         .pos
         .checked_add(frame_len)
         .ok_or(DecodeError::InvalidLength)?;
      if value_end > self.decoder.buf.len() {
         return Err(DecodeError::UnexpectedEnd);
      }

      self.value_end = value_end;
      self.value_pending = true;
      self.remaining -= 1;

      seed.deserialize(FieldName { name }).map(Some)
   }

   fn next_value_seed<V>(&mut self, seed: V) -> Result<V::Value, DecodeError>
   where
      V: DeserializeSeed<'de>,
   {
      if !self.value_pending {
         return Err(DecodeError::Custom(String::from(
            "next_value_seed called without a preceding next_key_seed",
         )));
      }
      self.value_pending = false;

      let start = self.decoder.pos;
      let end = self.value_end;

      // Bound the field to its frame. A decoder over just the frame body gets
      // the frame's end as a hard upper bound for free, and `framed` is what
      // lets `deserialize_ignored_any` skip a field body wholesale.
      let frame = &self.decoder.buf[start..end];
      let mut framed = Decoder {
         buf: frame,
         pos: 0,
         framed: true,
      };

      let value = seed.deserialize(&mut framed)?;

      if framed.pos != framed.buf.len() {
         return Err(DecodeError::FrameMismatch {
            unconsumed: framed.buf.len() - framed.pos,
         });
      }

      self.decoder.pos = end;

      Ok(value)
   }

   fn size_hint(&self) -> Option<usize> {
      Some(self.remaining)
   }
}

/// The variant source for enums. The variant name has already been read, so this
/// only has to hand it to the seed and then expose the payload.
pub(crate) struct EnumAccess<'de, 'a> {
   decoder: &'a mut Decoder<'de>,
   variant: &'de str,
}

impl<'de, 'a> de::EnumAccess<'de> for EnumAccess<'de, 'a> {
   type Error = DecodeError;
   type Variant = VariantAccess<'de, 'a>;

   fn variant_seed<V>(self, seed: V) -> Result<(V::Value, Self::Variant), DecodeError>
   where
      V: DeserializeSeed<'de>,
   {
      let variant = seed.deserialize(FieldName { name: self.variant })?;

      Ok((
         variant,
         VariantAccess {
            decoder: self.decoder,
         },
      ))
   }
}

/// The payload source for the enum variant [`EnumAccess`] just identified.
pub(crate) struct VariantAccess<'de, 'a> {
   decoder: &'a mut Decoder<'de>,
}

impl<'de> de::VariantAccess<'de> for VariantAccess<'de, '_> {
   type Error = DecodeError;

   fn unit_variant(self) -> Result<(), DecodeError> {
      // The variant name was the whole encoding.
      Ok(())
   }

   fn newtype_variant_seed<T>(self, seed: T) -> Result<T::Value, DecodeError>
   where
      T: DeserializeSeed<'de>,
   {
      seed.deserialize(&mut *self.decoder)
   }

   fn tuple_variant<V>(self, len: usize, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      let count = self.decoder.read_count()?;
      if count != len {
         return Err(DecodeError::InvalidLength);
      }

      visitor.visit_seq(SeqAccess::new(self.decoder, count))
   }

   fn struct_variant<V>(
      self,
      _fields: &'static [&'static str],
      visitor: V,
   ) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      let count = self.decoder.read_count()?;
      visitor.visit_map(StructMapAccess::new(self.decoder, count))
   }
}

/// A [`de::Deserializer`] that only ever yields a field or variant name read from
/// the wire.
///
/// Keys and variant tags are plain strings in this format, so every request
/// resolves to the same `visit_str`. The `&'de str` is borrowed from the input
/// buffer and is only handed over for the comparison the visitor performs; the
/// derive stores the matched variant, not the string.
struct FieldName<'de> {
   name: &'de str,
}

impl<'de> de::Deserializer<'de> for FieldName<'de> {
   type Error = DecodeError;

   fn deserialize_any<V>(self, visitor: V) -> Result<V::Value, DecodeError>
   where
      V: Visitor<'de>,
   {
      visitor.visit_str(self.name)
   }

   serde::forward_to_deserialize_any! {
      bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
      bytes byte_buf option unit unit_struct newtype_struct seq tuple
      tuple_struct map struct enum identifier ignored_any
   }
}
