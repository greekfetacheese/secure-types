//! The [`serde::Serializer`] that writes the codec's wire format.
//!
//! Every byte goes through [`SecureBytes::extend_from_slice`], so the encoded
//! document only ever exists in memory that is locked while unused and zeroized
//! on drop. Growth is safe too: [`SecureVec::reserve`] wipes the old allocation
//! after moving the elements out of it.

use core::fmt;

#[cfg(not(feature = "use_os"))]
use alloc::vec::Vec;

use serde::ser::{self, Serialize};
use zeroize::Zeroize;

use super::format::{EncodeError, FORMAT_VERSION, write_varint};
use crate::SecureBytes;

/// Bytes reserved for a struct field's `u32` length frame.
const FIELD_FRAME_LEN: usize = 4;

/// Initial capacity of the locked scratch buffer used when a container's length
/// is not known up front.
const SCRATCH_CAPACITY: usize = 64;

/// Writes the codec wire format into a borrowed locked buffer.
pub(crate) struct Encoder<'a> {
   bytes: &'a mut SecureBytes,
   /// One entry per struct field whose length frame is still open, innermost
   /// last. Entries below the current scope belong to enclosing structs and are
   /// left untouched until their own scope closes.
   frames: Vec<Frame>,
}

/// An open struct-field length frame.
#[derive(Clone, Copy)]
struct Frame {
   /// Offset of the 4-byte little-endian length placeholder.
   placeholder: usize,
   /// Offset of the first byte of the framed body.
   value_start: usize,
   /// Body length in bytes, filled in when the frame is closed.
   len: u32,
}

impl Zeroize for Frame {
   fn zeroize(&mut self) {
      self.placeholder.zeroize();
      self.value_start.zeroize();
      self.len.zeroize();
   }
}

impl Drop for Encoder<'_> {
   fn drop(&mut self) {
      // A frame records where a secret starts and how long it is. That is
      // metadata about the secret, so it is wiped rather than left in freed
      // memory — including on the error paths that skip the closing pass.
      for frame in &mut self.frames {
         frame.zeroize();
      }
   }
}

/// Encodes `value` into `buffer`, preceded by [`FORMAT_VERSION`].
///
/// `buffer` is expected to be empty; the document is appended to whatever it
/// already holds, which is what lets a caller size it for the payload up front.
///
/// # Errors
///
/// Fails if the locked buffer cannot grow, if a value does not fit the format,
/// or if a container's `Serialize` impl writes a different number of elements
/// than the length it declared.
pub(crate) fn encode_into<T>(buffer: &mut SecureBytes, value: &T) -> Result<(), EncodeError>
where
   T: ?Sized + Serialize,
{
   buffer.extend_from_slice(&[FORMAT_VERSION]);

   let mut encoder = Encoder::new(buffer);
   value.serialize(&mut encoder)
}

impl<'a> Encoder<'a> {
   fn new(bytes: &'a mut SecureBytes) -> Self {
      Self {
         bytes,
         frames: Vec::new(),
      }
   }

   /// Appends raw bytes to the document.
   fn write_bytes(&mut self, bytes: &[u8]) {
      self.bytes.extend_from_slice(bytes);
   }

   /// Appends `value` as an unsigned LEB128 varint.
   fn write_varint(&mut self, value: usize) {
      write_varint(self.bytes, value);
   }

   /// Appends a length-prefixed UTF-8 name: a struct field name or an enum
   /// variant name.
   fn write_name(&mut self, name: &str) {
      self.write_varint(name.len());
      self.write_bytes(name.as_bytes());
   }

   /// Opens a struct field: writes its name, reserves its length frame, and
   /// records the frame so [`close_frames`](Self::close_frames) can fill it in.
   ///
   /// `scope` is the frame count when the enclosing struct was opened. Only the
   /// *previous field of this struct* is finished by this call — a nested
   /// struct's first field must not close the frame of the field holding it.
   fn open_field(&mut self, scope: usize, name: &str) -> Result<(), EncodeError> {
      let cursor = self.bytes.len();

      if self.frames.len() > scope
         && let Some(previous) = self.frames.last_mut()
      {
         previous.len = u32::try_from(cursor - previous.value_start)
            .map_err(|_| EncodeError::LengthOverflow)?;
      }

      self.write_name(name);

      let placeholder = self.bytes.len();
      self.write_bytes(&[0u8; FIELD_FRAME_LEN]);

      self.frames.push(Frame {
         placeholder,
         value_start: self.bytes.len(),
         len: 0,
      });

      Ok(())
   }

   /// Finishes every frame opened by the struct scope starting at `scope`, then
   /// drops back to it.
   ///
   /// Only the innermost frame can still be open: each earlier frame in the
   /// scope was already filled in by the field that followed it. Frames below
   /// `scope` belong to enclosing structs and are left open on purpose.
   fn close_frames(&mut self, scope: usize) -> Result<(), EncodeError> {
      if self.frames.len() <= scope {
         return Ok(());
      }

      let cursor = self.bytes.len();

      if let Some(last) = self.frames.last_mut() {
         last.len =
            u32::try_from(cursor - last.value_start).map_err(|_| EncodeError::LengthOverflow)?;
      }

      // Split the borrows: the frames of this scope are read while the buffer is
      // written, and they are disjoint fields of the encoder.
      let bytes = &mut *self.bytes;
      let frames = &self.frames;

      for frame in &frames[scope..] {
         bytes.patch_at(frame.placeholder, &frame.len.to_le_bytes());
      }

      // Wipe before dropping: the spare capacity of the vector would otherwise
      // keep the offsets and lengths of the fields just written.
      for frame in &mut self.frames[scope..] {
         frame.zeroize();
      }
      self.frames.truncate(scope);

      Ok(())
   }
}

impl<'a, 'b> ser::Serializer for &'b mut Encoder<'a> {
   type Ok = ();
   type Error = EncodeError;

   type SerializeSeq = CompoundEncoder<'b, 'a>;
   type SerializeTuple = CompoundEncoder<'b, 'a>;
   type SerializeTupleStruct = CompoundEncoder<'b, 'a>;
   type SerializeTupleVariant = CompoundEncoder<'b, 'a>;
   type SerializeMap = CompoundEncoder<'b, 'a>;
   type SerializeStruct = StructEncoder<'b, 'a>;
   type SerializeStructVariant = StructEncoder<'b, 'a>;

   fn serialize_bool(self, value: bool) -> Result<Self::Ok, Self::Error> {
      self.write_bytes(&[u8::from(value)]);
      Ok(())
   }

   fn serialize_i8(self, value: i8) -> Result<Self::Ok, Self::Error> {
      self.write_bytes(&value.to_le_bytes());
      Ok(())
   }

   fn serialize_i16(self, value: i16) -> Result<Self::Ok, Self::Error> {
      self.write_bytes(&value.to_le_bytes());
      Ok(())
   }

   fn serialize_i32(self, value: i32) -> Result<Self::Ok, Self::Error> {
      self.write_bytes(&value.to_le_bytes());
      Ok(())
   }

   fn serialize_i64(self, value: i64) -> Result<Self::Ok, Self::Error> {
      self.write_bytes(&value.to_le_bytes());
      Ok(())
   }

   fn serialize_i128(self, value: i128) -> Result<Self::Ok, Self::Error> {
      self.write_bytes(&value.to_le_bytes());
      Ok(())
   }

   fn serialize_u8(self, value: u8) -> Result<Self::Ok, Self::Error> {
      self.write_bytes(&value.to_le_bytes());
      Ok(())
   }

   fn serialize_u16(self, value: u16) -> Result<Self::Ok, Self::Error> {
      self.write_bytes(&value.to_le_bytes());
      Ok(())
   }

   fn serialize_u32(self, value: u32) -> Result<Self::Ok, Self::Error> {
      self.write_bytes(&value.to_le_bytes());
      Ok(())
   }

   fn serialize_u64(self, value: u64) -> Result<Self::Ok, Self::Error> {
      self.write_bytes(&value.to_le_bytes());
      Ok(())
   }

   fn serialize_u128(self, value: u128) -> Result<Self::Ok, Self::Error> {
      self.write_bytes(&value.to_le_bytes());
      Ok(())
   }

   /// Floats are written as their raw IEEE-754 bit pattern, never reformatted,
   /// so a round-trip cannot round or normalise the value.
   fn serialize_f32(self, value: f32) -> Result<Self::Ok, Self::Error> {
      self.write_bytes(&value.to_bits().to_le_bytes());
      Ok(())
   }

   fn serialize_f64(self, value: f64) -> Result<Self::Ok, Self::Error> {
      self.write_bytes(&value.to_bits().to_le_bytes());
      Ok(())
   }

   fn serialize_char(self, value: char) -> Result<Self::Ok, Self::Error> {
      self.write_bytes(&u32::from(value).to_le_bytes());
      Ok(())
   }

   /// Strings are written as raw UTF-8 with a length prefix: no escaping pass,
   /// no scratch buffer, and nothing for an un-wiped copy to survive in.
   fn serialize_str(self, value: &str) -> Result<Self::Ok, Self::Error> {
      self.write_varint(value.len());
      self.write_bytes(value.as_bytes());
      Ok(())
   }

   fn serialize_bytes(self, value: &[u8]) -> Result<Self::Ok, Self::Error> {
      self.write_varint(value.len());
      self.write_bytes(value);
      Ok(())
   }

   fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
      self.write_bytes(&[0x00]);
      Ok(())
   }

   fn serialize_some<T>(self, value: &T) -> Result<Self::Ok, Self::Error>
   where
      T: ?Sized + Serialize,
   {
      self.write_bytes(&[0x01]);
      value.serialize(self)
   }

   fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
      Ok(())
   }

   fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
      Ok(())
   }

   fn serialize_unit_variant(
      self,
      _name: &'static str,
      _variant_index: u32,
      variant: &'static str,
   ) -> Result<Self::Ok, Self::Error> {
      self.write_name(variant);
      Ok(())
   }

   fn serialize_newtype_struct<T>(
      self,
      _name: &'static str,
      value: &T,
   ) -> Result<Self::Ok, Self::Error>
   where
      T: ?Sized + Serialize,
   {
      value.serialize(self)
   }

   fn serialize_newtype_variant<T>(
      self,
      _name: &'static str,
      _variant_index: u32,
      variant: &'static str,
      value: &T,
   ) -> Result<Self::Ok, Self::Error>
   where
      T: ?Sized + Serialize,
   {
      self.write_name(variant);
      value.serialize(self)
   }

   fn serialize_seq(self, len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
      CompoundEncoder::from_optional_len(self, len)
   }

   fn serialize_tuple(self, len: usize) -> Result<Self::SerializeTuple, Self::Error> {
      Ok(CompoundEncoder::from_len(self, len))
   }

   fn serialize_tuple_struct(
      self,
      _name: &'static str,
      len: usize,
   ) -> Result<Self::SerializeTupleStruct, Self::Error> {
      Ok(CompoundEncoder::from_len(self, len))
   }

   fn serialize_tuple_variant(
      self,
      _name: &'static str,
      _variant_index: u32,
      variant: &'static str,
      len: usize,
   ) -> Result<Self::SerializeTupleVariant, Self::Error> {
      self.write_name(variant);
      Ok(CompoundEncoder::from_len(self, len))
   }

   fn serialize_map(self, len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
      CompoundEncoder::from_optional_len(self, len)
   }

   fn serialize_struct(
      self,
      _name: &'static str,
      len: usize,
   ) -> Result<Self::SerializeStruct, Self::Error> {
      self.write_varint(len);
      Ok(StructEncoder::new(self, len))
   }

   fn serialize_struct_variant(
      self,
      _name: &'static str,
      _variant_index: u32,
      variant: &'static str,
      len: usize,
   ) -> Result<Self::SerializeStructVariant, Self::Error> {
      self.write_name(variant);
      self.write_varint(len);
      Ok(StructEncoder::new(self, len))
   }

   /// `serde`'s default implementation is `serialize_str(&value.to_string())`,
   /// which materialises the `Display` output in an ordinary `String` that
   /// nothing zeroizes. This streams it into locked memory instead, so the only
   /// copy is one that is wiped on drop.
   fn collect_str<T>(self, value: &T) -> Result<Self::Ok, Self::Error>
   where
      T: ?Sized + fmt::Display,
   {
      let mut scratch =
         SecureBytes::new_with_capacity(SCRATCH_CAPACITY).map_err(EncodeError::Secure)?;

      {
         let mut sink = DisplaySink {
            bytes: &mut scratch,
         };
         core::fmt::write(&mut sink, format_args!("{value}"))
            .map_err(|_| EncodeError::Unsupported("a Display impl that failed to format"))?;
      }

      self.write_varint(scratch.len());
      scratch.unlock_slice(|bytes| self.write_bytes(bytes));

      Ok(())
   }

   /// The format is binary, so types that have both a compact and a
   /// human-readable form should use the compact one.
   fn is_human_readable(&self) -> bool {
      false
   }
}

/// A [`fmt::Write`] sink that appends into locked memory, used only by
/// [`Serializer::collect_str`] so that `Display` output never lands in a
/// `String`.
struct DisplaySink<'a> {
   bytes: &'a mut SecureBytes,
}

impl fmt::Write for DisplaySink<'_> {
   fn write_str(&mut self, s: &str) -> fmt::Result {
      self.bytes.extend_from_slice(s.as_bytes());
      Ok(())
   }
}

/// The element sink shared by sequences, tuples, tuple structs, tuple variants
/// and maps, which differ only in how they are opened and what counts as one
/// element.
///
/// `pub(crate)` only because it appears as an associated type of the
/// [`ser::Serializer`] impl, which forces it to be at least as visible as the
/// impl being reachable.
pub(crate) struct CompoundEncoder<'b, 'a> {
   encoder: &'b mut Encoder<'a>,
   mode: CompoundMode,
}

enum CompoundMode {
   /// The length was known up front and has already been written.
   Direct {
      /// Elements still expected: entries for a map, values for a sequence.
      remaining: usize,
   },
   /// The length was not known, so elements are collected in locked scratch
   /// memory and the count is written by `end`. Reachable from `serde`'s own
   /// `collect_seq`/`collect_map`, which pass `None` whenever the iterator's
   /// `size_hint` is not exact.
   Buffered {
      /// Locked, zeroized-on-drop scratch holding the elements written so far.
      buffer: SecureBytes,
      /// Elements collected so far (entries for a map).
      count: usize,
   },
}

impl<'b, 'a> CompoundEncoder<'b, 'a> {
   fn from_optional_len(
      encoder: &'b mut Encoder<'a>,
      len: Option<usize>,
   ) -> Result<Self, EncodeError> {
      let mode = match len {
         Some(len) => {
            encoder.write_varint(len);
            CompoundMode::Direct { remaining: len }
         }
         None => CompoundMode::Buffered {
            buffer: SecureBytes::new_with_capacity(SCRATCH_CAPACITY)
               .map_err(EncodeError::Secure)?,
            count: 0,
         },
      };

      Ok(Self { encoder, mode })
   }

   /// Opens a container whose length is fixed and known, writing the count.
   fn from_len(encoder: &'b mut Encoder<'a>, len: usize) -> Self {
      encoder.write_varint(len);

      Self {
         encoder,
         mode: CompoundMode::Direct { remaining: len },
      }
   }

   /// Accounts for one more element, failing if the declared length is already
   /// used up. Writing a different number of elements than declared would leave
   /// a length prefix that lies about the payload, so it is an error rather
   /// than a buffer that decodes subtly wrong.
   fn open_element(&mut self) -> Result<(), EncodeError> {
      match &mut self.mode {
         CompoundMode::Direct { remaining } => {
            if *remaining == 0 {
               return Err(EncodeError::ElementCountMismatch);
            }
            *remaining -= 1;
         }
         CompoundMode::Buffered { count, .. } => *count += 1,
      }

      Ok(())
   }

   fn write_value<T>(&mut self, value: &T) -> Result<(), EncodeError>
   where
      T: ?Sized + Serialize,
   {
      match &mut self.mode {
         CompoundMode::Direct { .. } => value.serialize(&mut *self.encoder),
         CompoundMode::Buffered { buffer, .. } => {
            let mut encoder = Encoder::new(buffer);
            value.serialize(&mut encoder)
         }
      }
   }

   fn finish(self) -> Result<(), EncodeError> {
      match self.mode {
         CompoundMode::Direct { remaining } => {
            if remaining != 0 {
               return Err(EncodeError::ElementCountMismatch);
            }

            Ok(())
         }
         CompoundMode::Buffered { buffer, count } => {
            self.encoder.write_varint(count);
            buffer.unlock_slice(|bytes| self.encoder.write_bytes(bytes));

            // `buffer` is dropped here: locked, then zeroized.
            Ok(())
         }
      }
   }
}

impl<'b, 'a> ser::SerializeSeq for CompoundEncoder<'b, 'a> {
   type Ok = ();
   type Error = EncodeError;

   fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
   where
      T: ?Sized + Serialize,
   {
      self.open_element()?;
      self.write_value(value)
   }

   fn end(self) -> Result<Self::Ok, Self::Error> {
      self.finish()
   }
}

impl<'b, 'a> ser::SerializeTuple for CompoundEncoder<'b, 'a> {
   type Ok = ();
   type Error = EncodeError;

   fn serialize_element<T>(&mut self, value: &T) -> Result<(), Self::Error>
   where
      T: ?Sized + Serialize,
   {
      self.open_element()?;
      self.write_value(value)
   }

   fn end(self) -> Result<Self::Ok, Self::Error> {
      self.finish()
   }
}

impl<'b, 'a> ser::SerializeTupleStruct for CompoundEncoder<'b, 'a> {
   type Ok = ();
   type Error = EncodeError;

   fn serialize_field<T>(&mut self, value: &T) -> Result<(), Self::Error>
   where
      T: ?Sized + Serialize,
   {
      self.open_element()?;
      self.write_value(value)
   }

   fn end(self) -> Result<Self::Ok, Self::Error> {
      self.finish()
   }
}

impl<'b, 'a> ser::SerializeTupleVariant for CompoundEncoder<'b, 'a> {
   type Ok = ();
   type Error = EncodeError;

   fn serialize_field<T>(&mut self, value: &T) -> Result<(), Self::Error>
   where
      T: ?Sized + Serialize,
   {
      self.open_element()?;
      self.write_value(value)
   }

   fn end(self) -> Result<Self::Ok, Self::Error> {
      self.finish()
   }
}

impl<'b, 'a> ser::SerializeMap for CompoundEncoder<'b, 'a> {
   type Ok = ();
   type Error = EncodeError;

   fn serialize_key<T>(&mut self, key: &T) -> Result<(), Self::Error>
   where
      T: ?Sized + Serialize,
   {
      // One entry per key/value pair, so the count moves here rather than in
      // `serialize_value`.
      self.open_element()?;
      self.write_value(key)
   }

   fn serialize_value<T>(&mut self, value: &T) -> Result<(), Self::Error>
   where
      T: ?Sized + Serialize,
   {
      self.write_value(value)
   }

   fn end(self) -> Result<Self::Ok, Self::Error> {
      self.finish()
   }
}

/// The field sink for structs and struct variants, which carry a name and a
/// length frame per field.
///
/// `pub(crate)` for the same reason as [`CompoundEncoder`].
pub(crate) struct StructEncoder<'b, 'a> {
   encoder: &'b mut Encoder<'a>,
   /// Frame count when this struct was opened. Frames below it belong to
   /// enclosing structs and must be left open.
   scope: usize,
   remaining: usize,
}

impl<'b, 'a> StructEncoder<'b, 'a> {
   fn new(encoder: &'b mut Encoder<'a>, len: usize) -> Self {
      let scope = encoder.frames.len();

      Self {
         encoder,
         scope,
         remaining: len,
      }
   }

   fn write_field<T>(&mut self, key: &'static str, value: &T) -> Result<(), EncodeError>
   where
      T: ?Sized + Serialize,
   {
      if self.remaining == 0 {
         return Err(EncodeError::ElementCountMismatch);
      }
      self.remaining -= 1;

      self.encoder.open_field(self.scope, key)?;
      value.serialize(&mut *self.encoder)
   }
}

impl<'b, 'a> ser::SerializeStruct for StructEncoder<'b, 'a> {
   type Ok = ();
   type Error = EncodeError;

   fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error>
   where
      T: ?Sized + Serialize,
   {
      self.write_field(key, value)
   }

   fn end(self) -> Result<Self::Ok, Self::Error> {
      if self.remaining != 0 {
         return Err(EncodeError::ElementCountMismatch);
      }

      self.encoder.close_frames(self.scope)
   }
}

impl<'b, 'a> ser::SerializeStructVariant for StructEncoder<'b, 'a> {
   type Ok = ();
   type Error = EncodeError;

   fn serialize_field<T>(&mut self, key: &'static str, value: &T) -> Result<(), Self::Error>
   where
      T: ?Sized + Serialize,
   {
      self.write_field(key, value)
   }

   fn end(self) -> Result<Self::Ok, Self::Error> {
      if self.remaining != 0 {
         return Err(EncodeError::ElementCountMismatch);
      }

      self.encoder.close_frames(self.scope)
   }
}
