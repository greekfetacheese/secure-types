//! `SecureString` mutations against a `String` model.
//!
//! Every index handed to the container is derived from the model, so the input can never
//! ask for an out-of-bounds range or an off-boundary byte offset: a panic is a finding
//! here, not a rejected case. That is what makes the in-place shifting in
//! `insert_text_at_char_idx`, the `copy_within` in `delete_text_char_range` and the
//! length bookkeeping around them exercisable in arbitrary order.

#![no_main]

use libfuzzer_sys::fuzz_target;
use secure_types::SecureString;

/// Text with one-, two-, three- and four-byte characters, so an insertion or a deletion
/// moves a tail whose byte length is not its char length.
const PIECES: [&str; 6] = ["a", "é", "✓", "→", "ab", "🦀"];

/// The byte index of the `char_idx`-th character, or the buffer's end.
fn byte_idx(model: &str, char_idx: usize) -> usize {
   model
      .char_indices()
      .nth(char_idx)
      .map_or(model.len(), |(index, _)| index)
}

fuzz_target!(|data: &[u8]| {
   let mut secret = SecureString::new().unwrap();
   let mut model = String::new();

   for pair in data.chunks_exact(2) {
      let op = pair[0] % 5;
      let arg = usize::from(pair[1]);

      match op {
         // Append text.
         0 => {
            let piece = PIECES[arg % PIECES.len()];
            secret.push_str(piece);
            model.push_str(piece);
         }
         // Insert text at a char index inside the string, or at its end.
         1 => {
            let char_len = model.chars().count();
            let char_idx = if char_len == 0 {
               0
            } else {
               arg % (char_len + 1)
            };
            let piece = PIECES[(arg + 1) % PIECES.len()];

            assert_eq!(
               secret.insert_text_at_char_idx(char_idx, piece),
               piece.chars().count()
            );
            model.insert_str(byte_idx(&model, char_idx), piece);
         }
         // Delete a non-empty char range that lies inside the string.
         2 => {
            let char_len = model.chars().count();
            if char_len > 0 {
               let start = arg % char_len;
               let end = start + 1 + (arg >> 4) % (char_len - start);

               secret.delete_text_char_range(start..end);
               model.replace_range(byte_idx(&model, start)..byte_idx(&model, end), "");
            }
         }
         // Drain a byte range that lies on char boundaries.
         3 => {
            let boundaries: Vec<usize> = model
               .char_indices()
               .map(|(index, _)| index)
               .chain(core::iter::once(model.len()))
               .collect();

            let first = arg % boundaries.len();
            let last = (arg >> 3) % boundaries.len();
            let (low, high) = if first <= last {
               (first, last)
            } else {
               (last, first)
            };

            secret.drain(boundaries[low]..boundaries[high]);
            model.replace_range(boundaries[low]..boundaries[high], "");
         }
         // Read the whole value back.
         _ => {}
      }

      assert_eq!(secret.byte_len(), model.len());
      assert_eq!(secret.char_len(), model.chars().count());
      secret.unlock_str(|text| assert_eq!(text, model));
   }
});
