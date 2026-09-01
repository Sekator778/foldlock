//! ASCII **armor** — a copy-paste-friendly text encoding of a foldlock archive.
//!
//! The binary archive stream (an opaque `salt | nonce` prefix followed by the
//! AEAD ciphertext) is base64-encoded into a single continuous run of characters
//! with *no envelope* — no `BEGIN`/`END` lines, no markers, no framing. Nothing
//! in the text identifies it as foldlock: to a human, and to a scanner, it is an
//! anonymous run of base64 that is indistinguishable from random data without
//! the password.
//!
//! Armor is a pure, reversible transport encoding: it changes nothing about the
//! encryption. The decoded bytes are the *exact same* bytes the binary volume
//! path produces, so integrity is handled entirely by the existing AEAD
//! (ChaCha20-Poly1305 STREAM).
//!
//! The [decoder](decode) is forgiving of a clipboard round-trip: it discards
//! *every* byte that is not a base64 data symbol — ASCII whitespace, injected
//! line breaks of any flavor, a BOM, non-breaking spaces, zero-width characters,
//! Unicode line/paragraph separators, and `=` padding — then decodes the base64
//! that remains. Missing padding is fine too. Because there is no framing, the
//! blob is meant to be pasted as its *own* block: base64-alphabet letters from
//! surrounding prose would be slurped in and corrupt the decode.

use std::io::{self, Write};

/// Standard base64 alphabet (RFC 4648), with `=` padding on the final group.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
/// Sentinel in the decode table for a byte that is not a base64 symbol.
const INVALID: u8 = 0xFF;

/// Reverse lookup table: base64 character → 6-bit value, [`INVALID`] otherwise.
/// Built once at compile time so decoding is a branch-free table lookup.
const DECODE: [u8; 256] = {
    let mut table = [INVALID; 256];
    let mut i = 0;
    while i < ALPHABET.len() {
        table[ALPHABET[i] as usize] = i as u8;
        i += 1;
    }
    table
};

/// A `Write` sink that base64-encodes everything written to it and forwards the
/// characters to `inner` as one unbroken line. Call [`finish`](ArmorWriter::finish)
/// to emit the final (padded) group and recover the inner writer.
///
/// At most two raw bytes are ever buffered (an incomplete trailing group), so
/// memory use is constant regardless of how much data flows through.
pub struct ArmorWriter<W: Write> {
    inner: W,
    /// 0..=2 raw bytes not yet forming a complete three-byte group.
    carry: [u8; 3],
    carry_len: usize,
    /// Reused encode buffer, so steady-state writes do not allocate.
    scratch: Vec<u8>,
}

impl<W: Write> ArmorWriter<W> {
    /// Wrap `inner`. Nothing is written until data flows through — the output is
    /// a bare run of base64 characters with no leading marker.
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            carry: [0u8; 3],
            carry_len: 0,
            scratch: Vec::new(),
        }
    }

    /// Emit the final partial group (with `=` padding), then return the inner
    /// writer, flushed.
    pub fn finish(mut self) -> io::Result<W> {
        let mut tail = [0u8; 4];
        let n = match self.carry_len {
            0 => 0,
            1 => {
                let b0 = self.carry[0];
                tail[0] = ALPHABET[(b0 >> 2) as usize];
                tail[1] = ALPHABET[((b0 & 0x03) << 4) as usize];
                tail[2] = b'=';
                tail[3] = b'=';
                4
            }
            2 => {
                let (b0, b1) = (self.carry[0], self.carry[1]);
                tail[0] = ALPHABET[(b0 >> 2) as usize];
                tail[1] = ALPHABET[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize];
                tail[2] = ALPHABET[((b1 & 0x0f) << 2) as usize];
                tail[3] = b'=';
                4
            }
            _ => unreachable!("carry never holds a full group"),
        };
        if n > 0 {
            self.inner.write_all(&tail[..n])?;
        }
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for ArmorWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.scratch.clear();
        // Worst case: every input byte plus the carry rounds up to a 4-char group.
        self.scratch
            .reserve((self.carry_len + data.len()) / 3 * 4 + 4);

        let mut rest = data;
        // Top up a partial group left over from a previous write first.
        if self.carry_len > 0 {
            while self.carry_len < 3 && !rest.is_empty() {
                self.carry[self.carry_len] = rest[0];
                self.carry_len += 1;
                rest = &rest[1..];
            }
            if self.carry_len == 3 {
                self.scratch.extend_from_slice(&encode_group(&self.carry));
                self.carry_len = 0;
            }
        }
        // Encode whole three-byte groups straight from the input.
        let mut groups = rest.chunks_exact(3);
        for group in &mut groups {
            self.scratch.extend_from_slice(&encode_group(group));
        }
        // Stash the 0..=2-byte remainder for next time.
        for &byte in groups.remainder() {
            self.carry[self.carry_len] = byte;
            self.carry_len += 1;
        }

        self.inner.write_all(&self.scratch)?;
        Ok(data.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Decode armored text back into the raw archive bytes.
///
/// The whole input is reduced to just its base64 data characters — so any junk
/// (whitespace, injected newlines, a BOM, prose punctuation, `=` padding) simply
/// disappears — and the remainder is base64-decoded. There is no framing and no
/// marker, so this is a pure transport decode: whether the bytes are really a
/// foldlock archive is decided later, by attempting to decrypt them.
///
/// Returns `None` only when the surviving character count is a structurally
/// impossible base64 length (`len % 4 == 1`).
pub fn decode(input: &[u8]) -> Option<Vec<u8>> {
    sextets_to_bytes(&keep_base64_chars(input))
}

/// Encode one full three-byte group into four base64 characters.
#[inline]
fn encode_group(g: &[u8]) -> [u8; 4] {
    [
        ALPHABET[(g[0] >> 2) as usize],
        ALPHABET[(((g[0] & 0x03) << 4) | (g[1] >> 4)) as usize],
        ALPHABET[(((g[1] & 0x0f) << 2) | (g[2] >> 6)) as usize],
        ALPHABET[(g[2] & 0x3f) as usize],
    ]
}

/// Copy out only the base64 data characters, dropping everything else (all
/// whitespace, BOMs, non-ASCII junk, `=` padding, surrounding punctuation).
fn keep_base64_chars(input: &[u8]) -> Vec<u8> {
    let mut chars = Vec::with_capacity(input.len());
    for &byte in input {
        if DECODE[byte as usize] != INVALID {
            chars.push(byte);
        }
    }
    chars
}

/// Pack a run of base64 characters back into bytes. The `=` padding is optional
/// — the byte count is inferred from how many characters there are (2 chars → 1
/// byte, 3 → 2 bytes). Returns `None` only when the count is structurally
/// impossible (`len % 4 == 1`, a lone character carrying fewer than 8 bits).
///
/// `chars` must contain only base64 data characters (as produced by
/// [`keep_base64_chars`]); any stray byte simply maps through the table.
fn sextets_to_bytes(chars: &[u8]) -> Option<Vec<u8>> {
    if chars.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(chars.len() / 4 * 3 + 2);
    let mut quads = chars.chunks_exact(4);
    for q in &mut quads {
        let (a, b, c, d) = (
            DECODE[q[0] as usize],
            DECODE[q[1] as usize],
            DECODE[q[2] as usize],
            DECODE[q[3] as usize],
        );
        out.push((a << 2) | (b >> 4));
        out.push((b << 4) | (c >> 2));
        out.push((c << 6) | d);
    }
    match quads.remainder() {
        [] => {}
        [a, b] => {
            let (a, b) = (DECODE[*a as usize], DECODE[*b as usize]);
            out.push((a << 2) | (b >> 4));
        }
        [a, b, c] => {
            let (a, b, c) = (
                DECODE[*a as usize],
                DECODE[*b as usize],
                DECODE[*c as usize],
            );
            out.push((a << 2) | (b >> 4));
            out.push((b << 4) | (c >> 2));
        }
        _ => unreachable!("remainder of chunks_exact(4) is always < 4"),
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Encode `data` through the streaming writer, returning the armored bytes.
    fn armor(data: &[u8]) -> Vec<u8> {
        let mut w = ArmorWriter::new(Vec::new());
        w.write_all(data).unwrap();
        w.finish().unwrap()
    }

    #[test]
    fn output_is_pure_base64_with_no_marker() {
        let text = armor(b"some archive payload bytes");
        assert!(
            text.iter()
                .all(|&b| b == b'=' || DECODE[b as usize] != INVALID),
            "armored output must be pure base64 characters"
        );
    }

    #[test]
    fn base64_roundtrips_every_remainder_length() {
        for len in 0..256usize {
            let data: Vec<u8> = (0..len).map(|i| (i.wrapping_mul(7) + 3) as u8).collect();
            let text = armor(&data);
            assert_eq!(decode(&text).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn feeding_in_odd_sized_chunks_matches_a_single_write() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let mut w = ArmorWriter::new(Vec::new());
        for chunk in data.chunks(7) {
            w.write_all(chunk).unwrap();
        }
        let streamed = w.finish().unwrap();
        assert_eq!(streamed, armor(&data));
    }

    #[test]
    fn decode_reads_its_own_output() {
        let data = b"\x02\x00\x01\x02\xff pretend archive bytes".to_vec();
        let text = armor(&data);
        assert_eq!(decode(&text).unwrap(), data);
    }

    #[test]
    fn decode_survives_nonascii_junk_and_missing_padding() {
        // An 8-byte payload (len % 3 == 2) so base64 emits a '=' pad, letting us
        // prove padding is optional on the way back in.
        let data = b"pad byte".to_vec();
        let armored = armor(&data);
        assert!(armored.contains(&b'='), "fixture should exercise padding");

        // Strip the '=' padding and pepper the blob with non-ASCII junk that a
        // naive whitespace-only filter would choke on (but which is not part of
        // the base64 alphabet, so it must be dropped rather than decoded).
        let junk: &[u8] = "\r\n\u{00A0}\u{200B}\u{2028}\"' ".as_bytes();
        let mut mangled = Vec::new();
        for (i, &b) in armored.iter().enumerate() {
            if b == b'=' {
                continue;
            }
            mangled.push(b);
            if i % 3 == 0 {
                mangled.extend_from_slice(junk);
            }
        }
        assert_eq!(decode(&mangled).unwrap(), data);
    }

    #[test]
    fn decode_only_rejects_impossible_lengths() {
        assert!(decode(b"A").is_none()); // 1 char: < 8 bits
        assert_eq!(decode(b"").unwrap(), Vec::<u8>::new());
        // Padded and unpadded forms of the same data agree.
        assert_eq!(decode(b"TWE=").unwrap(), decode(b"TWE").unwrap());
    }
}
