//! ASCII **armor** — a copy-paste-friendly text encoding of a foldlock archive.
//!
//! The binary archive stream (the plaintext `FLK1` header followed by the AEAD
//! ciphertext) is base64-encoded into a single continuous run of characters with
//! *no envelope at all* — no markers, no header lines, no visible checksum. To a
//! human it is just a string of characters; the application recognizes it purely
//! from its structure (see [`decode`]).
//!
//! Armor is a pure, reversible transport encoding: it changes nothing about the
//! encryption. An armored blob decodes to the *exact same bytes* the binary
//! volume path produces, so integrity is handled entirely by the existing AEAD
//! (ChaCha20-Poly1305 STREAM) — a copied-wrong or truncated blob fails to
//! authenticate rather than producing garbage.
//!
//! The [encoder](ArmorWriter) streams in three-byte groups (bounded memory,
//! independent of payload size). The [decoder](decode) is deliberately liberal:
//! it drops all ASCII whitespace and a UTF-8 BOM, so CRLF line endings, wrapped
//! lines, or stray spaces introduced by a clipboard round-trip are all tolerated.

use std::io::{self, Write};

use anyhow::Result;

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
/// characters to `inner` as one unbroken line. Construction writes nothing;
/// call [`finish`](ArmorWriter::finish) to emit the final (padded) group.
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
    /// Wrap `inner`. No bytes are written until data flows in or [`finish`]
    /// is called.
    ///
    /// [`finish`]: ArmorWriter::finish
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            carry: [0u8; 3],
            carry_len: 0,
            scratch: Vec::new(),
        }
    }

    /// Emit the final partial group (with `=` padding) and return the inner
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
/// Whitespace and a leading BOM are ignored. Returns:
/// - `Ok(Some(bytes))` when `input`, once cleaned, is valid base64 that decodes
///   to a stream beginning with `magic` — i.e. it is one of ours;
/// - `Ok(None)` otherwise (foreign characters, invalid base64, or a decoded
///   prefix that is not `magic`), so the caller can fall back to the binary path.
pub fn decode(input: &[u8], magic: &[u8]) -> Result<Option<Vec<u8>>> {
    let input = strip_bom(input);

    // Collect base64 symbols, dropping whitespace. A single foreign byte means
    // this is not an armored blob at all.
    let mut cleaned: Vec<u8> = Vec::with_capacity(input.len());
    for &byte in input {
        if byte.is_ascii_whitespace() {
            continue;
        }
        if byte == b'=' || DECODE[byte as usize] != INVALID {
            cleaned.push(byte);
        } else {
            return Ok(None);
        }
    }
    if cleaned.is_empty() {
        return Ok(None);
    }

    match base64_decode(&cleaned) {
        Some(decoded) if decoded.starts_with(magic) => Ok(Some(decoded)),
        _ => Ok(None),
    }
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

/// Decode whitespace-free base64 (with optional trailing `=` padding). Returns
/// `None` on any structural error, since without an envelope we cannot tell a
/// corrupted archive from an unrelated file — the caller treats both as "not
/// ours".
fn base64_decode(s: &[u8]) -> Option<Vec<u8>> {
    if s.len() % 4 != 0 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() / 4 * 3);
    let mut i = 0;
    while i < s.len() {
        let v0 = DECODE[s[i] as usize];
        let v1 = DECODE[s[i + 1] as usize];
        if v0 == INVALID || v1 == INVALID {
            return None;
        }
        out.push((v0 << 2) | (v1 >> 4));

        // Padding is only ever valid in the final quantum.
        let last = i + 4 == s.len();
        if s[i + 2] == b'=' {
            return (last && s[i + 3] == b'=').then_some(out);
        }
        let v2 = DECODE[s[i + 2] as usize];
        if v2 == INVALID {
            return None;
        }
        out.push((v1 << 4) | (v2 >> 2));

        if s[i + 3] == b'=' {
            return last.then_some(out);
        }
        let v3 = DECODE[s[i + 3] as usize];
        if v3 == INVALID {
            return None;
        }
        out.push((v2 << 6) | v3);
        i += 4;
    }
    Some(out)
}

/// Strip a leading UTF-8 byte-order mark, if present.
#[inline]
fn strip_bom(input: &[u8]) -> &[u8] {
    input.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(input)
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
    fn base64_roundtrips_every_remainder_length() {
        for len in 0..256usize {
            let data: Vec<u8> = (0..len).map(|i| (i.wrapping_mul(7) + 3) as u8).collect();
            let text = armor(&data);
            // Output is pure base64: only alphabet characters and padding.
            assert!(
                text.iter()
                    .all(|&b| b == b'=' || DECODE[b as usize] != INVALID),
                "len {len}: armored output must be pure base64"
            );
            assert_eq!(base64_decode(&text).unwrap(), data, "len {len}");
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
        let data = b"FLK1\x02\x00\x01\x02\xff pretend archive bytes".to_vec();
        let text = armor(&data);
        assert_eq!(decode(&text, b"FLK1").unwrap().unwrap(), data);
    }

    #[test]
    fn decode_tolerates_bom_crlf_and_stray_whitespace() {
        let data: Vec<u8> = (0..500).map(|i| (i % 251) as u8).collect();
        let mut prefixed = vec![0u8; 4];
        prefixed[..4].copy_from_slice(b"FLK1");
        prefixed.extend_from_slice(&data);
        let text = armor(&prefixed);

        // Simulate a hostile clipboard: a BOM, CRLF endings, injected blank lines.
        let mut messy = vec![0xEF, 0xBB, 0xBF];
        for (i, &b) in text.iter().enumerate() {
            messy.push(b);
            if i % 37 == 36 {
                messy.extend_from_slice(b"\r\n  \t");
            }
        }
        assert_eq!(decode(&messy, b"FLK1").unwrap().unwrap(), prefixed);
    }

    #[test]
    fn decode_ignores_unrelated_text() {
        assert!(decode(b"just some notes, not an archive!", b"FLK1")
            .unwrap()
            .is_none());
    }

    #[test]
    fn decode_returns_none_when_magic_does_not_match() {
        let text = armor(b"XXXX definitely not a foldlock stream");
        assert!(decode(&text, b"FLK1").unwrap().is_none());
    }

    #[test]
    fn base64_decode_rejects_malformed_input() {
        assert!(base64_decode(b"AAA").is_none()); // not a multiple of 4
        assert!(base64_decode(b"A=AA").is_none()); // padding not at the end
        assert!(base64_decode(b"====").is_none()); // padding with no data
    }
}
