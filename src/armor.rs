//! ASCII **armor** — a copy-paste-friendly text encoding of a foldlock archive.
//!
//! The binary archive stream (the plaintext `FLK1` header followed by the AEAD
//! ciphertext) is base64-encoded into a single continuous run of characters with
//! *no human-readable envelope* — no `BEGIN`/`END` lines, no headers. To a human
//! it is just a string of characters.
//!
//! To let the payload be pasted **inside arbitrary surrounding text** (a chat
//! message, an email with a greeting and a signature, quoted lines) it is
//! bracketed by two hidden [frame delimiters](FRAME_START): fixed, random-looking
//! runs of base64 characters that are indistinguishable by eye from the payload
//! but let the decoder find where the payload begins and ends.
//!
//! Armor is a pure, reversible transport encoding: it changes nothing about the
//! encryption. The framed payload decodes to the *exact same bytes* the binary
//! volume path produces, so integrity is handled entirely by the existing AEAD
//! (ChaCha20-Poly1305 STREAM).
//!
//! The [decoder](decode) is maximally forgiving of a clipboard round-trip: it
//! first discards *every* byte that is not a base64 data symbol — ASCII
//! whitespace, injected line breaks of any flavor (even ones that land inside a
//! frame token), a BOM, non-breaking spaces, zero-width characters, Unicode
//! line/paragraph separators, quotes, and `=` padding — then locates the frame
//! and decodes what is between. Missing padding is fine too.

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

/// Hidden frame delimiters bracketing the payload. They are deliberately
/// random-looking runs of base64 characters — indistinguishable by eye from the
/// payload itself — yet let the decoder pick the payload out of arbitrary
/// surrounding text. At 16 characters each, an accidental collision inside a
/// payload is about `2^-96`. The two tokens are distinct so a stray copy of one
/// cannot be mistaken for the other.
const FRAME_START: &[u8] = b"o3Qv9Xz1Lp7Rk2Bf";
const FRAME_END: &[u8] = b"e8Wn4Yc6Hs0Jd5Tg";

/// A `Write` sink that base64-encodes everything written to it and forwards the
/// characters to `inner` as one unbroken line, bracketed by the hidden frame
/// tokens. [`new`](ArmorWriter::new) writes the opening token; call
/// [`finish`](ArmorWriter::finish) to emit the final (padded) group and the
/// closing token.
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
    /// Wrap `inner` and write the opening frame token.
    pub fn new(mut inner: W) -> io::Result<Self> {
        inner.write_all(FRAME_START)?;
        Ok(Self {
            inner,
            carry: [0u8; 3],
            carry_len: 0,
            scratch: Vec::new(),
        })
    }

    /// Emit the final partial group (with `=` padding) and the closing frame
    /// token, then return the inner writer, flushed.
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
        self.inner.write_all(FRAME_END)?;
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
/// The whole input is first reduced to just its base64 data characters, so any
/// junk — including newlines injected *inside* a frame token, and any prose
/// punctuation — disappears. The payload is then located by its hidden frame
/// (`FRAME_START` … `FRAME_END`), which lets it be buried in surrounding text.
/// Files written before framing existed (or a bare blob pasted on its own) are
/// still handled by a whole-stream fallback.
///
/// Returns `Ok(Some(bytes))` when the decoded stream begins with `magic` — i.e.
/// it is one of ours — and `Ok(None)` otherwise, so the caller can fall back to
/// the binary/volume path.
pub fn decode(input: &[u8], magic: &[u8]) -> Result<Option<Vec<u8>>> {
    let chars = keep_base64_chars(input);

    // Preferred form: the payload is bracketed by hidden frame tokens, so it can
    // sit inside arbitrary surrounding text. Slice out START..END and decode it.
    if let Some(region) = between(&chars, FRAME_START, FRAME_END) {
        if let Some(bytes) = sextets_to_bytes(region) {
            if bytes.starts_with(magic) {
                return Ok(Some(bytes));
            }
        }
    }

    // Fallback: an un-framed blob (an older armored file, or a blob pasted on its
    // own). Trusted only when it decodes to our magic, so unrelated text and
    // surrounding prose are rejected.
    Ok(sextets_to_bytes(&chars).filter(|bytes| bytes.starts_with(magic)))
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

/// The slice of `hay` strictly between the first occurrence of `start` and the
/// first occurrence of `end` after it. `None` if either token is missing.
fn between<'a>(hay: &'a [u8], start: &[u8], end: &[u8]) -> Option<&'a [u8]> {
    let s = find(hay, start)?;
    let after = s + start.len();
    let e = find(&hay[after..], end)?;
    Some(&hay[after..after + e])
}

/// Index of the first occurrence of `needle` in `hay`, if any.
fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
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
        let mut w = ArmorWriter::new(Vec::new()).unwrap();
        w.write_all(data).unwrap();
        w.finish().unwrap()
    }

    /// Decode the whole (framed or bare) blob's base64, ignoring the magic check.
    fn decode_lenient(input: &[u8]) -> Option<Vec<u8>> {
        sextets_to_bytes(&keep_base64_chars(input))
    }

    #[test]
    fn output_is_pure_base64_bracketed_by_the_frame() {
        let text = armor(b"FLK1 hello world payload");
        assert!(text.starts_with(FRAME_START), "must open with the frame");
        assert!(text.ends_with(FRAME_END), "must close with the frame");
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
            // Strip the fixed-length frame and decode the payload base64 (via the
            // same padding-tolerant path the real decoder uses).
            let inner = &text[FRAME_START.len()..text.len() - FRAME_END.len()];
            assert_eq!(decode_lenient(inner).unwrap(), data, "len {len}");
        }
    }

    #[test]
    fn feeding_in_odd_sized_chunks_matches_a_single_write() {
        let data: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let mut w = ArmorWriter::new(Vec::new()).unwrap();
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
    fn decode_finds_payload_buried_in_prose() {
        let data = b"FLK1 the real payload bytes \x00\xff".to_vec();
        let blob = String::from_utf8(armor(&data)).unwrap();
        // Bury it in an email, wrapping the blob across CRLF lines mid-token.
        let wrapped = blob
            .as_bytes()
            .chunks(9)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join("\r\n");
        let message = format!(
            "Hi Bob,\r\n\r\npaste this into foldlock:\r\n{wrapped}\r\n\r\nCheers, Alice\r\n"
        );
        assert_eq!(decode(message.as_bytes(), b"FLK1").unwrap().unwrap(), data);
    }

    #[test]
    fn decode_survives_nonascii_junk_and_missing_padding() {
        // An 8-byte payload (len % 3 == 2) so base64 emits a '=' pad, letting us
        // prove padding is optional on the way back in.
        let data = b"FLK1 pad".to_vec();
        let armored = armor(&data);
        assert!(armored.contains(&b'='), "fixture should exercise padding");

        // Strip the '=' padding and pepper the blob with non-ASCII junk that a
        // naive whitespace-only filter would choke on.
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
        assert_eq!(decode(&mangled, b"FLK1").unwrap().unwrap(), data);
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
    fn lenient_decode_only_rejects_impossible_lengths() {
        assert!(decode_lenient(b"A").is_none()); // 1 char: < 8 bits
        assert_eq!(decode_lenient(b"").unwrap(), Vec::<u8>::new());
        // Padded and unpadded forms of the same data agree.
        assert_eq!(
            decode_lenient(b"TWE=").unwrap(),
            decode_lenient(b"TWE").unwrap()
        );
    }
}
