//! Password-based key derivation and streaming authenticated encryption.
//!
//! Encryption uses ChaCha20-Poly1305 in the AEAD **STREAM** construction
//! (`EncryptorBE32` / `DecryptorBE32`). The plaintext (a zstd-compressed tar)
//! is split into fixed-size blocks; each block is sealed independently with a
//! per-block nonce derived from a random 7-byte prefix plus a 32-bit counter.
//! The construction is tamper-evident and resistant to block reordering,
//! truncation, and duplication.

use std::io::{self, Read, Write};

use anyhow::{anyhow, bail, Result};
use argon2::Argon2;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::stream::{DecryptorBE32, EncryptorBE32};
use chacha20poly1305::aead::Payload;
use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit};
use zeroize::Zeroizing;

/// Plaintext block size fed to the AEAD stream (64 KiB).
pub const BLOCK: usize = 64 * 1024;
/// Poly1305 authentication tag length.
pub const TAG: usize = 16;
/// Ciphertext block size on disk (plaintext block + tag).
pub const CBLOCK: usize = BLOCK + TAG;

/// Length of the random salt fed to Argon2id, in bytes.
pub const SALT_LEN: usize = 16;
/// Length of the STREAM nonce prefix (ChaCha20-Poly1305 nonce is 12 bytes;
/// STREAM BE32 reserves 5 bytes for the counter + last-block flag).
pub const NONCE_PREFIX_LEN: usize = 7;

/// Derive a 256-bit key from a password and salt using Argon2id (default
/// parameters: 19 MiB memory, 2 iterations, 1 lane).
///
/// The returned key is wrapped in [`Zeroizing`] so it is wiped from memory when
/// dropped. An empty password is rejected (it would derive a worthless key).
pub fn derive_key(password: &str, salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    if password.is_empty() {
        bail!("password must not be empty");
    }
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, key.as_mut_slice())
        .map_err(|e| anyhow!("key derivation failed: {e}"))?;
    Ok(key)
}

/// A `Write` adapter that buffers plaintext into [`BLOCK`]-sized chunks and
/// seals each chunk with the AEAD stream, forwarding ciphertext to `inner`.
///
/// The header bytes are passed as additional authenticated data (AAD) for the
/// very first block, binding the (otherwise plaintext) header to the ciphertext.
pub struct EncryptingWriter<W: Write> {
    stream: Option<EncryptorBE32<ChaCha20Poly1305>>,
    buf: Vec<u8>,
    first: bool,
    aad: Vec<u8>,
    inner: W,
}

impl<W: Write> EncryptingWriter<W> {
    pub fn new(
        inner: W,
        key: &[u8; 32],
        nonce_prefix: &[u8; NONCE_PREFIX_LEN],
        aad: Vec<u8>,
    ) -> Self {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let stream = EncryptorBE32::from_aead(cipher, GenericArray::from_slice(nonce_prefix));
        Self {
            stream: Some(stream),
            buf: Vec::with_capacity(BLOCK * 2),
            first: true,
            aad,
            inner,
        }
    }

    fn emit_next(&mut self, plain: &[u8]) -> io::Result<()> {
        let stream = self.stream.as_mut().expect("stream already finalized");
        let ciphertext = if self.first {
            self.first = false;
            stream.encrypt_next(Payload {
                msg: plain,
                aad: &self.aad,
            })
        } else {
            stream.encrypt_next(plain)
        }
        .map_err(|_| io::Error::other("encryption failed"))?;
        self.inner.write_all(&ciphertext)
    }

    /// Seal the final (partial) block and flush, returning the inner writer.
    pub fn finish(mut self) -> io::Result<W> {
        // Emit every complete block except keep a non-empty remainder for the
        // final `encrypt_last` call. Using strict `>` guarantees the remainder
        // is always in 1..=BLOCK (never zero) for any non-empty input.
        while self.buf.len() > BLOCK {
            let block: Vec<u8> = self.buf.drain(..BLOCK).collect();
            self.emit_next(&block)?;
        }
        let last = std::mem::take(&mut self.buf);
        let stream = self.stream.take().expect("stream already finalized");
        let ciphertext = if self.first {
            stream.encrypt_last(Payload {
                msg: last.as_slice(),
                aad: &self.aad,
            })
        } else {
            stream.encrypt_last(last.as_slice())
        }
        .map_err(|_| io::Error::other("encryption failed"))?;
        self.inner.write_all(&ciphertext)?;
        self.inner.flush()?;
        Ok(self.inner)
    }
}

impl<W: Write> Write for EncryptingWriter<W> {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.buf.extend_from_slice(data);
        while self.buf.len() > BLOCK {
            let block: Vec<u8> = self.buf.drain(..BLOCK).collect();
            self.emit_next(&block)?;
        }
        Ok(data.len())
    }

    // Block boundaries must be preserved, so a mid-stream flush is a no-op;
    // the buffered tail is sealed by `finish`.
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A `Read` adapter that pulls ciphertext blocks from `inner`, verifies and
/// decrypts each, and yields plaintext. Uses one-block lookahead to know when
/// the current block is the final one (so it calls `decrypt_last`).
pub struct DecryptingReader<R: Read> {
    stream: Option<DecryptorBE32<ChaCha20Poly1305>>,
    inner: R,
    pending: Option<Vec<u8>>,
    first: bool,
    aad: Vec<u8>,
    out: Vec<u8>,
    out_pos: usize,
    done: bool,
}

impl<R: Read> DecryptingReader<R> {
    pub fn new(
        inner: R,
        key: &[u8; 32],
        nonce_prefix: &[u8; NONCE_PREFIX_LEN],
        aad: Vec<u8>,
    ) -> Self {
        let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
        let stream = DecryptorBE32::from_aead(cipher, GenericArray::from_slice(nonce_prefix));
        Self {
            stream: Some(stream),
            inner,
            pending: None,
            first: true,
            aad,
            out: Vec::new(),
            out_pos: 0,
            done: false,
        }
    }

    /// Read exactly [`CBLOCK`] bytes unless the underlying stream ends first.
    /// Looping is required because `VolumeReader` returns short reads at every
    /// volume boundary — a single `read` may straddle several files.
    fn fill_block(&mut self) -> io::Result<Vec<u8>> {
        let mut block = vec![0u8; CBLOCK];
        let mut filled = 0;
        while filled < CBLOCK {
            let n = self.inner.read(&mut block[filled..])?;
            if n == 0 {
                break;
            }
            filled += n;
        }
        block.truncate(filled);
        Ok(block)
    }

    /// Decrypt the next available block into `self.out`. Returns `false` at EOF.
    fn decrypt_one(&mut self) -> io::Result<bool> {
        if self.done {
            return Ok(false);
        }
        if self.pending.is_none() {
            let first_block = self.fill_block()?;
            if first_block.is_empty() {
                self.done = true;
                return Ok(false);
            }
            self.pending = Some(first_block);
        }
        let current = self.pending.take().expect("pending block missing");
        let lookahead = self.fill_block()?;

        let plaintext = if lookahead.is_empty() {
            // No more data follows: `current` is the final block.
            let stream = self.stream.take().expect("stream already finalized");
            let result = if self.first {
                stream.decrypt_last(Payload {
                    msg: &current,
                    aad: &self.aad,
                })
            } else {
                stream.decrypt_last(current.as_slice())
            };
            self.done = true;
            result
        } else {
            let stream = self.stream.as_mut().expect("stream already finalized");
            let result = if self.first {
                stream.decrypt_next(Payload {
                    msg: &current,
                    aad: &self.aad,
                })
            } else {
                stream.decrypt_next(current.as_slice())
            };
            self.pending = Some(lookahead);
            result
        };
        self.first = false;

        let plaintext = plaintext.map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "decryption failed: wrong password or corrupted archive",
            )
        })?;
        self.out = plaintext;
        self.out_pos = 0;
        Ok(true)
    }
}

impl<R: Read> Read for DecryptingReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        loop {
            if self.out_pos < self.out.len() {
                let n = std::cmp::min(buf.len(), self.out.len() - self.out_pos);
                buf[..n].copy_from_slice(&self.out[self.out_pos..self.out_pos + n]);
                self.out_pos += n;
                return Ok(n);
            }
            if !self.decrypt_one()? {
                return Ok(0);
            }
        }
    }
}
