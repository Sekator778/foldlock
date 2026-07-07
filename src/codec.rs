//! Pluggable compression backends: `zstd` (fast, the default) and `xz`/LZMA
//! (maximum density). Which one produced an archive is recorded in the header,
//! so decompression picks the matching decoder automatically.
//!
//! The two encoders and two decoders are wrapped in small enums so the rest of
//! the pipeline can stay generic over one concrete `Write`/`Read` type.

use std::io::{self, Read, Write};
use std::str::FromStr;

use anyhow::{anyhow, bail, Result};
use xz2::stream::{Check, Stream};

/// Default zstd level: excellent ratio/speed balance (unchanged from v1).
pub const ZSTD_DEFAULT_LEVEL: i32 = 19;
/// zstd levels 20..=22 are "ultra"; only there do we widen the window / enable
/// long-distance matching to catch redundancy across large folders.
const ZSTD_ULTRA_THRESHOLD: i32 = 20;
/// 128 MiB window for ultra levels — matches zstd's own level-22 default and
/// lets it find matches far apart in the stream (e.g. duplicated files).
const ZSTD_ULTRA_WINDOW_LOG: u32 = 27;
/// Default xz preset when `--algo xz` is chosen without an explicit level.
pub const XZ_DEFAULT_LEVEL: i32 = 9;
/// `LZMA_PRESET_EXTREME` flag (from liblzma) — the "-e" in `xz -9e`. Always OR'd
/// into the xz preset: choosing xz means the caller is after maximum density.
const LZMA_PRESET_EXTREME: u32 = 1 << 31;

/// Which compression backend an archive uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Algorithm {
    /// zstd — fast, great ratio. The default and the only v1 codec.
    #[default]
    Zstd,
    /// xz / LZMA — ~9% smaller than zstd-19 on source trees, ~3x slower.
    Xz,
}

impl Algorithm {
    /// Stable on-disk identifier stored in the archive header.
    pub fn to_byte(self) -> u8 {
        match self {
            Algorithm::Zstd => 0,
            Algorithm::Xz => 1,
        }
    }

    /// Recover the algorithm from its header byte.
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0 => Ok(Algorithm::Zstd),
            1 => Ok(Algorithm::Xz),
            other => bail!("unknown compression algorithm id {other}"),
        }
    }

    /// Human-readable name, as accepted on the command line.
    pub fn as_str(self) -> &'static str {
        match self {
            Algorithm::Zstd => "zstd",
            Algorithm::Xz => "xz",
        }
    }

    /// Inclusive range of valid `--level` values for this backend.
    pub fn level_range(self) -> std::ops::RangeInclusive<i32> {
        match self {
            Algorithm::Zstd => 1..=22,
            Algorithm::Xz => 0..=9,
        }
    }
}

impl FromStr for Algorithm {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "zstd" | "zst" => Ok(Algorithm::Zstd),
            "xz" | "lzma" => Ok(Algorithm::Xz),
            other => bail!("unknown algorithm '{other}' (expected 'zstd' or 'xz')"),
        }
    }
}

/// A streaming compressor over one of the supported backends.
pub enum CompressWriter<W: Write> {
    Zstd(zstd::Encoder<'static, W>),
    Xz(xz2::write::XzEncoder<W>),
}

impl<W: Write> CompressWriter<W> {
    /// Build an encoder for `algo` writing into `inner`.
    ///
    /// `level` overrides the per-backend default when `Some`. `threads` requests
    /// multi-threaded compression; it is honored best-effort for zstd and
    /// ignored for xz (which compresses single-threaded here).
    pub fn new(inner: W, algo: Algorithm, level: Option<i32>, threads: u32) -> Result<Self> {
        match algo {
            Algorithm::Zstd => {
                let lvl = level.unwrap_or(ZSTD_DEFAULT_LEVEL);
                let mut enc = zstd::Encoder::new(inner, lvl)
                    .map_err(|e| anyhow!("failed to start zstd: {e}"))?;
                // Ultra levels: widen the window and enable long-distance
                // matching so redundancy far apart in the stream is found.
                if lvl >= ZSTD_ULTRA_THRESHOLD {
                    let _ = enc.long_distance_matching(true);
                    let _ = enc.window_log(ZSTD_ULTRA_WINDOW_LOG);
                }
                // Best-effort multi-threading: on failure it stays single-threaded.
                if threads > 1 {
                    let _ = enc.multithread(threads);
                }
                Ok(CompressWriter::Zstd(enc))
            }
            Algorithm::Xz => {
                let preset = level.unwrap_or(XZ_DEFAULT_LEVEL) as u32 | LZMA_PRESET_EXTREME;
                let stream = Stream::new_easy_encoder(preset, Check::Crc64)
                    .map_err(|e| anyhow!("failed to start xz: {e}"))?;
                Ok(CompressWriter::Xz(xz2::write::XzEncoder::new_stream(
                    inner, stream,
                )))
            }
        }
    }

    /// Flush and finalize the stream, returning the inner writer.
    pub fn finish(self) -> io::Result<W> {
        match self {
            CompressWriter::Zstd(enc) => enc.finish(),
            CompressWriter::Xz(enc) => enc.finish(),
        }
    }
}

impl<W: Write> Write for CompressWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            CompressWriter::Zstd(enc) => enc.write(buf),
            CompressWriter::Xz(enc) => enc.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            CompressWriter::Zstd(enc) => enc.flush(),
            CompressWriter::Xz(enc) => enc.flush(),
        }
    }
}

/// A streaming decompressor over one of the supported backends.
pub enum DecompressReader<R: Read> {
    Zstd(Box<zstd::Decoder<'static, io::BufReader<R>>>),
    Xz(xz2::read::XzDecoder<R>),
}

impl<R: Read> DecompressReader<R> {
    /// Build the decoder matching `algo`, reading from `inner`.
    pub fn new(inner: R, algo: Algorithm) -> Result<Self> {
        match algo {
            Algorithm::Zstd => {
                let mut dec =
                    zstd::Decoder::new(inner).map_err(|e| anyhow!("failed to start zstd: {e}"))?;
                // Accept the largest window an ultra-level encoder might have used.
                let _ = dec.window_log_max(31);
                Ok(DecompressReader::Zstd(Box::new(dec)))
            }
            Algorithm::Xz => Ok(DecompressReader::Xz(xz2::read::XzDecoder::new(inner))),
        }
    }
}

impl<R: Read> Read for DecompressReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            DecompressReader::Zstd(dec) => dec.read(buf),
            DecompressReader::Xz(dec) => dec.read(buf),
        }
    }
}
