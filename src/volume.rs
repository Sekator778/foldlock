//! Splitting a byte stream across fixed-size volume files, and reading them
//! back as one continuous stream.
//!
//! Volumes are named `<base>.001`, `<base>.002`, … (zero-padded to at least
//! three digits, widening automatically past 999).

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};

/// How many indices past a gap to probe for a stray later volume, to tell an
/// interior gap (missing volume) apart from a clean end-of-set.
const GAP_PROBE_WINDOW: u32 = 16;

/// Format a volume path for the given base and 1-based index.
fn volume_path(base: &Path, index: u32) -> PathBuf {
    let name = base
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    base.with_file_name(format!("{name}.{index:03}"))
}

/// A `Write` sink that rolls over to a new file every `max_bytes` bytes.
pub struct VolumeWriter {
    base: PathBuf,
    max_bytes: u64,
    index: u32,
    current: Option<BufWriter<File>>,
    current_len: u64,
    paths: Vec<PathBuf>,
}

impl VolumeWriter {
    /// Create a writer producing `<base>.001`, `<base>.002`, … Each volume is
    /// at most `max_bytes` bytes (must be >= 1).
    pub fn new(base: PathBuf, max_bytes: u64) -> Self {
        Self {
            base,
            max_bytes: max_bytes.max(1),
            index: 0,
            current: None,
            current_len: 0,
            paths: Vec::new(),
        }
    }

    fn open_next(&mut self) -> io::Result<()> {
        self.index += 1;
        let path = volume_path(&self.base, self.index);
        let file = File::create(&path)?;
        self.current = Some(BufWriter::new(file));
        self.current_len = 0;
        self.paths.push(path);
        Ok(())
    }

    /// Flush and close the final volume, returning all written volume paths.
    pub fn finish(mut self) -> io::Result<Vec<PathBuf>> {
        if let Some(mut writer) = self.current.take() {
            writer.flush()?;
        }
        Ok(self.paths)
    }
}

impl Write for VolumeWriter {
    fn write(&mut self, mut data: &[u8]) -> io::Result<usize> {
        let total = data.len();
        while !data.is_empty() {
            if self.current.is_none() || self.current_len >= self.max_bytes {
                self.open_next()?;
            }
            // Compute the min in u64 so the value narrowed to usize is always
            // bounded by data.len() (never truncates on 32-bit targets).
            let take = (self.max_bytes - self.current_len).min(data.len() as u64) as usize;
            self.current
                .as_mut()
                .expect("volume open")
                .write_all(&data[..take])?;
            self.current_len += take as u64;
            data = &data[take..];
        }
        Ok(total)
    }

    fn flush(&mut self) -> io::Result<()> {
        if let Some(writer) = self.current.as_mut() {
            writer.flush()?;
        }
        Ok(())
    }
}

/// A `Read` source that presents a set of `<base>.NNN` volumes as one stream.
pub struct VolumeReader {
    paths: Vec<PathBuf>,
    index: usize,
    current: Option<BufReader<File>>,
}

impl VolumeReader {
    /// Open the volume set referenced by `arg`. `arg` may be the base name
    /// (`photos.flk`) or any individual volume (`photos.flk.001`).
    pub fn open(arg: &Path) -> Result<Self> {
        let base = strip_volume_extension(arg);
        let mut paths = Vec::new();
        let mut index = 1u32;
        loop {
            let candidate = volume_path(&base, index);
            if candidate.is_file() {
                paths.push(candidate);
                index += 1;
            } else {
                break;
            }
        }
        if paths.is_empty() {
            bail!(
                "no volumes found for '{}' (expected '{}')",
                arg.display(),
                volume_path(&base, 1).display()
            );
        }
        // The scan stops at the first missing index. A lone trailing stray is
        // correctly ignored, but if a higher-numbered volume still exists past
        // the gap, an interior volume is missing — fail with a clear message
        // instead of silently truncating the stream (which would later surface
        // as a confusing "wrong password or corrupted archive" error).
        for probe in (index + 1)..=(index + GAP_PROBE_WINDOW) {
            if volume_path(&base, probe).is_file() {
                bail!(
                    "missing volume '{}' (found a later volume, so the set has a gap)",
                    volume_path(&base, index).display()
                );
            }
        }
        Ok(Self {
            paths,
            index: 0,
            current: None,
        })
    }

    /// Number of volumes in the set.
    pub fn volume_count(&self) -> usize {
        self.paths.len()
    }
}

impl Read for VolumeReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        // A zero-length read must be a side-effect-free no-op; otherwise the
        // `n == 0` branch below would wrongly treat it as end-of-volume.
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            if self.current.is_none() {
                if self.index >= self.paths.len() {
                    return Ok(0);
                }
                let file = File::open(&self.paths[self.index])?;
                self.current = Some(BufReader::new(file));
                self.index += 1;
            }
            let n = self.current.as_mut().expect("volume open").read(buf)?;
            if n == 0 {
                self.current = None; // advance to the next volume
                continue;
            }
            return Ok(n);
        }
    }
}

/// If `path` ends in an all-digit extension (a volume suffix like `.001`),
/// strip it to recover the base name; otherwise return `path` unchanged.
fn strip_volume_extension(path: &Path) -> PathBuf {
    if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
        if !ext.is_empty() && ext.chars().all(|c| c.is_ascii_digit()) {
            return path.with_extension("");
        }
    }
    path.to_path_buf()
}
