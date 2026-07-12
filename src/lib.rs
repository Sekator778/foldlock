//! `foldlock` — compress a folder, encrypt it with a password, and split it
//! into fixed-size volumes (and the reverse).
//!
//! Pipeline: `tar` → compress (`zstd` or `xz`) → ChaCha20-Poly1305 STREAM →
//! split volumes.
//!
//! On-disk layout of the logical stream (before volume splitting):
//!
//! ```text
//! ┌──────────────── plaintext header ────────────────┐┌── AEAD ciphertext ──┐
//! │ "FLK1" │ ver │ algo │ salt[16] │ nprefix[7]       ││ block₀ │ … │ blockₙ │
//! │ name_len(u16-le) │ name[name_len]                 ││ (ciphertext ‖ tag)  │
//! └───────────────────────────────────────────────────┘└─────────────────────┘
//! ```
//!
//! `algo` selects the compression backend (zstd or xz) and is present from
//! header version 2 onward; version-1 archives have no `algo` byte and are
//! always zstd.
//!
//! The full header is fed as AEAD additional-authenticated-data to the first
//! block, so tampering with the salt, nonce, or stored name is detected.

mod codec;
mod crypto;
mod volume;

use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use walkdir::WalkDir;

use crypto::{derive_key, DecryptingReader, EncryptingWriter, NONCE_PREFIX_LEN, SALT_LEN};
use volume::{VolumeReader, VolumeWriter};

pub use codec::Algorithm;
use codec::{CompressWriter, DecompressReader};

/// File extension marking a foldlock volume set: `<folder>.flk.NNN`.
const ARCHIVE_EXT: &str = "flk";
const MAGIC: &[u8; 4] = b"FLK1";
/// Header format version. v1 (zstd only, no algorithm byte) is still readable;
/// v2 adds a one-byte compression-algorithm selector after the version.
const FORMAT_VERSION: u8 = 2;
/// Upper bound on the stored folder name, to reject corrupt headers cheaply.
const MAX_NAME_LEN: usize = 4096;

/// Options for [`compress`].
pub struct CompressOptions {
    /// Folder (or file) to pack.
    pub source: PathBuf,
    /// Password used to derive the encryption key.
    pub password: String,
    /// Maximum size of each output volume, in bytes.
    pub volume_size: u64,
    /// Directory the `<name>.flk.NNN` volumes are written to.
    pub output_dir: PathBuf,
    /// Compression backend to use.
    pub algorithm: Algorithm,
    /// Explicit compression level; `None` uses the backend's default.
    pub level: Option<i32>,
}

/// Result of a successful [`compress`].
#[derive(Debug)]
pub struct CompressSummary {
    /// Paths of the volumes that were written, in order.
    pub volumes: Vec<PathBuf>,
    /// Total bytes across all volumes.
    pub total_bytes: u64,
    /// Number of source symlinks that were skipped (unsupported in v1).
    pub skipped_symlinks: usize,
    /// Number of compression worker threads that were used.
    pub threads: u32,
}

/// Options for [`decompress`].
pub struct DecompressOptions {
    /// Path to the volume set: the base name or any single `.NNN` volume.
    pub archive: PathBuf,
    /// Password used during compression.
    pub password: String,
    /// Directory to extract into (the original folder is recreated inside it).
    pub output_dir: PathBuf,
    /// Overwrite the destination folder if it already exists.
    pub force: bool,
}

/// Result of a successful [`decompress`].
#[derive(Debug)]
pub struct DecompressSummary {
    /// Path of the folder that was recreated.
    pub output: PathBuf,
    /// Number of volumes that were read.
    pub volumes_read: usize,
}

/// Compress, encrypt, and split `opts.source` into volumes.
pub fn compress(opts: &CompressOptions) -> Result<CompressSummary> {
    let source = opts
        .source
        .canonicalize()
        .with_context(|| format!("cannot access source '{}'", opts.source.display()))?;

    let root_name = source
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .filter(|n| !n.is_empty())
        .unwrap_or_else(|| "archive".to_string());

    std::fs::create_dir_all(&opts.output_dir)
        .with_context(|| format!("cannot create output dir '{}'", opts.output_dir.display()))?;
    // Keep a canonical copy of the output dir only for self-output detection;
    // write volumes under the path the caller gave us, so displayed paths stay
    // relative (e.g. `./photos.flk.001`) and match what the user typed.
    let canon_output_dir = opts.output_dir.canonicalize()?;
    let base_name = format!("{root_name}.{ARCHIVE_EXT}");
    let base_path = opts.output_dir.join(&base_name);

    // Random salt + nonce prefix.
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| anyhow!("RNG failure: {e}"))?;
    getrandom::getrandom(&mut nonce_prefix).map_err(|e| anyhow!("RNG failure: {e}"))?;

    let header = build_header(opts.algorithm, &salt, &nonce_prefix, &root_name)?;
    let key = derive_key(&opts.password, &salt)?;

    // Pre-collect entries before any volume is written, so that when we pack the
    // current directory we never see our own (still-being-written) output files.
    let volume_prefix = format!("{base_name}.");
    let mut entries: Vec<walkdir::DirEntry> = Vec::new();
    let mut skipped_symlinks = 0usize;
    for entry in WalkDir::new(&source).sort_by_file_name() {
        let entry = entry.with_context(|| "error while scanning source")?;
        if entry.file_type().is_symlink() {
            skipped_symlinks += 1;
            continue;
        }
        if is_own_output(entry.path(), &canon_output_dir, &volume_prefix) {
            continue;
        }
        entries.push(entry);
    }

    // Build the writer chain: volumes <- encrypt <- compress <- tar.
    let mut volume_writer = VolumeWriter::new(base_path, opts.volume_size);
    volume_writer
        .write_all(&header)
        .context("failed to write archive header")?;

    // Use every available core for the CPU-bound compression stage (zstd only;
    // the xz backend runs single-threaded here). Multi-threading is best-effort:
    // if it cannot be enabled, compression simply runs single-threaded.
    let threads = if opts.algorithm == Algorithm::Xz {
        1
    } else {
        std::thread::available_parallelism()
            .map(|n| n.get() as u32)
            .unwrap_or(1)
    };

    let encryptor = EncryptingWriter::new(volume_writer, &key, &nonce_prefix, header);
    let comp = CompressWriter::new(encryptor, opts.algorithm, opts.level, threads)
        .context("failed to start compressor")?;

    let mut builder = tar::Builder::new(comp);
    builder.follow_symlinks(false);

    for entry in &entries {
        let rel = entry.path().strip_prefix(&source).unwrap_or(entry.path());
        let arch_path = if rel.as_os_str().is_empty() {
            PathBuf::from(&root_name)
        } else {
            Path::new(&root_name).join(rel)
        };
        if entry.file_type().is_dir() {
            builder
                .append_dir(&arch_path, entry.path())
                .with_context(|| format!("failed to add dir '{}'", entry.path().display()))?;
        } else {
            builder
                .append_path_with_name(entry.path(), &arch_path)
                .with_context(|| format!("failed to add file '{}'", entry.path().display()))?;
        }
    }

    let comp = builder.into_inner().context("failed to finish tar")?;
    let encryptor = comp.finish().context("failed to finish compression")?;
    let volume_writer = encryptor.finish().context("failed to finish encryption")?;
    let volumes = volume_writer.finish().context("failed to flush volumes")?;

    let total_bytes = volumes
        .iter()
        .map(|p| p.metadata().map(|m| m.len()).unwrap_or(0))
        .sum();

    Ok(CompressSummary {
        volumes,
        total_bytes,
        skipped_symlinks,
        threads,
    })
}

/// Reassemble, decrypt, decompress, and extract a volume set.
pub fn decompress(opts: &DecompressOptions) -> Result<DecompressSummary> {
    let mut reader = VolumeReader::open(&opts.archive)?;
    let volumes_read = reader.volume_count();

    // Read and validate the plaintext header, accumulating the exact bytes so
    // they can be replayed as the AEAD additional-authenticated-data.
    let mut header: Vec<u8> = Vec::with_capacity(64);

    let mut magic_ver = [0u8; 5];
    reader
        .read_exact(&mut magic_ver)
        .context("archive is truncated (header)")?;
    if &magic_ver[0..4] != MAGIC {
        bail!("not a foldlock archive (bad magic)");
    }
    header.extend_from_slice(&magic_ver);

    // Version gates the layout: v1 has no algorithm byte (always zstd); v2+
    // stores the compression backend in one byte right after the version.
    let algorithm = match magic_ver[4] {
        1 => Algorithm::Zstd,
        2 => {
            let mut algo = [0u8; 1];
            reader
                .read_exact(&mut algo)
                .context("archive is truncated (header)")?;
            header.extend_from_slice(&algo);
            Algorithm::from_byte(algo[0])?
        }
        v => bail!("unsupported archive version {v}"),
    };

    let mut rest = [0u8; SALT_LEN + NONCE_PREFIX_LEN + 2];
    reader
        .read_exact(&mut rest)
        .context("archive is truncated (header)")?;
    let salt: [u8; SALT_LEN] = rest[..SALT_LEN].try_into().unwrap();
    let nonce_prefix: [u8; NONCE_PREFIX_LEN] = rest[SALT_LEN..SALT_LEN + NONCE_PREFIX_LEN]
        .try_into()
        .unwrap();
    let name_len = u16::from_le_bytes([rest[rest.len() - 2], rest[rest.len() - 1]]) as usize;
    header.extend_from_slice(&rest);
    if name_len == 0 || name_len > MAX_NAME_LEN {
        bail!("corrupt header (name length {name_len})");
    }

    let mut name_bytes = vec![0u8; name_len];
    reader
        .read_exact(&mut name_bytes)
        .context("archive is truncated (name)")?;
    let root_name = String::from_utf8(name_bytes.clone()).context("corrupt header (name)")?;
    header.extend_from_slice(&name_bytes);

    std::fs::create_dir_all(&opts.output_dir)
        .with_context(|| format!("cannot create output dir '{}'", opts.output_dir.display()))?;
    let target = opts.output_dir.join(&root_name);
    if target.exists() && !opts.force {
        bail!(
            "destination '{}' already exists (use --force to overwrite)",
            target.display()
        );
    }

    let key = derive_key(&opts.password, &salt)?;
    let decryptor = DecryptingReader::new(reader, &key, &nonce_prefix, header);
    let decomp =
        DecompressReader::new(decryptor, algorithm).context("failed to start decompressor")?;
    let mut archive = tar::Archive::new(decomp);
    let extract_err = "failed to extract archive (wrong password or corrupted data?)";

    if opts.force && target.exists() {
        // Extract into a staging directory first, then swap it into place, so a
        // failed extraction (e.g. wrong password) never destroys the folder
        // that is already there — `--force` becomes a clean replacement, not a
        // merge into stale contents.
        let staging = opts.output_dir.join(format!(".{root_name}.foldlock-tmp"));
        let _ = remove_path(&staging);
        std::fs::create_dir_all(&staging)
            .with_context(|| format!("cannot create staging dir '{}'", staging.display()))?;
        match archive.unpack(&staging).context(extract_err) {
            Ok(()) => {
                let staged = staging.join(&root_name);
                remove_path(&target)?;
                let renamed = std::fs::rename(&staged, &target)
                    .with_context(|| format!("cannot move '{}' into place", staged.display()));
                let _ = remove_path(&staging);
                renamed?;
            }
            Err(e) => {
                let _ = remove_path(&staging);
                return Err(e);
            }
        }
    } else {
        archive.unpack(&opts.output_dir).context(extract_err)?;
    }

    Ok(DecompressSummary {
        output: target,
        volumes_read,
    })
}

/// Remove a file or directory at `path` if it exists.
fn remove_path(path: &Path) -> Result<()> {
    if path.is_dir() {
        std::fs::remove_dir_all(path)
    } else if path.exists() {
        std::fs::remove_file(path)
    } else {
        Ok(())
    }
    .with_context(|| format!("cannot remove '{}'", path.display()))
}

/// Build the plaintext header: magic, version, algorithm, salt, nonce prefix,
/// and name.
fn build_header(
    algorithm: Algorithm,
    salt: &[u8; SALT_LEN],
    nonce_prefix: &[u8; NONCE_PREFIX_LEN],
    name: &str,
) -> Result<Vec<u8>> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() > MAX_NAME_LEN {
        bail!("folder name too long ({} bytes)", name_bytes.len());
    }
    let mut header =
        Vec::with_capacity(4 + 1 + 1 + SALT_LEN + NONCE_PREFIX_LEN + 2 + name_bytes.len());
    header.extend_from_slice(MAGIC);
    header.push(FORMAT_VERSION);
    header.push(algorithm.to_byte());
    header.extend_from_slice(salt);
    header.extend_from_slice(nonce_prefix);
    header.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    header.extend_from_slice(name_bytes);
    Ok(header)
}

/// True if `path` is one of our own output volumes living directly in
/// `output_dir` (named `<base>.<digits>`), so we never archive our own output.
fn is_own_output(path: &Path, output_dir: &Path, volume_prefix: &str) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let Some(suffix) = name.strip_prefix(volume_prefix) else {
        return false;
    };
    if suffix.is_empty() || !suffix.chars().all(|c| c.is_ascii_digit()) {
        return false;
    }
    path.parent()
        .and_then(|p| p.canonicalize().ok())
        .map(|p| p == output_dir)
        .unwrap_or(false)
}
