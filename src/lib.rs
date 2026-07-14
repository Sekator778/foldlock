//! `foldlock` — compress a folder, encrypt it with a password, and split it
//! into fixed-size volumes (and the reverse).
//!
//! Pipeline: `tar` → compress (`zstd` or `xz`) → ChaCha20-Poly1305 STREAM →
//! split volumes.
//!
//! On-disk layout of the logical stream (before volume splitting):
//!
//! ```text
//! ┌─ opaque prefix ─┐┌──────────── AEAD ciphertext ────────────┐
//! │ salt[16] nonc[7]││ enc( inner header ‖ compressed tar )     │
//! └─────────────────┘└─────────────────────────────────────────┘
//!
//! inner header (encrypted): "FLK1" │ ver │ algo │ name_len(u16-le) │ name
//! ```
//!
//! Only the random salt and nonce prefix are in the clear; the magic, version,
//! compression `algo`, and folder `name` all live *inside* the ciphertext, so a
//! stored blob is byte-for-byte indistinguishable from random data without the
//! password — and it cannot even be identified as a foldlock archive. `algo`
//! selects the compression backend (zstd or xz). Salt and nonce need no AEAD
//! additional-data: tampering with the salt derives the wrong key and tampering
//! with the nonce fails the tag, so both are caught implicitly.
//!
//! Legacy v1/v2 archives — which carried a *plaintext* `FLK1` header — are still
//! read (detected by that leading magic); new archives are only ever written in
//! the current format.

mod armor;
mod codec;
mod crypto;
mod volume;

use std::fs::File;
use std::io::{self, BufReader, BufWriter, Cursor, Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use walkdir::WalkDir;

use armor::ArmorWriter;
use crypto::{derive_key, DecryptingReader, EncryptingWriter, NONCE_PREFIX_LEN, SALT_LEN};
use volume::{VolumeReader, VolumeWriter};

pub use codec::Algorithm;
use codec::{CompressWriter, DecompressReader};

/// Files above this size are never slurped to test for armored text — an
/// armored blob is meant for small (byte/kilobyte) payloads, so anything larger
/// is assumed to be binary and streamed rather than read into memory.
const ARMOR_READ_CAP: u64 = 64 * 1024 * 1024;

/// Smallest a base64-decoded blob can be and still be plausibly an archive
/// (salt + nonce + a non-empty AEAD block). Shorter decodes are unrelated text
/// that merely happened to contain base64 letters, so they are not treated as
/// armor. Kept safely below the true minimum (~70 bytes) to never reject a real
/// archive; anything above it that is *not* ours simply fails to decrypt later.
const MIN_ARMOR_BYTES: usize = 40;

/// File extension marking a foldlock volume set: `<folder>.flk.NNN`.
const ARCHIVE_EXT: &str = "flk";
const MAGIC: &[u8; 4] = b"FLK1";
/// Inner-header format version, written *inside* the ciphertext. Legacy plaintext
/// headers used v1 (zstd only, no algorithm byte) and v2 (adds an algorithm
/// byte); both are still readable via the legacy path. v3 is the current format,
/// where the whole header moved inside the AEAD.
const FORMAT_VERSION: u8 = 3;
/// Legacy plaintext-header versions, recognized by a leading [`MAGIC`].
const LEGACY_VERSION_ZSTD: u8 = 1;
const LEGACY_VERSION_ALGO: u8 = 2;
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
    /// Emit a single copy-pasteable armored text file instead of binary volumes.
    /// When set, [`volume_size`](CompressOptions::volume_size) is ignored.
    pub armor: bool,
}

/// Result of a successful [`compress`].
#[derive(Debug)]
pub struct CompressSummary {
    /// Paths of the output files that were written, in order. For an armored
    /// run this is the single `.flk.txt` file; otherwise the `.NNN` volumes.
    pub volumes: Vec<PathBuf>,
    /// Total bytes across all output files.
    pub total_bytes: u64,
    /// Whether the output is a single armored text file rather than volumes.
    pub armored: bool,
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
    /// How the archive bytes were obtained.
    pub source: SourceKind,
}

/// Where a [`decompress`] read its archive bytes from, for reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceKind {
    /// Reassembled from this many split `.NNN` volumes.
    Volumes(usize),
    /// Decoded from a single armored (base64) text file.
    Armor,
    /// Streamed from a single standalone binary archive file.
    SingleFile,
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

    // Random salt + nonce prefix — the only bytes ever written in the clear.
    let mut salt = [0u8; SALT_LEN];
    let mut nonce_prefix = [0u8; NONCE_PREFIX_LEN];
    getrandom::getrandom(&mut salt).map_err(|e| anyhow!("RNG failure: {e}"))?;
    getrandom::getrandom(&mut nonce_prefix).map_err(|e| anyhow!("RNG failure: {e}"))?;

    // The identifying header (magic, version, algorithm, folder name) is encrypted
    // below rather than written in the clear, so it leaks nothing.
    let inner_header = build_inner_header(opts.algorithm, &root_name)?;
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

    // Build the writer chain: sink <- encrypt <- compress <- tar. The sink is
    // either the split-volume writer or, for `--armor`, a base64 text writer;
    // both are hidden behind `Sink` so the rest of the chain stays generic.
    let mut sink = if opts.armor {
        let armor_path = opts.output_dir.join(format!("{base_name}.txt"));
        let file = File::create(&armor_path)
            .with_context(|| format!("cannot create '{}'", armor_path.display()))?;
        Sink::Armor(ArmorWriter::new(BufWriter::new(file)), armor_path)
    } else {
        Sink::Volumes(VolumeWriter::new(base_path, opts.volume_size))
    };
    // Opaque prefix: salt || nonce, indistinguishable from random data.
    sink.write_all(&salt)
        .context("failed to write archive header")?;
    sink.write_all(&nonce_prefix)
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

    // No AAD: the inner header is encrypted as the first plaintext written to the
    // stream, so it is authenticated as ciphertext rather than as additional data.
    let mut encryptor = EncryptingWriter::new(sink, &key, &nonce_prefix, Vec::new());
    encryptor
        .write_all(&inner_header)
        .context("failed to write archive header")?;
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
    let sink = encryptor.finish().context("failed to finish encryption")?;
    let (volumes, armored) = match sink.finish().context("failed to flush output")? {
        SinkOutput::Volumes(paths) => (paths, false),
        SinkOutput::Armor(path) => (vec![path], true),
    };

    let total_bytes = volumes
        .iter()
        .map(|p| p.metadata().map(|m| m.len()).unwrap_or(0))
        .sum();

    Ok(CompressSummary {
        volumes,
        total_bytes,
        armored,
        skipped_symlinks,
        threads,
    })
}

/// Reassemble, decrypt, decompress, and extract a volume set.
pub fn decompress(opts: &DecompressOptions) -> Result<DecompressSummary> {
    // Obtain the raw archive byte stream — an armored (base64) blob, a standalone
    // binary file, or a joined split-volume set.
    let (mut source, source_kind) = open_source(&opts.archive)?;

    // The current format opens with an opaque salt|nonce prefix; a legacy archive
    // opens with the plaintext "FLK1" magic. Peek the first four bytes to tell
    // them apart, then recover the folder name, compression algorithm, and a
    // decryptor positioned at the (encrypted) tar stream.
    let mut prefix = [0u8; 4];
    source
        .read_exact(&mut prefix)
        .context("archive is truncated (header)")?;

    let (root_name, algorithm, decryptor) = if &prefix == MAGIC {
        read_legacy_header(source, &opts.password)?
    } else {
        read_current_header(source, prefix, &opts.password)?
    };

    std::fs::create_dir_all(&opts.output_dir)
        .with_context(|| format!("cannot create output dir '{}'", opts.output_dir.display()))?;
    let target = opts.output_dir.join(&root_name);
    if target.exists() && !opts.force {
        bail!(
            "destination '{}' already exists (use --force to overwrite)",
            target.display()
        );
    }

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
        source: source_kind,
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

/// Build the inner header — magic, version, algorithm, and name — that is
/// written *inside* the ciphertext (the salt and nonce prefix stay outside, in
/// the clear, and so are not part of it).
fn build_inner_header(algorithm: Algorithm, name: &str) -> Result<Vec<u8>> {
    let name_bytes = name.as_bytes();
    if name_bytes.len() > MAX_NAME_LEN {
        bail!("folder name too long ({} bytes)", name_bytes.len());
    }
    let mut header = Vec::with_capacity(4 + 1 + 1 + 2 + name_bytes.len());
    header.extend_from_slice(MAGIC);
    header.push(FORMAT_VERSION);
    header.push(algorithm.to_byte());
    header.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    header.extend_from_slice(name_bytes);
    Ok(header)
}

/// Read a legacy (v1/v2) *plaintext* header. The leading magic has already been
/// consumed from `source`; the exact header bytes are re-accumulated so they can
/// be replayed as the AEAD additional-authenticated-data the way these archives
/// were written. Returns the folder name, algorithm, and a decryptor positioned
/// at the ciphertext.
fn read_legacy_header(
    mut source: Source,
    password: &str,
) -> Result<(String, Algorithm, DecryptingReader<Source>)> {
    let mut header: Vec<u8> = Vec::with_capacity(64);
    header.extend_from_slice(MAGIC);

    let mut ver = [0u8; 1];
    source
        .read_exact(&mut ver)
        .context("archive is truncated (header)")?;
    header.extend_from_slice(&ver);

    // v1 has no algorithm byte (always zstd); v2 stores the backend right after
    // the version.
    let algorithm = match ver[0] {
        LEGACY_VERSION_ZSTD => Algorithm::Zstd,
        LEGACY_VERSION_ALGO => {
            let mut algo = [0u8; 1];
            source
                .read_exact(&mut algo)
                .context("archive is truncated (header)")?;
            header.extend_from_slice(&algo);
            Algorithm::from_byte(algo[0])?
        }
        v => bail!("unsupported archive version {v}"),
    };

    let mut rest = [0u8; SALT_LEN + NONCE_PREFIX_LEN + 2];
    source
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
    source
        .read_exact(&mut name_bytes)
        .context("archive is truncated (name)")?;
    let root_name = String::from_utf8(name_bytes.clone()).context("corrupt header (name)")?;
    header.extend_from_slice(&name_bytes);

    let key = derive_key(password, &salt)?;
    let decryptor = DecryptingReader::new(source, &key, &nonce_prefix, header);
    Ok((root_name, algorithm, decryptor))
}

/// Read the current-format header. The opaque prefix is `salt || nonce`; its
/// first four bytes are already consumed and passed in as `prefix`. The rest of
/// the prefix is read in the clear, then the magic, version, algorithm, and name
/// are recovered from *inside* the ciphertext.
///
/// A wrong password makes the AEAD tag fail while reading the inner magic, which
/// is deliberately indistinguishable from "not a foldlock archive" — without the
/// password there is nothing that identifies the blob as ours.
fn read_current_header(
    mut source: Source,
    prefix: [u8; 4],
    password: &str,
) -> Result<(String, Algorithm, DecryptingReader<Source>)> {
    // Finish reading the opaque prefix: salt (16) + nonce prefix (7), of which
    // the first four salt bytes are already in `prefix`.
    let mut tail = [0u8; SALT_LEN + NONCE_PREFIX_LEN - 4];
    source
        .read_exact(&mut tail)
        .context("archive is truncated (header)")?;
    let mut salt = [0u8; SALT_LEN];
    salt[..4].copy_from_slice(&prefix);
    salt[4..].copy_from_slice(&tail[..SALT_LEN - 4]);
    let nonce_prefix: [u8; NONCE_PREFIX_LEN] = tail[SALT_LEN - 4..].try_into().unwrap();

    let key = derive_key(password, &salt)?;
    // No AAD: the header is encrypted plaintext, authenticated as ciphertext.
    let mut decryptor = DecryptingReader::new(source, &key, &nonce_prefix, Vec::new());

    let bad = || anyhow!("wrong password, or not a foldlock archive");
    let mut magic = [0u8; MAGIC.len()];
    decryptor.read_exact(&mut magic).map_err(|_| bad())?;
    if &magic != MAGIC {
        return Err(bad());
    }

    let mut ver = [0u8; 1];
    decryptor.read_exact(&mut ver).context("corrupt header")?;
    if ver[0] != FORMAT_VERSION {
        bail!("unsupported archive version {}", ver[0]);
    }

    let mut algo = [0u8; 1];
    decryptor.read_exact(&mut algo).context("corrupt header")?;
    let algorithm = Algorithm::from_byte(algo[0])?;

    let mut name_len_bytes = [0u8; 2];
    decryptor
        .read_exact(&mut name_len_bytes)
        .context("corrupt header")?;
    let name_len = u16::from_le_bytes(name_len_bytes) as usize;
    if name_len == 0 || name_len > MAX_NAME_LEN {
        bail!("corrupt header (name length {name_len})");
    }

    let mut name_bytes = vec![0u8; name_len];
    decryptor
        .read_exact(&mut name_bytes)
        .context("corrupt header (name)")?;
    let root_name = String::from_utf8(name_bytes).context("corrupt header (name)")?;

    Ok((root_name, algorithm, decryptor))
}

/// True if `path` is one of our own output files living directly in
/// `output_dir` — a numbered volume (`<base>.<digits>`) or the armored text file
/// (`<base>.txt`) — so we never archive our own output when packing in place.
fn is_own_output(path: &Path, output_dir: &Path, volume_prefix: &str) -> bool {
    let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let Some(suffix) = name.strip_prefix(volume_prefix) else {
        return false;
    };
    let is_volume = !suffix.is_empty() && suffix.chars().all(|c| c.is_ascii_digit());
    let is_armor = suffix == "txt";
    if !is_volume && !is_armor {
        return false;
    }
    path.parent()
        .and_then(|p| p.canonicalize().ok())
        .map(|p| p == output_dir)
        .unwrap_or(false)
}

/// The final sink of the compression chain: either the split-volume writer or,
/// for `--armor`, a base64 text writer over a single file. Wrapping both behind
/// one `Write` type keeps `tar` → compress → encrypt generic over the output.
enum Sink {
    Volumes(VolumeWriter),
    Armor(ArmorWriter<BufWriter<File>>, PathBuf),
}

/// What a [`Sink`] produced once finalized.
enum SinkOutput {
    Volumes(Vec<PathBuf>),
    Armor(PathBuf),
}

impl Sink {
    /// Flush and close the sink, returning the paths it wrote.
    fn finish(self) -> io::Result<SinkOutput> {
        match self {
            Sink::Volumes(w) => Ok(SinkOutput::Volumes(w.finish()?)),
            Sink::Armor(w, path) => {
                w.finish()?;
                Ok(SinkOutput::Armor(path))
            }
        }
    }
}

impl Write for Sink {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Sink::Volumes(w) => w.write(buf),
            Sink::Armor(w, _) => w.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Sink::Volumes(w) => w.flush(),
            Sink::Armor(w, _) => w.flush(),
        }
    }
}

/// The source a [`decompress`] reads its archive bytes from. All three variants
/// present a single continuous `Read` stream to the header parser and decryptor.
enum Source {
    Volumes(VolumeReader),
    Armor(Cursor<Vec<u8>>),
    SingleFile(BufReader<File>),
}

impl Read for Source {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Source::Volumes(r) => r.read(buf),
            Source::Armor(r) => r.read(buf),
            Source::SingleFile(r) => r.read(buf),
        }
    }
}

/// Classify `archive` and open the right source.
///
/// Precedence for a single existing file: a numbered `.NNN` volume is joined by
/// name (the current format has no content magic to key off); otherwise a legacy
/// plaintext-magic file streams directly; otherwise a small file is tried as an
/// armored base64 blob. Whether an armored blob is genuinely ours is settled
/// later by decryption, so the length gate here only skips obviously-too-short
/// text. Anything unrecognized (including a bare base name whose only real files
/// are `.NNN` volumes) falls through to the volume opener.
fn open_source(archive: &Path) -> Result<(Source, SourceKind)> {
    if archive.is_file() {
        // A numbered volume is recognized by its name and handed to the volume
        // opener to join the whole set — regardless of its (now unmarked) content.
        if has_digit_extension(archive) {
            let reader = VolumeReader::open(archive)?;
            let count = reader.volume_count();
            return Ok((Source::Volumes(reader), SourceKind::Volumes(count)));
        }

        // A legacy archive still carries the plaintext magic; stream it directly.
        let mut file =
            File::open(archive).with_context(|| format!("cannot open '{}'", archive.display()))?;
        let mut magic = [0u8; MAGIC.len()];
        let n = read_fully(&mut file, &mut magic)?;
        if n == MAGIC.len() && &magic == MAGIC {
            let file = File::open(archive)?;
            return Ok((
                Source::SingleFile(BufReader::new(file)),
                SourceKind::SingleFile,
            ));
        }

        // Otherwise try to read it as an armored (base64) blob.
        let len = file.metadata().map(|m| m.len()).unwrap_or(0);
        if len <= ARMOR_READ_CAP {
            let data = std::fs::read(archive)
                .with_context(|| format!("cannot read '{}'", archive.display()))?;
            if let Some(bytes) = armor::decode(&data) {
                if bytes.len() >= MIN_ARMOR_BYTES {
                    return Ok((Source::Armor(Cursor::new(bytes)), SourceKind::Armor));
                }
            }
        }
    }
    // Fall back to the volume opener: a base name or a numbered volume.
    let reader = VolumeReader::open(archive)?;
    let count = reader.volume_count();
    Ok((Source::Volumes(reader), SourceKind::Volumes(count)))
}

/// Read from `r` until `buf` is full or EOF, returning the number of bytes read.
fn read_fully(r: &mut impl Read, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..])? {
            0 => break,
            n => filled += n,
        }
    }
    Ok(filled)
}

/// True if `path`'s extension is a non-empty run of ASCII digits (a `.NNN`
/// volume suffix).
fn has_digit_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|e| e.to_str())
        .map(|e| !e.is_empty() && e.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or(false)
}
