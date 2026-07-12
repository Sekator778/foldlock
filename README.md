# 🔒 foldlock

[![CI](https://github.com/Sekator778/foldlock/actions/workflows/ci.yml/badge.svg)](https://github.com/Sekator778/foldlock/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)

**A tiny, fast Rust CLI that compresses a folder, encrypts it with a password, and splits it into fixed-size volumes — in one command.** Decompression reverses all three steps with just the archive and the password.

Think `tar | zstd | encrypt | split`, but a single ~1 MB self-contained binary with strong authenticated encryption and no shell pipelines to remember.

```console
$ foldlock compress ./photos s3cret 100
Created 11 volume(s) of up to 100 MiB (1.0 GiB total, 48 thread(s)):
  ./photos.flk.001  (100.0 MiB)
  ./photos.flk.002  (100.0 MiB)
  ...
  ./photos.flk.011  (47.3 MiB)

$ foldlock decompress ./photos.flk s3cret
Extracted './photos' from 11 volume(s).
```

## ✨ Features

- **One command does it all** — archive + compress + encrypt + split (and the exact reverse).
- **Strong, authenticated encryption** — ChaCha20-Poly1305 in AEAD **STREAM** mode, keyed by **Argon2id** from your password. Tampering, truncation, reordering, and wrong passwords are all detected.
- **Excellent compression** — zstd at level 19 by default, with optional zstd-ultra (`-l 22`) or xz/LZMA (`--max`) for maximum density.
- **Uses every CPU core** — multi-threaded compression (the only CPU-bound stage) scales across all cores automatically.
- **Splits into volumes** — choose any volume size in MiB; great for size-limited storage, uploads, or transfer.
- **Tiny & self-contained** — a single ~1 MB binary, no runtime dependencies, optimized for size.
- **Safe by default** — refuses to overwrite an existing folder; can prompt for the password without echoing it.

## 📦 Install

### Download a prebuilt binary

Grab the binary for your platform from the [Releases](https://github.com/Sekator778/foldlock/releases) page, then make it executable:

```sh
chmod +x foldlock
./foldlock --help
```

### Build from source

```sh
cargo install --git https://github.com/Sekator778/foldlock
# or
git clone https://github.com/Sekator778/foldlock
cd foldlock
cargo build --release   # binary at target/release/foldlock
```

Requires Rust **1.85+** and a C compiler (for the bundled libzstd).

## 🚀 Usage

```text
foldlock compress   <folder> <password> <size_MiB>
foldlock decompress <archive> [password]
```

### Compress

```sh
foldlock compress ./photos s3cret 100   # 100 MiB volumes: photos.flk.001, .002, …
```

- `<folder>`   – the directory (or file) to pack
- `<password>` – password used to derive the encryption key
- `<size_MiB>` – maximum size of each output volume, in **MiB**

Volumes are written to the current directory as `<folder>.flk.001`, `.002`, …

#### Compression backend & level

By default foldlock uses **zstd level 19** — fast and a great ratio. For maximum density you can switch backends or raise the level:

```sh
foldlock compress ./src s3cret 100 --max        # xz / LZMA: ~9% smaller, ~3x slower
foldlock compress ./src s3cret 100 -l 22        # zstd ultra (wider window)
foldlock compress ./src s3cret 100 --algo xz -l 6   # xz, custom level
```

- `-a, --algo <zstd|xz>` – backend (default `zstd`). `xz` is ~9% smaller on source
  trees but ~3× slower; decompression speed is unaffected.
- `-l, --level <n>` – level. zstd: `1..=22` (default 19; `20..=22` enable a wider
  window for higher density). xz: `0..=9` (default 9, extreme).
- `--max` – shortcut for `--algo xz`.

The backend is recorded in the archive header, so **decompression detects it automatically** — no flag needed.

### Decompress

```sh
foldlock decompress ./photos.flk s3cret      # base name
foldlock decompress ./photos.flk.001 s3cret  # …or any single volume
```

The original folder name and the volume size are stored in the archive header, so **decompression only needs the archive and the password** — no size argument. The folder is recreated in the current directory. Pass `-f` / `--force` to overwrite an existing folder.

### Password handling

A password typed on the command line is visible to other users (via the process list) and is saved in your shell history. For sensitive data, prefer one of:

```sh
foldlock compress ./photos - 100             # '-' → prompt, no echo (asked twice to confirm)
FOLDLOCK_PASSWORD=s3cret foldlock compress ./photos - 100   # from the environment
```

When a password is passed as an argument, foldlock prints a one-line warning to stderr. If your password itself starts with `-`, put it after a `--` separator so it isn't parsed as an option:

```sh
foldlock compress ./photos -- -my-password 100
```

### Examples

**Back up a photo library into 100 MiB volumes** (fits on FAT32 / upload chunks):

```sh
foldlock compress ./photos - 100
# → photos.flk.001, photos.flk.002, …  (prompts for the password, no echo)
```

**Maximum density for a source tree** (xz, ~9% smaller than the default):

```sh
foldlock compress ./project - 500 --max
# Created N volume(s) … (xz, 1 thread(s))
```

**Single-file archive** (huge volume size ⇒ everything in `.001`):

```sh
foldlock compress ./project s3cret 1000000    # 1 TB cap → one volume
```

**Non-interactive backup from a script / cron** (password from the environment):

```sh
export FOLDLOCK_PASSWORD='correct horse battery staple'
foldlock compress /var/data/db - 250 --max
unset FOLDLOCK_PASSWORD
```

**zstd ultra when you want more density but keep zstd’s fast decompression:**

```sh
foldlock compress ./logs s3cret 100 -l 22
```

**Restore** — no size or algorithm needed, both are read from the archive:

```sh
foldlock decompress ./photos.flk -             # base name, prompt for password
foldlock decompress ./photos.flk.001 -         # …or point at any single volume
foldlock decompress ./photos.flk s3cret -f     # overwrite an existing ./photos
```

**Full round trip in one place:**

```sh
foldlock compress ./notes - 50 --max     # → notes.flk.001, …
rm -rf ./notes                            # (originals gone)
foldlock decompress ./notes.flk -         # → recreates ./notes, byte-identical
```

## 🧠 How it works

```text
compress:   folder ─▶ tar ─▶ compress (zstd or xz) ─▶ ChaCha20-Poly1305 STREAM ─▶ split into .NNN volumes
decompress: .NNN volumes ─▶ join ─▶ decrypt + verify ─▶ decompress ─▶ untar ─▶ folder
```

Each archive begins with a small plaintext header (magic, version, a random 16-byte salt, a random 7-byte nonce prefix, and the folder name). The header is fed as **additional authenticated data** to the first encryption block, so any tampering with it is detected.

The compressed byte stream is encrypted as a sequence of 64 KiB AEAD blocks (the STREAM construction), then sliced into volumes of the requested size. Because each block carries its own authentication tag and a sequence counter, a corrupted, missing, reordered, or extra volume — or a wrong password — fails loudly instead of producing garbage.

### Key derivation & crypto choices

| Concern | Choice |
|---|---|
| Key derivation | Argon2id (memory-hard) from password + random salt |
| Encryption | ChaCha20-Poly1305 (AEAD), STREAM/`BE32` construction |
| Per-block nonce | random 7-byte prefix ‖ 32-bit counter |
| Integrity | Poly1305 tag per block; header bound as AAD |
| Compression | zstd level 19 (default, multi-threaded); optional zstd-ultra or xz/LZMA |

## ⚠️ Security notes & limitations

- The encryption is authenticated, but **foldlock is a small utility, not an audited cryptography product.** Use it accordingly.
- There is **no password recovery.** If you forget the password, the data is unrecoverable by design.
- Symbolic links, file permissions, and extended attributes are **not** preserved in this version (plain files and directories are). Symlinks in the source are skipped with a note.
- Volume size is interpreted as **MiB** (1 MiB = 1024 × 1024 bytes).

## 🛠️ Development

```sh
cargo test                              # round-trip, multi-volume, wrong-password, overwrite tests
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

## 📄 License

[MIT](LICENSE) © Sekator778
