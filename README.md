# 🔒 foldlock

[![CI](https://github.com/Sekator778/foldlock/actions/workflows/ci.yml/badge.svg)](https://github.com/Sekator778/foldlock/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)

**A tiny, fast Rust CLI that compresses a folder, encrypts it with a password, and splits it into fixed-size volumes — in one command.** Decompression reverses all three steps with just the archive and the password.

Think `tar | zstd | encrypt | split`, but a single ~1 MB self-contained binary with strong authenticated encryption and no shell pipelines to remember.

```console
$ foldlock compress ./photos - 100
Password: ********
Confirm password: ********
Created 11 volume(s)

$ foldlock decompress ./photos.flk -
Password: ********
Extracted ./photos
```

## ✨ Features

- **One command does it all** — archive + compress + encrypt + split (and the exact reverse).
- **Strong, authenticated encryption** — ChaCha20-Poly1305 in AEAD **STREAM** mode, keyed by **Argon2id** from your password. Tampering, truncation, reordering, and wrong passwords are all detected.
- **Excellent compression** — zstd at level 19 by default, with optional zstd-ultra (`-l 22`) or xz/LZMA (`--max`) for maximum density.
- **Uses every CPU core** — multi-threaded compression (the only CPU-bound stage) scales across all cores automatically.
- **Splits into volumes** — choose any volume size in MiB; great for size-limited storage, uploads, or transfer.
- **Text-safe transport** — `--armor` base64-encodes the whole archive into a single line of plain text, for channels that only carry text (clipboard, chat, email); `decompress` detects it automatically. Line wrapping, CRLF, and stray whitespace are tolerated, so paste it as its own block. Best for small (byte/kilobyte) payloads.
- **Nothing identifying in the clear** — an archive begins with only its random salt and nonce; the magic, version, compression backend, and **folder name** all live *inside* the ciphertext. Without the password a blob is indistinguishable from random data — you cannot even tell it is a foldlock archive, and a wrong password is indistinguishable from "not ours."
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
foldlock compress ./photos - 100   # 100 MiB volumes: photos.flk.001, .002, … ('-' prompts for the password)
```

- `<folder>`   – the directory (or file) to pack
- `<password>` – password used to derive the encryption key
- `<size_MiB>` – maximum size of each output volume, in **MiB**

Volumes are written to the current directory as `<folder>.flk.001`, `.002`, …

#### Compression backend & level

By default foldlock uses **zstd level 19** — fast and a great ratio. For maximum density you can switch backends or raise the level:

```sh
foldlock compress ./src - 100 --max        # xz / LZMA: ~9% smaller, ~3x slower
foldlock compress ./src - 100 -l 22        # zstd ultra (wider window)
foldlock compress ./src - 100 --algo xz -l 6   # xz, custom level
```

- `-a, --algo <zstd|xz>` – backend (default `zstd`). `xz` is ~9% smaller on source
  trees but ~3× slower; decompression speed is unaffected.
- `-l, --level <n>` – level. zstd: `1..=22` (default 19; `20..=22` enable a wider
  window for higher density). xz: `0..=9` (default 9, extreme).
- `--max` – shortcut for `--algo xz`.

The backend is recorded in the archive header, so **decompression detects it automatically** — no flag needed.

#### Text-safe (armored) archives

Binary output doesn't survive plain-text channels: clipboards, chat apps, and email bodies can mangle, reject, or reformat raw bytes. `--armor` is a base64 text encoding for moving a small archive through exactly those channels. It writes the whole archive as a single continuous line of text instead of binary volumes, and takes **no size argument** (the output is always one file):

```console
$ foldlock compress ./notes - --armor
Password: ********
Confirm password: ********
Created ./notes.flk.txt
```

The file is base64 of `salt ‖ nonce ‖ ciphertext` — plain text, safe to paste anywhere text is accepted:

```console
$ cat notes.flk.txt
h2kX8DnQjaTYdJAMv4uSHAdhxcXDV8pAGSUk2bQrlWd6Edgc8T2FEQUF3DI38aWgnFkLNEz…
```

Copy those characters through a clipboard, chat, or email, paste them into a file (any name; line wrapping, CRLF, and stray whitespace are all tolerated), and decompress it by that name — `decompress` **auto-detects** the armored format, no flag needed:

```console
$ foldlock decompress ./one -
Password: ********
Extracted ./notes
```

Paste the blob as its **own block, with nothing else in the file**. There are no frame delimiters, so any other base64-alphabet text sharing the file would be read as part of the payload and corrupt it.

`--armor` is meant for **small data**: base64 adds ~33% overhead, and clipboards/chat apps/email have size limits — use binary volumes for anything larger. Integrity is unchanged: the same authenticated encryption still detects tampering or copy-paste corruption, and a bad password or malformed blob fails decompression cleanly.

### Decompress

```sh
foldlock decompress ./photos.flk -      # base name ('-' prompts for the password)
foldlock decompress ./photos.flk.001 -  # …or any single volume
```

The original folder name and the volume size are stored in the archive header, so **decompression only needs the archive and the password** — no size argument. The folder is recreated in the current directory. Pass `-f` / `--force` to overwrite an existing folder.

### Password handling

Pass `-` as the password to be prompted for it interactively, without echo. This is the form used throughout this README, and the one you should default to:

```sh
foldlock compress ./photos - 100    # prompts twice (to confirm) and doesn't echo
foldlock decompress ./photos.flk -  # prompts once
```

Avoid putting the password directly on the command line (`foldlock compress ./photos s3cret 100`) — any other user on the machine can read it from the process list (`ps`), and your shell saves it in plaintext history. foldlock still accepts it that way for backward compatibility, but prints a one-line warning to stderr when it does.

For scripts and other non-interactive callers, pipe the password in instead of typing it in argv:

```sh
echo "$PASSWORD" | foldlock compress ./photos - 100 --password-stdin
```

`--password-stdin` reads the password from stdin (trailing newline stripped) and pairs with `-` as the password argument. The `FOLDLOCK_PASSWORD` environment variable is also supported, and is checked when `-` is given without `--password-stdin`.

If your password itself starts with `-`, put it after a `--` separator so it isn't parsed as an option:

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
foldlock compress ./project - 1000000    # 1 TB cap → one volume
```

**Non-interactive backup from a script / cron** (password piped in, no TTY):

```sh
foldlock compress /var/data/db - 250 --max --password-stdin < /etc/foldlock/db.pass
```

Or from the environment, if a secrets manager already exports it:

```sh
export FOLDLOCK_PASSWORD='correct horse battery staple'
foldlock compress /var/data/db - 250 --max
unset FOLDLOCK_PASSWORD
```

**zstd ultra when you want more density but keep zstd’s fast decompression:**

```sh
foldlock compress ./logs - 100 -l 22
```

**A small secret as portable text** (armored, auto-detected on decompress):

```sh
foldlock compress ./ssh-keys - --armor    # → ssh-keys.flk.txt (one line of base64)
# copy the characters, paste into a file on another machine (any name), then:
foldlock decompress ./ssh-keys.flk.txt -   # auto-detected, prompts for the password
```

**Restore** — no size or algorithm needed, both are read from the archive:

```sh
foldlock decompress ./photos.flk -             # base name, prompt for password
foldlock decompress ./photos.flk.001 -         # …or point at any single volume
foldlock decompress ./photos.flk - -f          # overwrite an existing ./photos
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

With `--armor`, the final split stage is replaced by a base64 encoder that writes one text file; `decompress` sniffs the input and base64-decodes it back into the exact same byte stream before the usual join/decrypt/… path. Armor is a pure transport encoding — the encrypted bytes are identical either way.

Each archive begins with an **opaque prefix** — just the random 16-byte salt and 7-byte nonce prefix, both indistinguishable from noise. Everything identifying (the `FLK1` magic, format version, compression backend, and folder name) is an **inner header encrypted as the first bytes of the stream**, so none of it appears in the clear. The salt and nonce need no additional-authenticated-data: tampering with the salt derives the wrong key, and tampering with the nonce fails the tag, so both are caught implicitly. Recognizing an archive therefore means *decrypting* it — a wrong password is indistinguishable from "not a foldlock archive," which is what keeps a stored blob deniable. (Legacy v1/v2 archives that carried a plaintext header are still read.)

The compressed byte stream is encrypted as a sequence of 64 KiB AEAD blocks (the STREAM construction), then sliced into volumes of the requested size. Because each block carries its own authentication tag and a sequence counter, a corrupted, missing, reordered, or extra volume — or a wrong password — fails loudly instead of producing garbage.

### Key derivation & crypto choices

| Concern | Choice |
|---|---|
| Key derivation | Argon2id (memory-hard) from password + random salt |
| Encryption | ChaCha20-Poly1305 (AEAD), STREAM/`BE32` construction |
| Per-block nonce | random 7-byte prefix ‖ 32-bit counter |
| Integrity | Poly1305 tag per block; header encrypted inside the stream |
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
