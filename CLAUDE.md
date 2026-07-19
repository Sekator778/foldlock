# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

`foldlock` is a single-binary Rust CLI that runs `tar → compress → encrypt → split` in one command (and the exact reverse). It packs a folder, compresses it (zstd or xz), encrypts with a password-derived key (ChaCha20-Poly1305 STREAM, Argon2id KDF), and slices the result into fixed-size `.flk.NNN` volumes — or, with `--armor`, a single base64 text file.

## Commands

```sh
cargo build --release                         # optimized binary at target/release/foldlock (size-tuned: opt-level=z, LTO, strip, panic=abort)
cargo test                                     # unit tests + tests/integration.rs
cargo test roundtrip_armor_autodetected        # a single test by name (substring match)
cargo test --test integration                  # only the integration suite
cargo fmt --all -- --check                     # CI enforces this
cargo clippy --all-targets -- -D warnings      # CI enforces this (warnings are errors)
```

Requires Rust **1.85+** and a C compiler (libzstd and liblzma are built from source via `cc`). CI runs the test matrix on Linux/macOS/Windows plus a separate fmt+clippy job.

## Architecture

The whole program is a chain of `Read`/`Write` adapters. Compression builds the writer chain **sink ← encrypt ← compress ← tar** and feeds directory entries into it; decompression builds the mirror reader chain and unpacks. Each stage is a thin adapter implementing `std::io::Write` or `Read`, so the stages compose generically and stream without buffering the whole archive.

- **`src/lib.rs`** — the orchestrator and the public API (`compress`/`decompress`, their `*Options`/`*Summary` structs). Owns the archive format: the opaque `salt || nonce` prefix, the encrypted inner header, source classification (`open_source`), and the legacy-format reader. **Read this first.**
- **`src/crypto.rs`** — `derive_key` (Argon2id) and the AEAD STREAM adapters `EncryptingWriter` / `DecryptingReader`. Plaintext is sealed in 64 KiB blocks (`BLOCK`); `DecryptingReader` uses one-block lookahead to know when to call `decrypt_last`.
- **`src/codec.rs`** — pluggable compression backends behind the `Algorithm` enum (`Zstd`=0, `Xz`=1). `CompressWriter`/`DecompressReader` wrap zstd and xz encoders/decoders in enums. The algorithm byte is stored in the header, so decompression auto-selects.
- **`src/volume.rs`** — `VolumeWriter` rolls over every N bytes into `<base>.001`, `.002`, …; `VolumeReader` presents a volume set as one continuous stream and detects interior gaps (`GAP_PROBE_WINDOW`).
- **`src/armor.rs`** — base64 transport encoding with **no framing/markers**. `decode` discards every non-base64 byte (whitespace, CRLF, BOM, padding) before decoding, so a messy clipboard paste survives. Armored bytes are byte-identical to the binary path.
- **`src/main.rs`** — hand-rolled arg parsing (no clap), password resolution (`-` → prompt, `FOLDLOCK_PASSWORD` env, or literal arg), and terse output. `--` ends option parsing.

## Archive format (critical — versioned, back-compat matters)

Current format (v3): a stream begins with an **opaque prefix** of `salt[16] || nonce_prefix[7]` in the clear — indistinguishable from random. Everything identifying (`FLK1` magic, version byte, algorithm byte, folder name) lives in an **inner header encrypted as the first plaintext of the AEAD stream**. Without the password a blob cannot even be identified as a foldlock archive; a wrong password is indistinguishable from "not ours."

- **Detection on read** peeks the first 4 bytes: `FLK1` magic → legacy path (`read_legacy_header`); anything else → current path (`read_current_header`, which decrypts to find the magic).
- **Legacy v1/v2** archives carried a *plaintext* header and replayed those exact header bytes as AEAD additional-authenticated-data (AAD). They are still **read** (never written). The current format uses **no AAD** — the header is authenticated as ciphertext.
- When changing the format, bump `FORMAT_VERSION` in `lib.rs`, keep the legacy readers working, and add a round-trip test. The salt/nonce are deliberately *not* AAD: tampering with the salt derives a wrong key and tampering with the nonce fails the tag, so both are caught implicitly.

## Conventions & gotchas

- **Volume size is MiB** (× 1024²), parsed in `main.rs`. `--armor` takes no size argument and ignores volume size (`u64::MAX` cap → one blob).
- **Self-output avoidance**: when packing the current directory in place, entries are pre-collected and `is_own_output` skips our own `.flk.NNN` / `.flk.txt` files.
- **`--force` is atomic**: extraction goes to a `.<name>.foldlock-tmp` staging dir, then swaps in — a failed decrypt never destroys the existing folder.
- Not preserved: symlinks (skipped with a count), permissions, xattrs. Only plain files and directories.
- Empty passwords are rejected in `derive_key`. Derived keys are `Zeroizing` (wiped on drop).
- Tests live in **`tests/integration.rs`** and exercise real round trips (multi-volume mid-block splits, wrong password, force/overwrite, missing interior volume, xz, zstd-ultra, armor paste corruption, metadata-hiding). Any format or pipeline change should keep these green.
