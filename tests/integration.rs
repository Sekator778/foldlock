//! End-to-end tests for the foldlock library API.
//!
//! These call `compress`/`decompress` directly (no process spawn), so they work
//! regardless of the binary's `panic = "abort"` profile.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use foldlock::{compress, decompress, Algorithm, CompressOptions, DecompressOptions, SourceKind};
use tempfile::tempdir;

/// Deterministic, incompressible-ish bytes (so the compressed stream is large
/// enough to span several 64 KiB AEAD blocks).
fn pseudo_random(len: usize, seed: u64) -> Vec<u8> {
    let mut state = seed.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        // SplitMix64 step.
        state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^= z >> 31;
        out.push((z & 0xFF) as u8);
    }
    out
}

/// Build a nested fixture tree and return a map of relative path -> contents
/// (for files only; empty dirs are created but not in the map).
fn build_fixture(root: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut files = BTreeMap::new();

    let add = |rel: &str, data: Vec<u8>, files: &mut BTreeMap<PathBuf, Vec<u8>>| {
        let path = root.join(rel);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &data).unwrap();
        files.insert(PathBuf::from(rel), data);
    };

    add("readme.txt", b"hello foldlock\n".to_vec(), &mut files);
    add("nested/a.bin", pseudo_random(300 * 1024, 1), &mut files); // > 4 AEAD blocks
    add("nested/deep/b.bin", pseudo_random(70 * 1024, 2), &mut files);
    add(
        "nested/deep/c.txt",
        b"some plain text content".to_vec(),
        &mut files,
    );
    add("empty.dat", Vec::new(), &mut files);

    // An empty directory that should survive the round trip.
    fs::create_dir_all(root.join("emptydir")).unwrap();

    files
}

fn assert_tree_matches(extracted_root: &Path, expected: &BTreeMap<PathBuf, Vec<u8>>) {
    for (rel, data) in expected {
        let path = extracted_root.join(rel);
        let got = fs::read(&path)
            .unwrap_or_else(|e| panic!("missing extracted file {}: {e}", path.display()));
        assert_eq!(&got, data, "content mismatch for {}", rel.display());
    }
    assert!(
        extracted_root.join("emptydir").is_dir(),
        "empty directory was not preserved"
    );
}

#[test]
fn roundtrip_tiny_volumes_force_midblock_splits() {
    let work = tempdir().unwrap();
    let src_parent = work.path().join("src");
    let source = src_parent.join("payload");
    fs::create_dir_all(&source).unwrap();
    let expected = build_fixture(&source);

    let out_dir = work.path().join("out");
    fs::create_dir_all(&out_dir).unwrap();

    // 4 KiB volumes against a ~370 KiB incompressible payload => volume
    // boundaries fall in the middle of 64 KiB AEAD blocks (the case that
    // breaks naive stream readers).
    let summary = compress(&CompressOptions {
        source: source.clone(),
        password: "correct horse battery staple".to_string(),
        volume_size: 4 * 1024,
        output_dir: out_dir.clone(),
        algorithm: Algorithm::Zstd,
        level: None,
        armor: false,
    })
    .expect("compress failed");

    assert!(
        summary.volumes.len() > 50,
        "expected many small volumes, got {}",
        summary.volumes.len()
    );
    for v in &summary.volumes {
        assert!(v.is_file(), "volume {} missing", v.display());
    }

    let extract_dir = work.path().join("extract");
    let result = decompress(&DecompressOptions {
        archive: out_dir.join("payload.flk"),
        password: "correct horse battery staple".to_string(),
        output_dir: extract_dir.clone(),
        force: false,
    })
    .expect("decompress failed");

    assert_eq!(result.output, extract_dir.join("payload"));
    assert_tree_matches(&extract_dir.join("payload"), &expected);
}

#[test]
fn roundtrip_single_large_volume() {
    let work = tempdir().unwrap();
    let source = work.path().join("data");
    fs::create_dir_all(&source).unwrap();
    let expected = build_fixture(&source);
    let out_dir = work.path().join("out");

    compress(&CompressOptions {
        source: source.clone(),
        password: "pw".to_string(),
        volume_size: 1024 * 1024 * 1024, // 1 GiB => everything in one volume
        output_dir: out_dir.clone(),
        algorithm: Algorithm::Zstd,
        level: None,
        armor: false,
    })
    .unwrap();

    // Decompress by pointing at the first volume explicitly.
    let extract_dir = work.path().join("extract");
    decompress(&DecompressOptions {
        archive: out_dir.join("data.flk.001"),
        password: "pw".to_string(),
        output_dir: extract_dir.clone(),
        force: false,
    })
    .unwrap();

    assert_tree_matches(&extract_dir.join("data"), &expected);
}

#[test]
fn wrong_password_is_rejected() {
    let work = tempdir().unwrap();
    let source = work.path().join("secret");
    fs::create_dir_all(&source).unwrap();
    build_fixture(&source);
    let out_dir = work.path().join("out");

    compress(&CompressOptions {
        source: source.clone(),
        password: "right".to_string(),
        volume_size: 8 * 1024,
        output_dir: out_dir.clone(),
        algorithm: Algorithm::Zstd,
        level: None,
        armor: false,
    })
    .unwrap();

    let extract_dir = work.path().join("extract");
    let err = decompress(&DecompressOptions {
        archive: out_dir.join("secret.flk"),
        password: "wrong".to_string(),
        output_dir: extract_dir,
        force: false,
    });
    assert!(err.is_err(), "decompression with wrong password must fail");
}

#[test]
fn refuses_to_overwrite_without_force() {
    let work = tempdir().unwrap();
    let source = work.path().join("docs");
    fs::create_dir_all(&source).unwrap();
    build_fixture(&source);
    let out_dir = work.path().join("out");

    compress(&CompressOptions {
        source: source.clone(),
        password: "pw".to_string(),
        volume_size: 64 * 1024,
        output_dir: out_dir.clone(),
        algorithm: Algorithm::Zstd,
        level: None,
        armor: false,
    })
    .unwrap();

    let extract_dir = work.path().join("extract");
    // First extraction succeeds.
    decompress(&DecompressOptions {
        archive: out_dir.join("docs.flk"),
        password: "pw".to_string(),
        output_dir: extract_dir.clone(),
        force: false,
    })
    .unwrap();
    // Second without force must refuse.
    let err = decompress(&DecompressOptions {
        archive: out_dir.join("docs.flk"),
        password: "pw".to_string(),
        output_dir: extract_dir.clone(),
        force: false,
    });
    assert!(err.is_err(), "should refuse to overwrite existing folder");
    // With force it succeeds.
    decompress(&DecompressOptions {
        archive: out_dir.join("docs.flk"),
        password: "pw".to_string(),
        output_dir: extract_dir,
        force: true,
    })
    .unwrap();
}

#[test]
fn skips_own_output_volumes_when_packing_in_place() {
    let work = tempdir().unwrap();
    let source = work.path().join("inplace");
    fs::create_dir_all(&source).unwrap();
    fs::write(source.join("keep.txt"), b"keep me").unwrap();

    // A stale volume from a previous run, named like our own output.
    fs::write(source.join("inplace.flk.001"), b"stale junk").unwrap();

    // Output goes into the very directory we are packing.
    compress(&CompressOptions {
        source: source.clone(),
        password: "pw".to_string(),
        volume_size: 4 * 1024,
        output_dir: source.clone(),
        algorithm: Algorithm::Zstd,
        level: None,
        armor: false,
    })
    .unwrap();

    let extract_dir = work.path().join("extract");
    decompress(&DecompressOptions {
        archive: source.join("inplace.flk"),
        password: "pw".to_string(),
        output_dir: extract_dir.clone(),
        force: false,
    })
    .unwrap();

    let extracted = extract_dir.join("inplace");
    assert_eq!(fs::read(extracted.join("keep.txt")).unwrap(), b"keep me");
    assert!(
        !extracted.join("inplace.flk.001").exists(),
        "stale output volume must not be archived"
    );
}

#[test]
fn force_replaces_stale_files() {
    let work = tempdir().unwrap();
    let source = work.path().join("docs");
    fs::create_dir_all(&source).unwrap();
    build_fixture(&source);
    let out_dir = work.path().join("out");

    compress(&CompressOptions {
        source: source.clone(),
        password: "pw".to_string(),
        volume_size: 64 * 1024,
        output_dir: out_dir.clone(),
        algorithm: Algorithm::Zstd,
        level: None,
        armor: false,
    })
    .unwrap();

    let extract_dir = work.path().join("extract");
    decompress(&DecompressOptions {
        archive: out_dir.join("docs.flk"),
        password: "pw".to_string(),
        output_dir: extract_dir.clone(),
        force: false,
    })
    .unwrap();

    // Plant a stale file that is NOT part of the archive.
    let stale = extract_dir.join("docs").join("stale_secret.txt");
    fs::write(&stale, b"left over").unwrap();

    // A --force re-extract must produce a clean folder without the stale file.
    decompress(&DecompressOptions {
        archive: out_dir.join("docs.flk"),
        password: "pw".to_string(),
        output_dir: extract_dir.clone(),
        force: true,
    })
    .unwrap();

    assert!(!stale.exists(), "--force must not leave stale files behind");
    assert_eq!(
        fs::read(extract_dir.join("docs").join("readme.txt")).unwrap(),
        b"hello foldlock\n"
    );
}

#[test]
fn failed_force_preserves_existing_folder() {
    let work = tempdir().unwrap();
    let source = work.path().join("docs");
    fs::create_dir_all(&source).unwrap();
    build_fixture(&source);
    let out_dir = work.path().join("out");

    compress(&CompressOptions {
        source,
        password: "right".to_string(),
        volume_size: 64 * 1024,
        output_dir: out_dir.clone(),
        algorithm: Algorithm::Zstd,
        level: None,
        armor: false,
    })
    .unwrap();

    let extract_dir = work.path().join("extract");
    decompress(&DecompressOptions {
        archive: out_dir.join("docs.flk"),
        password: "right".to_string(),
        output_dir: extract_dir.clone(),
        force: false,
    })
    .unwrap();

    // Plant a marker in the already-extracted folder.
    let marker = extract_dir.join("docs").join("marker.txt");
    fs::write(&marker, b"precious").unwrap();

    // A --force extract with the WRONG password must fail AND leave the
    // existing folder untouched (staged-swap => no data loss on failure).
    let err = decompress(&DecompressOptions {
        archive: out_dir.join("docs.flk"),
        password: "wrong".to_string(),
        output_dir: extract_dir.clone(),
        force: true,
    });
    assert!(err.is_err(), "wrong password must fail even with --force");
    assert_eq!(
        fs::read(&marker).unwrap(),
        b"precious",
        "a failed --force must not destroy the existing folder"
    );
}

#[test]
fn empty_password_is_rejected() {
    let work = tempdir().unwrap();
    let source = work.path().join("data");
    fs::create_dir_all(&source).unwrap();
    build_fixture(&source);

    let err = compress(&CompressOptions {
        source,
        password: String::new(),
        volume_size: 64 * 1024,
        output_dir: work.path().join("out"),
        algorithm: Algorithm::Zstd,
        level: None,
        armor: false,
    });
    assert!(err.is_err(), "empty password must be rejected");
}

#[test]
fn missing_interior_volume_is_detected() {
    let work = tempdir().unwrap();
    let source = work.path().join("payload");
    fs::create_dir_all(&source).unwrap();
    build_fixture(&source);
    let out_dir = work.path().join("out");

    let summary = compress(&CompressOptions {
        source,
        password: "pw".to_string(),
        volume_size: 4 * 1024,
        output_dir: out_dir.clone(),
        algorithm: Algorithm::Zstd,
        level: None,
        armor: false,
    })
    .unwrap();
    assert!(summary.volumes.len() >= 3);

    // Delete an interior volume to create a gap.
    fs::remove_file(out_dir.join("payload.flk.002")).unwrap();

    let err = decompress(&DecompressOptions {
        archive: out_dir.join("payload.flk"),
        password: "pw".to_string(),
        output_dir: work.path().join("extract"),
        force: false,
    });
    let msg = format!("{:#}", err.unwrap_err());
    assert!(
        msg.contains("missing volume"),
        "interior gap should be reported clearly, got: {msg}"
    );
}

#[test]
fn roundtrip_xz_backend() {
    let work = tempdir().unwrap();
    let source = work.path().join("payload");
    fs::create_dir_all(&source).unwrap();
    let expected = build_fixture(&source);
    let out_dir = work.path().join("out");

    // Compress with the xz backend; tiny volumes force mid-block splits.
    let summary = compress(&CompressOptions {
        source: source.clone(),
        password: "pw".to_string(),
        volume_size: 4 * 1024,
        output_dir: out_dir.clone(),
        algorithm: Algorithm::Xz,
        level: None,
        armor: false,
    })
    .expect("xz compress failed");
    assert!(summary.volumes.len() > 1, "expected several volumes");

    // Decompress needs no algorithm flag — the backend is read from the header.
    let extract_dir = work.path().join("extract");
    decompress(&DecompressOptions {
        archive: out_dir.join("payload.flk"),
        password: "pw".to_string(),
        output_dir: extract_dir.clone(),
        force: false,
    })
    .expect("xz decompress failed");

    assert_tree_matches(&extract_dir.join("payload"), &expected);
}

#[test]
fn roundtrip_zstd_ultra_level() {
    let work = tempdir().unwrap();
    let source = work.path().join("payload");
    fs::create_dir_all(&source).unwrap();
    let expected = build_fixture(&source);
    let out_dir = work.path().join("out");

    // Level 22 exercises the ultra path (wide window + long-distance matching),
    // which the decoder must accept via its raised window_log_max.
    compress(&CompressOptions {
        source: source.clone(),
        password: "pw".to_string(),
        volume_size: 1024 * 1024,
        output_dir: out_dir.clone(),
        algorithm: Algorithm::Zstd,
        level: Some(22),
        armor: false,
    })
    .expect("zstd ultra compress failed");

    let extract_dir = work.path().join("extract");
    decompress(&DecompressOptions {
        archive: out_dir.join("payload.flk"),
        password: "pw".to_string(),
        output_dir: extract_dir.clone(),
        force: false,
    })
    .expect("zstd ultra decompress failed");

    assert_tree_matches(&extract_dir.join("payload"), &expected);
}

/// Compress with `--armor`, then decompress by pointing at the text file — the
/// kind must be detected from its content, with no size or algorithm argument.
#[test]
fn roundtrip_armor_autodetected() {
    let work = tempdir().unwrap();
    let source = work.path().join("notes");
    fs::create_dir_all(&source).unwrap();
    let expected = build_fixture(&source);
    let out_dir = work.path().join("out");

    let summary = compress(&CompressOptions {
        source: source.clone(),
        password: "pw".to_string(),
        volume_size: u64::MAX, // ignored under armor
        output_dir: out_dir.clone(),
        algorithm: Algorithm::Zstd,
        level: None,
        armor: true,
    })
    .expect("armor compress failed");

    assert!(summary.armored, "summary should report an armored output");
    assert_eq!(summary.volumes.len(), 1, "armor writes exactly one file");
    let armored = summary.volumes[0].clone();
    assert_eq!(armored.extension().and_then(|e| e.to_str()), Some("txt"));

    // The file must be an opaque run of base64 characters: no markers, no
    // envelope, nothing readable — only the alphabet (and it is a single line).
    let text = fs::read(&armored).unwrap();
    assert!(!text.is_empty());
    assert!(
        text.iter()
            .all(|&b| { b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' }),
        "armored file must contain only base64 characters (no markers)"
    );
    assert!(
        !text.contains(&b'\n'),
        "armored output must be a single line"
    );

    let extract_dir = work.path().join("extract");
    let result = decompress(&DecompressOptions {
        archive: armored,
        password: "pw".to_string(),
        output_dir: extract_dir.clone(),
        force: false,
    })
    .expect("armor decompress failed");

    assert_eq!(result.source, SourceKind::Armor);
    assert_tree_matches(&extract_dir.join("notes"), &expected);
}

/// A messy clipboard round-trip — a BOM, CRLF endings, injected blank lines and
/// spaces, and a completely different file name — must still decode and extract.
#[test]
fn armor_survives_a_messy_paste() {
    let work = tempdir().unwrap();
    let source = work.path().join("notes");
    fs::create_dir_all(&source).unwrap();
    let expected = build_fixture(&source);
    let out_dir = work.path().join("out");

    compress(&CompressOptions {
        source: source.clone(),
        password: "pw".to_string(),
        volume_size: u64::MAX,
        output_dir: out_dir.clone(),
        algorithm: Algorithm::Zstd,
        level: None,
        armor: true,
    })
    .expect("armor compress failed");

    let clean = fs::read(out_dir.join("notes.flk.txt")).unwrap();
    // Reflow it the way an editor might after a paste: a BOM, then wrapped lines
    // with CRLF endings and some stray indentation.
    let mut messy = vec![0xEF, 0xBB, 0xBF];
    for (i, &b) in clean.iter().enumerate() {
        messy.push(b);
        if i % 40 == 39 {
            messy.extend_from_slice(b"\r\n   ");
        }
    }
    messy.extend_from_slice(b"\r\n");
    // Save under an arbitrary name the user might have chosen (e.g. "one").
    let pasted = work.path().join("one");
    fs::write(&pasted, &messy).unwrap();

    let extract_dir = work.path().join("extract");
    let result = decompress(&DecompressOptions {
        archive: pasted,
        password: "pw".to_string(),
        output_dir: extract_dir.clone(),
        force: false,
    })
    .expect("messy armored paste should still decompress");

    assert_eq!(result.source, SourceKind::Armor);
    assert_tree_matches(&extract_dir.join("notes"), &expected);
}

/// A single altered character in the armored body must be caught by the AEAD
/// (there is no separate checksum) rather than yielding corrupt output.
#[test]
fn armor_corruption_is_rejected() {
    let work = tempdir().unwrap();
    let source = work.path().join("notes");
    fs::create_dir_all(&source).unwrap();
    build_fixture(&source);
    let out_dir = work.path().join("out");

    compress(&CompressOptions {
        source: source.clone(),
        password: "pw".to_string(),
        volume_size: u64::MAX,
        output_dir: out_dir.clone(),
        algorithm: Algorithm::Zstd,
        level: None,
        armor: true,
    })
    .expect("armor compress failed");

    let mut text = fs::read(out_dir.join("notes.flk.txt")).unwrap();
    // Flip a character well inside the body (past the header) to hit ciphertext.
    let mid = text.len() / 2;
    text[mid] = if text[mid] == b'A' { b'B' } else { b'A' };
    let corrupted = work.path().join("corrupted");
    fs::write(&corrupted, &text).unwrap();

    let err = decompress(&DecompressOptions {
        archive: corrupted,
        password: "pw".to_string(),
        output_dir: work.path().join("extract"),
        force: false,
    });
    assert!(err.is_err(), "corrupted armored text must be rejected");
}

/// The armored blob must carry no foldlock fingerprint: no frame delimiters, no
/// plaintext magic, no leaked folder name, and no fixed "shoulders" shared by
/// every blob. Without the password it is indistinguishable from random base64.
#[test]
fn armored_blob_is_unmarked_and_hides_metadata() {
    let work = tempdir().unwrap();
    // A distinctive folder name that must NOT surface anywhere in the output.
    let source = work.path().join("top_secret_dossier");
    fs::create_dir_all(&source).unwrap();
    build_fixture(&source);
    let out_dir = work.path().join("out");

    let armor_once = |dir: &std::path::Path| -> Vec<u8> {
        compress(&CompressOptions {
            source: source.clone(),
            password: "pw".to_string(),
            volume_size: u64::MAX,
            output_dir: dir.to_path_buf(),
            algorithm: Algorithm::Zstd,
            level: None,
            armor: true,
        })
        .expect("armor compress failed");
        fs::read(dir.join("top_secret_dossier.flk.txt")).unwrap()
    };

    let blob = armor_once(&out_dir);

    // No legacy frame delimiters, and no base64 of the "FLK1" magic ("RkxLMQ"),
    // which every old-format blob began with.
    let text = String::from_utf8(blob.clone()).unwrap();
    for marker in ["o3Qv9Xz1Lp7Rk2Bf", "e8Wn4Yc6Hs0Jd5Tg", "RkxLMQ"] {
        assert!(!text.contains(marker), "blob leaks the marker {marker:?}");
    }
    // The decoded stream must NOT begin with the plaintext magic — it moved
    // inside the ciphertext — and the folder name must not appear in the clear.
    let decoded = base64_decode(&blob);
    assert!(
        !decoded.starts_with(b"FLK1"),
        "magic must not be in the clear"
    );
    assert!(
        !contains(&decoded, b"top_secret_dossier"),
        "folder name must not leak in plaintext"
    );

    // A second run of the *same* source and password must share no fixed prefix:
    // the random salt leads, so there are no constant shoulders to fingerprint.
    let out_dir2 = work.path().join("out2");
    let blob2 = armor_once(&out_dir2);
    assert_ne!(blob, blob2, "two blobs must differ (random salt/nonce)");
    let common = blob.iter().zip(&blob2).take_while(|(a, b)| a == b).count();
    assert!(
        common < 8,
        "blobs share a {common}-char prefix — looks like a fixed signature"
    );

    // And it still round-trips.
    let extract_dir = work.path().join("extract");
    decompress(&DecompressOptions {
        archive: out_dir.join("top_secret_dossier.flk.txt"),
        password: "pw".to_string(),
        output_dir: extract_dir.clone(),
        force: false,
    })
    .expect("armor decompress failed");
    assert!(extract_dir.join("top_secret_dossier").is_dir());
}

/// True if `hay` contains the contiguous byte sequence `needle`.
fn contains(hay: &[u8], needle: &[u8]) -> bool {
    needle.len() <= hay.len() && hay.windows(needle.len()).any(|w| w == needle)
}

/// Minimal standard-alphabet base64 decoder for the tests, tolerant of `=`
/// padding. Sufficient to inspect the decoded header of an armored blob.
fn base64_decode(input: &[u8]) -> Vec<u8> {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut table = [0xFFu8; 256];
    for (i, &c) in ALPHABET.iter().enumerate() {
        table[c as usize] = i as u8;
    }
    let sextets: Vec<u8> = input
        .iter()
        .filter_map(|&b| (table[b as usize] != 0xFF).then_some(table[b as usize]))
        .collect();
    let mut out = Vec::with_capacity(sextets.len() / 4 * 3);
    for quad in sextets.chunks(4) {
        match quad {
            [a, b, c, d] => {
                out.push((a << 2) | (b >> 4));
                out.push((b << 4) | (c >> 2));
                out.push((c << 6) | d);
            }
            [a, b, c] => {
                out.push((a << 2) | (b >> 4));
                out.push((b << 4) | (c >> 2));
            }
            [a, b] => out.push((a << 2) | (b >> 4)),
            _ => {}
        }
    }
    out
}

/// A plain text file that is not an archive must not be mistaken for armor; it
/// falls through to the binary path and fails cleanly.
#[test]
fn unrelated_text_file_is_not_armor() {
    let work = tempdir().unwrap();
    let note = work.path().join("shopping-list.txt");
    fs::write(&note, b"milk, eggs, bread\n").unwrap();

    let err = decompress(&DecompressOptions {
        archive: note,
        password: "pw".to_string(),
        output_dir: work.path().join("extract"),
        force: false,
    });
    assert!(
        err.is_err(),
        "an unrelated file must not decode as an archive"
    );
}
