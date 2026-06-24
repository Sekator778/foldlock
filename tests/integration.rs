//! End-to-end tests for the foldlock library API.
//!
//! These call `compress`/`decompress` directly (no process spawn), so they work
//! regardless of the binary's `panic = "abort"` profile.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use foldlock::{compress, decompress, CompressOptions, DecompressOptions};
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
