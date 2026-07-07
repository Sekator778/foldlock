//! `foldlock` command-line interface.

use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{anyhow, bail, Context, Result};
use foldlock::{
    compress, decompress, Algorithm, CompressOptions, CompressSummary, DecompressOptions,
    DecompressSummary,
};

const VERSION: &str = env!("CARGO_PKG_VERSION");

const HELP: &str = "\
foldlock — compress a folder, encrypt it with a password, split it into volumes.

USAGE:
    foldlock compress   <folder> <password> <size_MiB>
    foldlock decompress <archive> [password]

COMMANDS:
    compress     Pack <folder>, encrypt with <password>, and split into
                 <size_MiB>-MiB volumes named <folder>.flk.001, .002, …
    decompress   Reassemble, decrypt, and extract a <archive> volume set.
                 <archive> is the base name (photos.flk) or any volume
                 (photos.flk.001). The original folder name and volume size
                 are recovered from the archive, so no size argument is needed.

PASSWORD:
    Pass the password as an argument, or use '-' to be prompted without echo.
    The FOLDLOCK_PASSWORD environment variable is used when no argument (or '-')
    is given. Note: a password on the command line is visible to other users via
    the process list and your shell history — prefer '-' or the env var.

OPTIONS:
    -a, --algo <zstd|xz>   Compression backend (compress only). Default: zstd —
                           fast, great ratio. 'xz' is ~9% smaller on source
                           trees but ~3x slower.
    -l, --level <n>        Compression level (compress only). zstd: 1..=22
                           (default 19); xz: 0..=9 (default 9). zstd levels
                           20..=22 enable a wider window for higher density.
        --max              Shortcut for '--algo xz' (maximum density).
    -f, --force            Overwrite the destination folder if it already exists
                           (decompress only).
    -h, --help             Print this help.
    -V, --version          Print version.

The compression backend is recorded in the archive, so decompress needs no
algorithm flag — it is detected automatically.

EXAMPLES:
    foldlock compress ./photos s3cret 100          # 100 MiB volumes, zstd
    foldlock compress ./photos - 100 --max         # maximum density (xz)
    foldlock compress ./src s3cret 100 -l 22       # zstd ultra
    foldlock compress ./photos - 100               # prompt for the password
    foldlock decompress ./photos.flk s3cret
    foldlock decompress ./photos.flk.001 -         # prompt for the password
";

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = env::args().skip(1).collect();

    if args.is_empty() {
        print!("{HELP}");
        return Ok(());
    }
    // Honor help/version as the first token, so a password equal to "-h"/"-V"
    // passed in a later position is not swallowed.
    match args[0].as_str() {
        "-h" | "--help" => {
            print!("{HELP}");
            return Ok(());
        }
        "-V" | "--version" => {
            println!("foldlock {VERSION}");
            return Ok(());
        }
        _ => {}
    }

    let command = args[0].as_str();

    // Parse the remaining tokens. A literal "--" ends option parsing, so any
    // value (even one that looks like a flag) can follow it positionally.
    let mut force = false;
    let mut algo: Option<String> = None;
    let mut level: Option<String> = None;
    let mut positionals: Vec<String> = Vec::new();
    let mut options_done = false;
    let opt_args = &args[1..];
    let mut i = 0;
    while i < opt_args.len() {
        let arg = opt_args[i].as_str();
        if options_done {
            positionals.push(arg.to_string());
            i += 1;
            continue;
        }
        match arg {
            "--" => options_done = true,
            "-f" | "--force" => force = true,
            "--max" => algo = Some("xz".to_string()),
            "-a" | "--algo" => {
                i += 1;
                algo = Some(
                    opt_args
                        .get(i)
                        .ok_or_else(|| anyhow!("--algo requires a value (zstd|xz)"))?
                        .clone(),
                );
            }
            "-l" | "--level" => {
                i += 1;
                level = Some(
                    opt_args
                        .get(i)
                        .ok_or_else(|| anyhow!("--level requires a value"))?
                        .clone(),
                );
            }
            s if s.starts_with("--algo=") => algo = Some(s["--algo=".len()..].to_string()),
            s if s.starts_with("--level=") => level = Some(s["--level=".len()..].to_string()),
            "-h" | "--help" => {
                print!("{HELP}");
                return Ok(());
            }
            "-V" | "--version" => {
                println!("foldlock {VERSION}");
                return Ok(());
            }
            // A lone "-" is the password-prompt sentinel (a positional value);
            // any other leading-dash token is an unknown option.
            s if s.starts_with('-') && s != "-" => {
                bail!("unknown option '{s}' (use '--' before values that start with '-')");
            }
            other => positionals.push(other.to_string()),
        }
        i += 1;
    }

    match command {
        "compress" => {
            if force {
                bail!("--force is only valid for 'decompress'");
            }
            run_compress(&positionals, algo.as_deref(), level.as_deref())
        }
        "decompress" => {
            if algo.is_some() || level.is_some() {
                bail!("--algo/--level are only valid for 'compress'");
            }
            run_decompress(&positionals, force)
        }
        other => bail!("unknown command '{other}' (try 'foldlock --help')"),
    }
}

fn run_compress(positionals: &[String], algo: Option<&str>, level: Option<&str>) -> Result<()> {
    if positionals.len() != 3 {
        bail!("compress expects: <folder> <password> <size_MiB> (try 'foldlock --help')");
    }
    let source = PathBuf::from(&positionals[0]);
    if !source.exists() {
        bail!("source '{}' does not exist", source.display());
    }
    let password = resolve_password(Some(&positionals[1]), true)?;
    let size_mib: u64 = positionals[2].parse().with_context(|| {
        format!(
            "invalid size '{}' (expected a number of MiB)",
            positionals[2]
        )
    })?;
    if size_mib == 0 {
        bail!("volume size must be at least 1 MiB");
    }
    let volume_size = size_mib
        .checked_mul(1024 * 1024)
        .context("volume size is too large")?;

    let algorithm: Algorithm = match algo {
        Some(s) => s.parse()?,
        None => Algorithm::default(),
    };
    let level: Option<i32> = match level {
        Some(s) => Some(
            s.parse()
                .with_context(|| format!("invalid level '{s}' (expected a number)"))?,
        ),
        None => None,
    };
    if let Some(n) = level {
        let range = algorithm.level_range();
        if !range.contains(&n) {
            bail!(
                "level {n} out of range for {} ({}..={})",
                algorithm.as_str(),
                range.start(),
                range.end()
            );
        }
    }

    let opts = CompressOptions {
        source,
        password,
        volume_size,
        output_dir: PathBuf::from("."),
        algorithm,
        level,
    };
    let summary = compress(&opts)?;
    report_compress(&summary, size_mib, algorithm, level);
    Ok(())
}

fn run_decompress(positionals: &[String], force: bool) -> Result<()> {
    if positionals.is_empty() || positionals.len() > 2 {
        bail!("decompress expects: <archive> [password] (try 'foldlock --help')");
    }
    let archive = PathBuf::from(&positionals[0]);
    let password = resolve_password(positionals.get(1).map(String::as_str), false)?;

    let opts = DecompressOptions {
        archive,
        password,
        output_dir: PathBuf::from("."),
        force,
    };
    let summary = decompress(&opts)?;
    report_decompress(&summary);
    Ok(())
}

/// Resolve the password from the argument, the environment, or a TTY prompt.
/// `confirm` asks twice when prompting interactively (used for compression).
fn resolve_password(arg: Option<&str>, confirm: bool) -> Result<String> {
    if let Some(pw) = arg {
        if pw != "-" {
            if pw.is_empty() {
                bail!("password must not be empty");
            }
            eprintln!(
                "warning: passing the password as an argument exposes it via the process \
                 list and shell history; prefer '-' (prompt) or FOLDLOCK_PASSWORD."
            );
            return Ok(pw.to_string());
        }
    }
    if let Ok(pw) = env::var("FOLDLOCK_PASSWORD") {
        if !pw.is_empty() {
            return Ok(pw);
        }
    }
    let password = rpassword::prompt_password("Password: ").context("failed to read password")?;
    if password.is_empty() {
        bail!("password must not be empty");
    }
    if confirm {
        let again =
            rpassword::prompt_password("Confirm password: ").context("failed to read password")?;
        if again != password {
            bail!("passwords do not match");
        }
    }
    Ok(password)
}

fn report_compress(
    summary: &CompressSummary,
    size_mib: u64,
    algorithm: Algorithm,
    level: Option<i32>,
) {
    let level_note = match level {
        Some(n) => format!(" level {n}"),
        None => String::new(),
    };
    println!(
        "Created {} volume(s) of up to {} MiB ({} total, {}{}, {} thread(s)):",
        summary.volumes.len(),
        size_mib,
        human_bytes(summary.total_bytes),
        algorithm.as_str(),
        level_note,
        summary.threads
    );
    for path in &summary.volumes {
        let len = path.metadata().map(|m| m.len()).unwrap_or(0);
        println!("  {}  ({})", path.display(), human_bytes(len));
    }
    if summary.skipped_symlinks > 0 {
        println!(
            "note: skipped {} symlink(s) (not supported in this version)",
            summary.skipped_symlinks
        );
    }
}

fn report_decompress(summary: &DecompressSummary) {
    println!(
        "Extracted '{}' from {} volume(s).",
        summary.output.display(),
        summary.volumes_read
    );
}

/// Format a byte count as a short human-readable string.
fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} {}", UNITS[unit])
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
