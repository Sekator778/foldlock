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
    foldlock compress   <folder> <password> --armor
    foldlock decompress <archive> [password]

COMMANDS:
    compress     Pack <folder>, encrypt with <password>, and split into
                 <size_MiB>-MiB volumes named <folder>.flk.001, .002, …
                 With --armor, write one copy-pasteable text file instead
                 (<folder>.flk.txt) and take no size argument.
    decompress   Reassemble, decrypt, and extract an <archive>. <archive> is the
                 base name (photos.flk), any volume (photos.flk.001), or an
                 armored text file — the kind is detected from its content. The
                 original folder name and volume size are recovered from the
                 archive, so no size argument is needed.

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
        --armor            Write a single copy-pasteable base64 text file instead
                           of binary volumes (compress only; takes no size arg).
                           decompress detects an armored file automatically.
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
    foldlock compress ./notes s3cret --armor       # one base64 text blob to paste
    foldlock decompress ./photos.flk s3cret
    foldlock decompress ./photos.flk.001 -         # prompt for the password
    foldlock decompress ./notes.flk.txt s3cret     # armored file, auto-detected
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
    let mut armor = false;
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
            "--armor" => armor = true,
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
            run_compress(&positionals, algo.as_deref(), level.as_deref(), armor)
        }
        "decompress" => {
            if algo.is_some() || level.is_some() || armor {
                bail!("--algo/--level/--armor are only valid for 'compress'");
            }
            run_decompress(&positionals, force)
        }
        other => bail!("unknown command '{other}' (try 'foldlock --help')"),
    }
}

fn run_compress(
    positionals: &[String],
    algo: Option<&str>,
    level: Option<&str>,
    armor: bool,
) -> Result<()> {
    // Armor writes a single text file, so it takes no volume-size argument.
    let (folder, password_arg, size_arg) = if armor {
        match positionals {
            [f, p] => (f, p, None),
            _ => bail!(
                "compress --armor expects: <folder> <password> (no size — output is one text file)"
            ),
        }
    } else {
        match positionals {
            [f, p, s] => (f, p, Some(s)),
            _ => bail!("compress expects: <folder> <password> <size_MiB> (try 'foldlock --help')"),
        }
    };
    let source = PathBuf::from(folder);
    if !source.exists() {
        bail!("source '{}' does not exist", source.display());
    }
    let password = resolve_password(Some(password_arg), true)?;
    let volume_size = match size_arg {
        Some(s) => {
            let size_mib: u64 = s
                .parse()
                .with_context(|| format!("invalid size '{s}' (expected a number of MiB)"))?;
            if size_mib == 0 {
                bail!("volume size must be at least 1 MiB");
            }
            size_mib
                .checked_mul(1024 * 1024)
                .context("volume size is too large")?
        }
        // Armor ignores the volume size; a huge cap keeps everything in one blob.
        None => u64::MAX,
    };

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
        armor,
    };
    let summary = compress(&opts)?;
    report_compress(&summary);
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

/// Print a single concise confirmation line — the output location and nothing
/// more (no per-file dump, sizes, or thread counts).
fn report_compress(summary: &CompressSummary) {
    if summary.armored {
        println!("Created {}", summary.volumes[0].display());
    } else {
        println!("Created {} volume(s)", summary.volumes.len());
    }
}

fn report_decompress(summary: &DecompressSummary) {
    println!("Extracted {}", summary.output.display());
}
