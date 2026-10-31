use crate::compression::CompressionType;
use crate::format::{ArchiveReader, ArchiveWriter};
use crate::keys::{read_key_archive, KeyStorage};
use anyhow::{anyhow, bail, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::{Path, PathBuf};

#[derive(Parser, Debug)]
#[command(name = "vfsx", version, about = "Signed, content-addressed virtual filesystem archives", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Create a new vfsx archive from a directory
    Create(CreateArgs),

    /// Extract a vfsx archive
    Extract(ExtractArgs),

    /// List contents of a vfsx archive
    List(ListArgs),

    /// Verify a vfsx archive signature and contents
    Verify(VerifyArgs),

    /// Key management commands
    #[command(subcommand)]
    Key(KeyCommands),
}

#[derive(Parser, Debug, Clone)]
pub struct CreateArgs {
    /// Source directory to archive
    #[arg(value_name = "DIR", default_value = ".")]
    pub source: PathBuf,

    /// Output archive path (auto-derived if omitted)
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Compression algorithm
    #[arg(short, long, value_enum, default_value_t = CompressionArg::Zstd)]
    pub compression: CompressionArg,

    /// Compression level (1-22 for zstd, 1-9 for xz/gzip)
    #[arg(short, long, value_name = "LEVEL")]
    pub level: Option<i32>,

    /// Base archive: files it already holds are stored as references
    #[arg(long, value_name = "BASE")]
    pub base: Option<PathBuf>,

    /// Archive what symlinks point to instead of the symlinks
    #[arg(long)]
    pub follow_links: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct ExtractArgs {
    /// Archive to extract
    #[arg(value_name = "ARCHIVE")]
    pub archive: PathBuf,

    /// Output directory
    #[arg(short = 'C', long = "directory", value_name = "DIR", default_value = ".")]
    pub output: PathBuf,

    /// Overwrite existing files
    #[arg(short, long)]
    pub force: bool,

    /// Base archive of a delta archive
    #[arg(long, value_name = "BASE")]
    pub base: Option<PathBuf>,

    /// Public key archive to verify against before extracting
    #[arg(short, long, value_name = "KEY")]
    pub key: Option<PathBuf>,
}

#[derive(Parser, Debug, Clone)]
pub struct ListArgs {
    /// Archive to list
    #[arg(value_name = "ARCHIVE")]
    pub archive: PathBuf,

    /// Output as JSON
    #[arg(long)]
    pub json: bool,

    /// Show detailed info (sizes, hashes, xattrs)
    #[arg(short, long)]
    pub detail: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct VerifyArgs {
    /// Archive to verify
    #[arg(value_name = "ARCHIVE")]
    pub archive: PathBuf,

    /// Public key archive (default: your own or an imported key matching the archive)
    #[arg(short, long, value_name = "KEY")]
    pub key: Option<PathBuf>,
}

#[derive(Subcommand, Debug, Clone)]
pub enum KeyCommands {
    /// Generate a new keypair
    Gen {
        /// Force regenerate even if keys exist
        #[arg(long)]
        force: bool,
    },

    /// Export public key as a vfsx archive
    Export {
        /// Output path for key archive (default: pubkey.vfsx)
        #[arg(short, long, value_name = "FILE", default_value = "pubkey.vfsx")]
        output: PathBuf,

        /// Owner name for metadata
        #[arg(long, value_name = "NAME")]
        owner: Option<String>,
    },

    /// Import a public key so archives signed with it verify without -k
    Import {
        /// Key archive to import
        #[arg(value_name = "KEY")]
        key: PathBuf,
    },

    /// Show public key info
    Show,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum CompressionArg {
    Zstd,
    Xz,
    Gzip,
}

impl From<CompressionArg> for CompressionType {
    fn from(arg: CompressionArg) -> Self {
        match arg {
            CompressionArg::Zstd => CompressionType::Zstd,
            CompressionArg::Xz => CompressionType::Xz,
            CompressionArg::Gzip => CompressionType::Gzip,
        }
    }
}

/// `dir.vfsx.tar.<ext>` for an output name given with or without suffixes.
fn archive_path(path: &Path, ext: &str) -> PathBuf {
    let suffix = format!(".vfsx.tar.{}", ext);
    let name = path.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if name.ends_with(&suffix) {
        return path.to_path_buf();
    }
    let mut stem = name.as_str();
    while let Some(s) = [".zst", ".xz", ".gz", ".tar", ".vfsx"]
        .iter()
        .find_map(|sfx| stem.strip_suffix(sfx))
    {
        stem = s;
    }
    let stem = if stem.is_empty() { "archive" } else { stem };
    path.with_file_name(format!("{}{}", stem, suffix))
}

/// The key to check an archive with: the key archive given, else this
/// machine's own key or an imported key matching the archive's key id.
fn resolve_key(key: Option<&Path>, reader: &ArchiveReader) -> Result<Option<[u8; 32]>> {
    match key {
        Some(path) => Ok(Some(read_key_archive(path)?.0)),
        None => Ok(KeyStorage::new()?.find_key(&reader.header.public_key_hash)),
    }
}

impl Cli {
    pub fn run(self) -> Result<()> {
        match self.command {
            Commands::Create(args) => cmd_create(args),
            Commands::Extract(args) => cmd_extract(args),
            Commands::List(args) => cmd_list(args),
            Commands::Verify(args) => cmd_verify(args),
            Commands::Key(cmd) => cmd_key(cmd),
        }
    }
}

fn cmd_create(args: CreateArgs) -> Result<()> {
    if !args.source.is_dir() {
        bail!("Source is not a directory: {}", args.source.display());
    }

    let compression_type: CompressionType = args.compression.into();
    let level = args.level.unwrap_or(compression_type.default_level());
    let ext = compression_type.extension();

    let output = match &args.output {
        Some(p) => archive_path(p, ext),
        None => {
            let name = args
                .source
                .canonicalize()?
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_else(|| "archive".to_string());
            archive_path(&PathBuf::from(name), ext)
        }
    };

    let storage = KeyStorage::new()?;
    if !storage.has_keypair() {
        println!("No keypair found, generating one at {}", storage.keys_dir().display());
    }
    let keypair = storage.load_keypair()?;

    let mut writer = ArchiveWriter::new(args.source.clone(), output.clone(), compression_type, level, keypair)
        .follow_links(args.follow_links);
    if let Some(base) = &args.base {
        writer = writer.with_base(base)?;
    }
    writer.write()?;

    println!("Created {}", output.display());
    Ok(())
}

fn cmd_extract(args: ExtractArgs) -> Result<()> {
    let mut reader = ArchiveReader::open(&args.archive)?;
    match resolve_key(args.key.as_deref(), &reader)? {
        Some(pubkey) => reader.verify_signature(&pubkey)?,
        None => eprintln!(
            "warning: signature not checked: key {} is not imported (pass -k KEY)",
            &hex::encode(reader.header.public_key_hash)[..16]
        ),
    }

    let mut base = args.base.as_ref().map(ArchiveReader::open).transpose()?;
    let warnings = reader.extract_to(&args.output, args.force, base.as_mut())?;
    for w in &warnings {
        eprintln!("warning: {}", w);
    }
    println!("Extracted to {}", args.output.display());
    Ok(())
}

fn cmd_list(args: ListArgs) -> Result<()> {
    let reader = ArchiveReader::open(&args.archive)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&reader.manifest)?);
        return Ok(());
    }

    println!("Archive: {}", args.archive.display());
    println!("Version: {}", reader.header.version);
    println!("Created: {}", reader.manifest.created_at);
    println!("Files: {}", reader.manifest.total_files);
    println!("Total size: {} bytes", reader.manifest.total_size);
    if let Some(base) = &reader.manifest.base_archive_hash {
        println!("Base: {}", base);
    }
    println!();

    for entry in &reader.manifest.entries {
        let kind = if entry.is_dir {
            "d"
        } else if entry.is_symlink {
            "l"
        } else {
            "-"
        };
        let name = match &entry.symlink_target {
            Some(target) => format!("{} -> {}", entry.path, target),
            None => entry.path.clone(),
        };
        if args.detail {
            let hash = if entry.is_file() { entry.blake3_hash.to_hex()[..16].to_string() } else { "-".repeat(16) };
            println!("{} {:o} {} {} {}", kind, entry.mode & 0o7777, entry.size, hash, name);
            for (k, v) in &entry.xattrs {
                println!("    xattr: {} = {:?}", k, v);
            }
            if entry.in_base() {
                println!("    stored in base archive");
            }
        } else {
            println!("{} {}", kind, name);
        }
    }
    Ok(())
}

fn cmd_verify(args: VerifyArgs) -> Result<()> {
    let mut reader = ArchiveReader::open(&args.archive)?;
    let pubkey = resolve_key(args.key.as_deref(), &reader)?.ok_or_else(|| {
        anyhow!(
            "Archive was signed by key {}, which is not imported: pass -k KEY or run vfsx key import",
            hex::encode(reader.header.public_key_hash)
        )
    })?;

    match crate::verify::verify_archive(&mut reader, &pubkey) {
        Ok(result) => {
            println!("\u{2713} Signature verified successfully");
            println!("  Files verified: {}", result.files_verified);
            if result.files_in_base > 0 {
                println!("  Files in base archive: {}", result.files_in_base);
            }
            Ok(())
        }
        Err(e) => {
            eprintln!("\u{2717} Verification FAILED");
            Err(e)
        }
    }
}

fn cmd_key(cmd: KeyCommands) -> Result<()> {
    let storage = KeyStorage::new()?;
    match cmd {
        KeyCommands::Gen { force } => {
            if force || !storage.has_keypair() {
                storage.generate_keypair()?;
                println!("Generated new keypair at {}", storage.keys_dir().display());
            } else {
                let keypair = storage.load_keypair()?;
                println!("Using existing keypair");
                println!("Public key hash: {}", keypair.public_key_hash());
            }
        }
        KeyCommands::Export { output, owner } => {
            storage.export_key(&output, owner)?;
            println!("Exported public key to {}", output.display());
        }
        KeyCommands::Import { key } => {
            let (_, metadata) = storage.import_key(&key)?;
            println!("Imported public key of {}", metadata.owner);
            println!("Key hash: {}", metadata.key_id);
        }
        KeyCommands::Show => {
            let keypair = storage.load_keypair()?;
            println!("Public key (hex): {}", hex::encode(keypair.public_key_bytes()));
            println!("Public key hash (blake3): {}", keypair.public_key_hash());
        }
    }
    Ok(())
}
