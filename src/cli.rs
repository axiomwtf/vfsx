use crate::compression::CompressionType;
use crate::keys::{KeyStorage, export_public_key, import_public_key};
use anyhow::{anyhow, Context, Result};
use clap::{Parser, Subcommand, ValueEnum};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "vfsx", version, about = "Virtual Filesystem Archive Tool", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,

    #[arg(global = true, short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Create a new vfsx archive from a directory
    Create(CreateArgs),

    /// Extract a vfsx archive
    Extract(ExtractArgs),

    /// List contents of a vfsx archive
    List(ListArgs),

    /// Verify a vfsx archive signature
    Verify(VerifyArgs),

    /// Key management commands
    #[command(subcommand)]
    Key(KeyCommands),

    /// Mount a vfsx archive (FUSE)
    Mount(MountArgs),
}

#[derive(Parser, Debug, Clone)]
pub struct CreateArgs {
    /// Source directory to archive
    #[arg(value_name = "DIR")]
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

    /// Base archive for incremental/delta creation
    #[arg(long, value_name = "BASE")]
    pub base: Option<PathBuf>,

    /// Follow symlinks
    #[arg(long)]
    pub follow_links: bool,

    /// Show progress
    #[arg(short, long, default_value_t = true)]
    pub progress: bool,
}

#[derive(Parser, Debug, Clone)]
pub struct ExtractArgs {
    /// Archive to extract
    #[arg(value_name = "ARCHIVE")]
    pub archive: PathBuf,

    /// Output directory
    #[arg(short, long, value_name = "DIR", default_value = ".")]
    pub output: PathBuf,

    /// Overwrite existing files
    #[arg(short, long)]
    pub force: bool,

    /// Show progress
    #[arg(short, long, default_value_t = true)]
    pub progress: bool,
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

    /// Public key archive for verification
    #[arg(short, long, value_name = "KEY")]
    pub key: PathBuf,
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
        /// Output path for key archive
        /// Output path for key archive (default: pubkey.vfsx)
        #[arg(short, long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Owner name for metadata
        #[arg(long, value_name = "NAME")]
        owner: Option<String>,
    },

    /// Import public key from a vfsx key archive
    Import {
        /// Key archive to import
        #[arg(value_name = "KEY")]
        key: PathBuf,
    },

    /// Show public key info
    Show,
}

#[derive(Parser, Debug, Clone)]
pub struct MountArgs {
    /// Archive to mount
    #[arg(value_name = "ARCHIVE")]
    pub archive: PathBuf,

    /// Mount point
    #[arg(value_name = "MOUNT_POINT")]
    pub mount_point: PathBuf,

    /// Run in foreground (don't daemonize)
    #[arg(long)]
    pub foreground: bool,

    /// Allow other users to access (requires user_allow_other in fuse.conf)
    #[arg(long)]
    pub allow_other: bool,

    /// Read-only mount
    #[arg(long, default_value_t = true)]
    pub read_only: bool,
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

impl Cli {
    pub fn run(self) -> Result<()> {
        match &self.command {
            Commands::Create(args) => self.cmd_create(args.clone()),
            Commands::Extract(args) => self.cmd_extract(args.clone()),
            Commands::List(args) => self.cmd_list(args.clone()),
            Commands::Verify(args) => self.cmd_verify(args.clone()),
            Commands::Key(cmd) => self.cmd_key(cmd.clone()),
            Commands::Mount(args) => self.cmd_mount(args.clone()),
        }
    }

    fn cmd_create(&self, args: CreateArgs) -> Result<()> {
        use crate::format::ArchiveWriter;
        use indicatif::{ProgressBar, ProgressStyle};

        if !args.source.exists() {
            return Err(anyhow!("Source directory does not exist: {}", args.source.display()));
        }
        if !args.source.is_dir() {
            return Err(anyhow!("Source is not a directory: {}", args.source.display()));
        }

        let compression_type: CompressionType = args.compression.into();
        let level = args.level.unwrap_or(match compression_type {
            CompressionType::Zstd => 3,
            CompressionType::Xz => 6,
            CompressionType::Gzip => 6,
            CompressionType::None => 0,
        });

        let pb = if args.progress {
            let pb = ProgressBar::new_spinner();
            pb.set_style(ProgressStyle::default_spinner()
                .template("{spinner:.green} [{elapsed_precise}] {msg}")
                .unwrap());
            pb.enable_steady_tick(std::time::Duration::from_millis(100));
            Some(pb)
        } else {
            None
        };

        if let Some(pb) = &pb {
            pb.set_message("Creating archive...");
        }

        let ext = match compression_type {
            CompressionType::Zstd => "zst",
            CompressionType::Xz => "xz",
            CompressionType::Gzip => "gz",
            CompressionType::None => "tar",
        };

        let output = match &args.output {
            Some(p) => {
                let expected_suffix = format!(".vfsx.tar.{}", ext);
                let p_str = p.to_string_lossy();
                if p_str.ends_with(&expected_suffix)
                    || (ext == "tar" && p_str.ends_with(".vfsx.tar"))
                {
                    p.clone()
                } else {
                    // Append the correct suffix: parent/stem.vfsx.tar.ext
                    let stem = p.file_stem()
                        .map(|s| s.to_string_lossy().into_owned())
                        .unwrap_or_else(|| p.to_string_lossy().into_owned());
                    let parent = p.parent().unwrap_or(std::path::Path::new("."));
                    if ext == "tar" {
                        parent.join(format!("{}.vfsx.tar", stem))
                    } else {
                        parent.join(format!("{}.vfsx.tar.{}", stem, ext))
                    }
                }
            }
            None => {
                let source_name = args.source
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .or_else(|| {
                        // Handle "." and relative paths — canonicalize to get the real dir name
                        args.source
                            .canonicalize()
                            .ok()
                            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
                    })
                    .unwrap_or_else(|| "archive".to_string());
                if ext == "tar" {
                    args.source.with_file_name(format!("{}.vfsx.tar", source_name))
                } else {
                    args.source.with_file_name(format!("{}.vfsx.tar.{}", source_name, ext))
                }
            }
        };

        // Auto-generate keypair if none exists
        let storage = crate::keys::KeyStorage::new()?;
        let key_existed = storage.pubkey_path().exists() && storage.privkey_path().exists();
        if !key_existed {
            if let Some(pb) = &pb {
                pb.println(format!("No keypair found, auto-generating new keypair at {}", storage.keys_dir().display()));
            } else {
                println!("No keypair found, auto-generating new keypair at {}", storage.keys_dir().display());
            }
        }
        let keypair = storage.load_keypair()?;

        let writer = ArchiveWriter::new(
            args.source.clone(),
            output.clone(),
            compression_type,
            level,
        ).with_keypair(keypair.clone());

        let mut writer = if let Some(base) = &args.base {
            writer.with_base(base)?
        } else {
            writer
        };

        writer.write()?;

        if let Some(pb) = &pb {
            pb.finish_with_message(format!("Created {}", output.display()));
        } else {
            println!("Created {}", output.display());
        }

        Ok(())
    }

    fn cmd_extract(&self, args: ExtractArgs) -> Result<()> {
        use crate::format::ArchiveReader;
        use indicatif::{ProgressBar, ProgressStyle};
        use std::fs;

        if !args.archive.exists() {
            return Err(anyhow!("Archive does not exist: {}", args.archive.display()));
        }

        fs::create_dir_all(&args.output)
            .with_context(|| format!("Failed to create output directory: {}", args.output.display()))?;

        let mut reader = ArchiveReader::open(&args.archive)?;

        let pb = if args.progress {
            let pb = ProgressBar::new(reader.manifest.total_files);
            pb.set_style(ProgressStyle::default_bar()
                .template("{spinner:.green} [{elapsed_precise}] [{bar:40.cyan/blue}] {pos}/{len} {msg}")
                .unwrap()
                .progress_chars("##-"));
            Some(pb)
        } else {
            None
        };

        if let Some(pb) = &pb {
            pb.set_message("Extracting...");
        }

        reader.extract_to(&args.output, args.force)?;

        if let Some(pb) = &pb {
            pb.finish_with_message("Extraction complete");
        } else {
            println!("Extracted to {}", args.output.display());
        }

        Ok(())
    }

    fn cmd_list(&self, args: ListArgs) -> Result<()> {
        use crate::format::ArchiveReader;

        if !args.archive.exists() {
            return Err(anyhow!("Archive does not exist: {}", args.archive.display()));
        }

        let reader = ArchiveReader::open(&args.archive)?;

        if args.json {
            println!("{}", serde_json::to_string_pretty(&reader.manifest)?);
            return Ok(());
        }

        println!("Archive: {}", args.archive.display());
        println!("Version: {}", crate::format::VERSION);
        println!("Created: {}", reader.manifest.created_at);
        println!("Files: {}", reader.manifest.total_files);
        println!("Total size: {} bytes", reader.manifest.total_size);
        if let Some(parent) = &reader.manifest.parent_hash {
            println!("Parent: {}", parent.to_hex());
        }
        println!();

        for entry in &reader.manifest.entries {
            if args.detail {
                let hash_str = entry.blake3_hash.to_hex();
                println!(
                    "{} {} {} {} {}",
                    if entry.chunk_refs.is_empty() { "d" } else { "-" },
                    entry.mode,
                    entry.size,
                    &hash_str[..16],
                    entry.path
                );
                if !entry.xattrs.is_empty() {
                    for (k, v) in &entry.xattrs {
                        println!("    xattr: {} = {:?}", k, v);
                    }
                }
                if !entry.chunk_refs.is_empty() {
                    println!("    chunks: {}", entry.chunk_refs.len());
                }
            } else {
                println!(
                    "{} {}",
                    if entry.chunk_refs.is_empty() { "d" } else { "-" },
                    entry.path
                );
            }
        }

        Ok(())
    }

    fn cmd_verify(&self, args: VerifyArgs) -> Result<()> {
        if !args.archive.exists() {
            return Err(anyhow!("Archive does not exist: {}", args.archive.display()));
        }
        if !args.key.exists() {
            return Err(anyhow!("Key archive does not exist: {}", args.key.display()));
        }

        // Load the public key from the key archive
        let public_key = import_public_key(&args.key)?;

        // Verify the embedded .hash.json: hash match + signature
        match crate::hashjson::verify_embedded_hash_json(&args.archive, &public_key) {
            Ok(()) => {
                println!("\u{2713} Archive verified: blake3 hash matches, signature valid");
            }
            Err(e) => {
                eprintln!("\u{2717} {}", e);
                return Err(e);
            }
        }

        // Verify the archive's internal signature and file hashes
        let result = crate::verify::verify_archive(&args.archive, Some(args.key.as_path()), true)?;

        if result.valid {
            println!("\u{2713} Signature verified successfully");
            println!("  Files verified: {}", result.files_verified);
            Ok(())
        } else {
            eprintln!("\u{2717} Signature verification FAILED");
            for error in &result.errors {
                eprintln!("  {}", error);
            }
            Err(anyhow!("Verification failed"))
        }
    }

    fn cmd_key(&self, cmd: KeyCommands) -> Result<()> {
        let storage = KeyStorage::new()?;

        match cmd {
            KeyCommands::Gen { force } => {
                if force {
                    storage.generate_keypair()?;
                    println!("Generated new keypair at {}", storage.keys_dir().display());
                } else {
                    let keypair = storage.load_keypair()?;
                    println!("Using existing keypair");
                    println!("Public key hash: {}", hex::encode(keypair.public_key_hash().as_bytes()));
                }
            }
            KeyCommands::Export { output, owner } => {
                let output = output.unwrap_or_else(|| {
                    let cwd = std::env::current_dir().unwrap_or_default();
                    cwd.join("pubkey.vfsx")
                });
                export_public_key(&output, owner)?;
                println!("Exported public key to {}", output.display());
            }
            KeyCommands::Import { key } => {
                let pubkey = import_public_key(&key)?;
                let hash = blake3::hash(&pubkey);
                println!("Imported public key");
                println!("Key hash: {}", hex::encode(hash.as_bytes()));
            }
            KeyCommands::Show => {
                let keypair = storage.load_keypair()?;
                let pubkey = keypair.public_key_bytes();
                let hash = keypair.public_key_hash();
                println!("Public key (hex): {}", hex::encode(pubkey));
                println!("Public key hash (blake3): {}", hash.to_hex());
            }
        }

        Ok(())
    }

    fn cmd_mount(&self, args: MountArgs) -> Result<()> {
        #[cfg(feature = "fuse")]
        {
            use crate::mount::mount_archive;
            mount_archive(&args.archive, &args.mount_point, args.foreground, args.allow_other, args.read_only)?;
        }
        #[cfg(not(feature = "fuse"))]
        {
            let _ = args;
            return Err(anyhow!("FUSE support not compiled in. Build with --features fuse"));
        }
    }
}
