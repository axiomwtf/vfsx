use std::fs::{self, DirBuilder, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};

pub use crate::format::KeyPair;
use crate::format::ArchiveReader;
use crate::hash::Blake3Hash;

/// Metadata stored in the key export archive
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyMetadata {
    pub algorithm: String,
    pub created_timestamp: u64,
    pub key_id: String,
    pub owner: String,
}

/// Manages key storage in ~/.config/vfsx/keys/
pub struct KeyStorage {
    keys_dir: PathBuf,
}

impl KeyStorage {
    pub fn new() -> Result<Self> {
        let config_dir = dirs::config_dir().ok_or_else(|| anyhow!("Could not determine config directory"))?;
        Ok(Self { keys_dir: config_dir.join("vfsx").join("keys") })
    }

    pub fn with_path(path: PathBuf) -> Self {
        Self { keys_dir: path }
    }

    pub fn keys_dir(&self) -> &Path {
        &self.keys_dir
    }

    fn ensure_dir(&self, dir: &Path) -> Result<()> {
        DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("Failed to create {}", dir.display()))
    }

    pub fn pubkey_path(&self) -> PathBuf {
        self.keys_dir.join("identity.pub")
    }

    pub fn privkey_path(&self) -> PathBuf {
        self.keys_dir.join("identity.priv")
    }

    /// Imported public keys, one `<key_id>.pub` file each.
    pub fn trusted_dir(&self) -> PathBuf {
        self.keys_dir.join("trusted")
    }

    pub fn has_keypair(&self) -> bool {
        self.privkey_path().exists()
    }

    /// Generate a new keypair and save it. The private key is created with
    /// mode 0600, so it is never readable by others, not even briefly.
    pub fn generate_keypair(&self) -> Result<KeyPair> {
        self.ensure_dir(&self.keys_dir)?;
        let keypair = KeyPair::generate();
        let mut priv_file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(self.privkey_path())
            .context("Failed to write private key")?;
        priv_file.set_permissions(Permissions::from_mode(0o600))?;
        priv_file.write_all(&keypair.private_key_seed())?;
        fs::write(self.pubkey_path(), keypair.public_key_bytes()).context("Failed to write public key")?;
        Ok(keypair)
    }

    /// Load the keypair, generating one on first use. The public key file
    /// is rewritten from the private key if it does not match it.
    pub fn load_keypair(&self) -> Result<KeyPair> {
        let privkey_path = self.privkey_path();
        if !privkey_path.exists() {
            return self.generate_keypair();
        }
        let seed: [u8; 32] = fs::read(&privkey_path)
            .with_context(|| format!("Failed to read private key: {}", privkey_path.display()))?
            .try_into()
            .map_err(|b: Vec<u8>| anyhow!("Invalid private key length: expected 32 bytes, got {}", b.len()))?;
        let keypair = KeyPair::from_seed(&seed);
        if fs::read(self.pubkey_path()).ok().as_deref() != Some(&keypair.public_key_bytes()[..]) {
            fs::write(self.pubkey_path(), keypair.public_key_bytes()).context("Failed to write public key")?;
        }
        Ok(keypair)
    }

    /// Export the public key as a key archive signed by the key itself.
    pub fn export_key(&self, output_path: &Path, owner: Option<String>) -> Result<()> {
        let keypair = self.load_keypair()?;
        let metadata = KeyMetadata {
            algorithm: "Ed25519".to_string(),
            created_timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            key_id: keypair.public_key_hash().to_hex(),
            owner: owner.unwrap_or_else(whoami::username),
        };

        let temp_dir = tempfile::tempdir()?;
        fs::write(temp_dir.path().join("pubkey.bin"), keypair.public_key_bytes())?;
        fs::write(temp_dir.path().join("metadata.json"), serde_json::to_vec_pretty(&metadata)?)?;
        crate::format::ArchiveWriter::new(
            temp_dir.path().to_path_buf(),
            output_path.to_path_buf(),
            crate::compression::CompressionType::Zstd,
            3,
            keypair,
        )
        .write()
    }

    /// Import a key archive into the trusted keys.
    pub fn import_key(&self, archive_path: &Path) -> Result<([u8; 32], KeyMetadata)> {
        let (pubkey, metadata) = read_key_archive(archive_path)?;
        let dir = self.trusted_dir();
        self.ensure_dir(&dir)?;
        fs::write(dir.join(format!("{}.pub", metadata.key_id)), pubkey)
            .context("Failed to write imported public key")?;
        Ok((pubkey, metadata))
    }

    /// The public key whose blake3 hash is `key_hash`: this machine's own
    /// key or an imported one.
    pub fn find_key(&self, key_hash: &[u8; 32]) -> Option<[u8; 32]> {
        let candidates = [
            self.pubkey_path(),
            self.trusted_dir().join(format!("{}.pub", hex::encode(key_hash))),
        ];
        candidates.iter().find_map(|path| {
            let key: [u8; 32] = fs::read(path).ok()?.try_into().ok()?;
            (Blake3Hash::new(&key).as_bytes() == key_hash).then_some(key)
        })
    }
}

/// Read a key archive: its public key and metadata. The archive has to be
/// signed by the key it carries.
pub fn read_key_archive(archive_path: &Path) -> Result<([u8; 32], KeyMetadata)> {
    let mut reader = ArchiveReader::open(archive_path)?;
    let entry = |name: &str| {
        reader
            .manifest
            .entries
            .iter()
            .find(|e| e.path == name && e.is_file())
            .cloned()
            .with_context(|| format!("Not a key archive: no {} in {}", name, archive_path.display()))
    };
    let pubkey_entry = entry("pubkey.bin")?;
    let metadata_entry = entry("metadata.json")?;

    let pubkey: [u8; 32] = reader
        .file_data(&pubkey_entry)?
        .try_into()
        .map_err(|b: Vec<u8>| anyhow!("Invalid public key length: expected 32 bytes, got {}", b.len()))?;
    let metadata: KeyMetadata =
        serde_json::from_slice(&reader.file_data(&metadata_entry)?).context("Failed to parse metadata.json")?;

    if metadata.algorithm != "Ed25519" {
        bail!("Unsupported algorithm: {}", metadata.algorithm);
    }
    if Blake3Hash::new(&pubkey).to_hex() != metadata.key_id {
        bail!("Key ID mismatch: metadata key_id doesn't match public key hash");
    }
    reader
        .verify_signature(&pubkey)
        .context("Key archive is not signed by the key it carries")?;
    Ok((pubkey, metadata))
}
