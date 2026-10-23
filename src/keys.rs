use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};

pub use crate::format::KeyPair;
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
    /// Create a new KeyStorage with default path
    pub fn new() -> Result<Self> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| anyhow!("Could not determine config directory"))?;
        let keys_dir = config_dir.join("vfsx").join("keys");
        Ok(Self { keys_dir })
    }

    /// Create a KeyStorage with a custom path
    pub fn with_path(path: PathBuf) -> Self {
        Self { keys_dir: path }
    }

    /// Get the keys directory path
    pub fn keys_dir(&self) -> &Path {
        &self.keys_dir
    }

    /// Ensure the keys directory exists
    pub fn ensure_dir(&self) -> Result<()> {
        fs::create_dir_all(&self.keys_dir)
            .with_context(|| format!("Failed to create keys directory: {}", self.keys_dir.display()))
    }

    /// Path to the public key file
    pub fn pubkey_path(&self) -> PathBuf {
        self.keys_dir.join("identity.pub")
    }

    /// Path to the private key file
    pub fn privkey_path(&self) -> PathBuf {
        self.keys_dir.join("identity.priv")
    }

    /// Generate a new keypair and save it
    pub fn generate_keypair(&self) -> Result<KeyPair> {
        self.ensure_dir()?;

        let keypair = KeyPair::generate();

        // Save public key (32 bytes raw)
        fs::write(self.pubkey_path(), keypair.public_key_bytes())
            .with_context(|| "Failed to write public key")?;

        // Save private key seed (32 bytes raw)
        fs::write(self.privkey_path(), keypair.private_key_seed())
            .with_context(|| "Failed to write private key")?;

        // Set restrictive permissions on private key
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = fs::metadata(self.privkey_path())?.permissions();
            perms.set_mode(0o600);
            fs::set_permissions(self.privkey_path(), perms)?;
        }

        Ok(keypair)
    }

    /// Load existing keypair or generate a new one
    pub fn load_keypair(&self) -> Result<KeyPair> {
        self.ensure_dir()?;

        let pubkey_path = self.pubkey_path();
        let privkey_path = self.privkey_path();

        if pubkey_path.exists() && privkey_path.exists() {
            let pubkey_bytes = fs::read(&pubkey_path)
                .with_context(|| format!("Failed to read public key: {}", pubkey_path.display()))?;
            let privkey_bytes = fs::read(&privkey_path)
                .with_context(|| format!("Failed to read private key: {}", privkey_path.display()))?;

            if pubkey_bytes.len() != 32 {
                return Err(anyhow!("Invalid public key length: expected 32 bytes, got {}", pubkey_bytes.len()));
            }
            if privkey_bytes.len() != 32 {
                return Err(anyhow!("Invalid private key length: expected 32 bytes, got {}", privkey_bytes.len()));
            }

            let mut seed = [0u8; 32];
            seed.copy_from_slice(&privkey_bytes);
            KeyPair::from_seed(&seed)
        } else {
            self.generate_keypair()
        }
    }

    /// Get the public key hash (blake3) for the header
    pub fn public_key_hash(&self) -> Result<Blake3Hash> {
        let keypair = self.load_keypair()?;
        Ok(keypair.public_key_hash())
    }

    /// Export public key as a vfsx archive
    pub fn export_key(&self, output_path: &Path, owner: Option<String>) -> Result<()> {
        let keypair = self.load_keypair()?;
        let pubkey = keypair.public_key_bytes();

        let key_id = keypair.public_key_hash().to_hex();
        let created_timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let metadata = KeyMetadata {
            algorithm: "Ed25519".to_string(),
            created_timestamp,
            key_id,
            owner: owner.unwrap_or_else(|| whoami::username()),
        };

        let temp_dir = tempfile::tempdir()?;
        let temp_path = temp_dir.path();

        fs::write(temp_path.join("pubkey.bin"), pubkey)?;

        let metadata_json = serde_json::to_vec_pretty(&metadata)?;
        fs::write(temp_path.join("metadata.json"), metadata_json)?;

        let mut writer = crate::format::ArchiveWriter::new(
            temp_path.to_path_buf(),
            output_path.to_path_buf(),
            crate::compression::CompressionType::Zstd,
            3,
        )
        .with_keypair(keypair);

        writer.write()?;

        Ok(())
    }

    /// Import a public key from a vfsx archive
    pub fn import_key(&self, archive_path: &Path) -> Result<[u8; 32]> {
        let temp_dir = tempfile::tempdir()?;
        let temp_path = temp_dir.path();

        let mut reader = crate::format::ArchiveReader::open(archive_path)?;
        reader.extract_to(temp_path, true)?;

        let pubkey_path = temp_path.join("pubkey.bin");
        let pubkey_bytes = fs::read(&pubkey_path)
            .with_context(|| format!("Failed to read pubkey.bin from archive: {}", pubkey_path.display()))?;

        if pubkey_bytes.len() != 32 {
            return Err(anyhow!("Invalid public key length: expected 32 bytes, got {}", pubkey_bytes.len()));
        }

        let metadata_path = temp_path.join("metadata.json");
        let metadata_bytes = fs::read(&metadata_path)
            .with_context(|| format!("Failed to read metadata.json from archive: {}", metadata_path.display()))?;

        let metadata: KeyMetadata = serde_json::from_slice(&metadata_bytes)
            .context("Failed to parse metadata.json")?;

        let computed_hash = blake3::hash(&pubkey_bytes);
        let computed_key_id = hex::encode(computed_hash.as_bytes());
        if computed_key_id != metadata.key_id {
            return Err(anyhow!("Key ID mismatch: metadata key_id doesn't match public key hash"));
        }

        if metadata.algorithm != "Ed25519" {
            return Err(anyhow!("Unsupported algorithm: {}", metadata.algorithm));
        }

        self.ensure_dir()?;
        fs::write(self.pubkey_path(), &pubkey_bytes)
            .with_context(|| "Failed to write imported public key")?;

        let mut key_array = [0u8; 32];
        key_array.copy_from_slice(&pubkey_bytes);
        Ok(key_array)
    }
}

impl Default for KeyStorage {
    fn default() -> Self {
        Self::new().expect("Failed to create default KeyStorage")
    }
}

/// High-level key management functions
pub fn sign_data(data: &[u8]) -> Result<[u8; 64]> {
    let storage = KeyStorage::new()?;
    let keypair = storage.load_keypair()?;
    Ok(keypair.sign(data))
}

pub fn verify_signature(pubkey: &[u8; 32], data: &[u8], sig: &[u8; 64]) -> bool {
    KeyPair::verify(pubkey, data, sig)
}

pub fn get_public_key_hash() -> Result<Blake3Hash> {
    let storage = KeyStorage::new()?;
    storage.public_key_hash()
}

pub fn export_public_key(output_path: &Path, owner: Option<String>) -> Result<()> {
    let storage = KeyStorage::new()?;
    storage.export_key(output_path, owner)
}

pub fn import_public_key(archive_path: &Path) -> Result<[u8; 32]> {
    let storage = KeyStorage::new()?;
    storage.import_key(archive_path)
}
