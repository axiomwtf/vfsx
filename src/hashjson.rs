use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::format::KeyPair;
use crate::hash::Blake3Hash;
use crate::format::{VfsxHeader, HEADER_SIZE, SIGNATURE_SIZE};
use std::io::{Cursor, Read, Write};

/// Data fields embedded in the .hash.json sidecar (the payload that gets signed).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashJsonData {
    /// Filename of the archive (e.g. "src.vfsx.tar.zst")
    pub archive: String,
    /// Blake3 hash of the archive file, as lowercase hex
    pub hash: String,
    /// Hex-encoded blake3 hash of the public key (key identifier)
    pub key_id: String,
    /// Unix timestamp when the sidecar was created
    pub created: u64,
}

/// Full .hash.json sidecar file — data fields plus the Ed25519 signature
/// over the serialized `HashJsonData`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashJsonFile {
    pub archive: String,
    pub hash: String,
    pub key_id: String,
    pub created: u64,
    /// Ed25519 signature (hex) over the canonical JSON of the data fields
    pub signature: String,
}

/// Compute the sidecar path: `<archive_path>.hash.json`
pub fn sidecar_path(archive_path: &Path) -> PathBuf {
    let current_name = archive_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();
    let sidecar_name = format!("{}.hash.json", current_name);
    archive_path.with_file_name(sidecar_name)
}

/// Create a `.hash.json` sidecar for the given archive, signed by the provided keypair.
pub fn create_hash_json(archive_path: &Path, keypair: &KeyPair) -> Result<PathBuf> {
    // Compute the blake3 hash of the archive file
    let hash = Blake3Hash::from_file(archive_path)
        .with_context(|| format!("Failed to hash archive: {}", archive_path.display()))?;

    let archive_name = archive_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    let key_id = keypair.public_key_hash().to_hex();

    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Build the data payload that will be signed
    let data = HashJsonData {
        archive: archive_name.clone(),
        hash: hash.to_hex(),
        key_id: key_id.clone(),
        created,
    };

    // Serialize data canonically (struct field order is deterministic with serde_json)
    let data_json = serde_json::to_vec(&data)
        .context("Failed to serialize hash.json data for signing")?;

    // Sign the serialized data
    let signature = keypair.sign(&data_json);

    let file = HashJsonFile {
        archive: archive_name,
        hash: hash.to_hex(),
        key_id,
        created,
        signature: hex::encode(signature),
    };

    // Write the sidecar next to the archive
    let sidecar = sidecar_path(archive_path);
    let json_str = serde_json::to_string_pretty(&file)
        .context("Failed to serialize hash.json file")?;
    std::fs::write(&sidecar, json_str)
        .with_context(|| format!("Failed to write hash.json: {}", sidecar.display()))?;

    Ok(sidecar)
}

/// Verify an archive against its `.hash.json` sidecar.
///
/// Checks:
///   1. The .hash.json sidecar exists
///   2. The blake3 hash of the archive matches the hash in the sidecar
///   3. The Ed25519 signature on the sidecar data is valid for the given public key
///
/// Returns `Ok(())` on success, or an error with a tamper/invalid message.
pub fn verify_hash_json(archive_path: &Path, pubkey: &[u8; 32]) -> Result<()> {
    let sidecar = sidecar_path(archive_path);

    if !sidecar.exists() {
        return Err(anyhow::anyhow!(
            "No .hash.json sidecar found at {}",
            sidecar.display()
        ));
    }

    // Read and parse the sidecar
    let sidecar_contents = std::fs::read_to_string(&sidecar)
        .with_context(|| format!("Failed to read hash.json: {}", sidecar.display()))?;
    let file: HashJsonFile = serde_json::from_str(&sidecar_contents)
        .context("Failed to parse hash.json (corrupt or malformed)")?;

    // 1. Verify the archive hash matches
    let actual_hash = Blake3Hash::from_file(archive_path)
        .with_context(|| format!("Failed to hash archive: {}", archive_path.display()))?;
    if actual_hash.to_hex() != file.hash {
        return Err(anyhow::anyhow!(
            "Archive TAMPERED: hash mismatch — expected {}, got {}",
            file.hash,
            actual_hash.to_hex()
        ));
    }

    // 2. Verify the signature on the data payload
    let data = HashJsonData {
        archive: file.archive,
        hash: file.hash,
        key_id: file.key_id,
        created: file.created,
    };
    let data_json = serde_json::to_vec(&data)
        .context("Failed to re-serialize hash.json data for verification")?;

    let signature_bytes = hex::decode(&file.signature)
        .context("Failed to decode signature from hash.json")?;
    if signature_bytes.len() != 64 {
        return Err(anyhow::anyhow!(
            "Archive TAMPERED: signature invalid (wrong length: {})",
            signature_bytes.len()
        ));
    }
    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&signature_bytes);

    let valid = KeyPair::verify(pubkey, &data_json, &sig_array);
    if !valid {
        return Err(anyhow::anyhow!(
            "Archive TAMPERED: Signature invalid on hash.json — wrong key or corrupted signature"
        ));
    }

    Ok(())
}


/// Name of the embedded signed sidecar entry (exact).
pub const EMBEDDED_HASH_JSON_NAME: &str = ".hash.json";

/// Build the signed .hash.json content over the archive's final prefix hash.
fn build_hash_json(archive_name: &str, prefix_hash: &Blake3Hash, keypair: &KeyPair) -> Result<Vec<u8>> {
    let created = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let data = HashJsonData {
        archive: archive_name.to_string(),
        hash: prefix_hash.to_hex(),
        key_id: keypair.public_key_hash().to_hex(),
        created,
    };
    let data_json = serde_json::to_vec(&data).context("Failed to serialize hash.json data")?;
    let signature = keypair.sign(&data_json);

    let file = HashJsonFile {
        archive: data.archive,
        hash: data.hash,
        key_id: data.key_id,
        created,
        signature: hex::encode(signature),
    };
    serde_json::to_vec_pretty(&file).context("Failed to serialize hash.json file")
}

/// Append the signed .hash.json as a one-entry tar trailer after the archive's
/// Ed25519 signature. The archive's own bytes (header through signature) are
/// hashed, so the trailer cannot be part of what it covers.
pub fn embed_hash_json(archive_path: &Path, keypair: &KeyPair) -> Result<()> {
    let archive_name = archive_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_default();

    let prefix_hash = Blake3Hash::from_file(archive_path)
        .with_context(|| format!("Failed to hash archive: {}", archive_path.display()))?;
    let json = build_hash_json(&archive_name, &prefix_hash, keypair)?;

    let mut trailer: Vec<u8> = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut trailer);
        let mut header = tar::Header::new_gnu();
        header.set_path(EMBEDDED_HASH_JSON_NAME)?;
        header.set_size(json.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder.append(&header, json.as_slice())?;
        builder.finish()?;
    }

    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(archive_path)
        .context("Failed to open archive to embed .hash.json")?;
    file.write_all(&trailer)?;
    file.flush()?;
    Ok(())
}

/// Verify the .hash.json embedded in an archive: the prefix hash matches the
/// signed hash, and the Ed25519 signature over the JSON data is valid.
pub fn verify_embedded_hash_json(archive_path: &Path, pubkey: &[u8; 32]) -> Result<()> {
    let bytes = std::fs::read(archive_path)
        .with_context(|| format!("Failed to read archive: {}", archive_path.display()))?;
    if bytes.len() < HEADER_SIZE {
        anyhow::bail!("Archive TAMPERED: file too small to be a vfsx archive");
    }

    let header = VfsxHeader::from_bytes(&bytes[..HEADER_SIZE])?;
    let sig_end = (header.index_offset + header.index_size) as usize + SIGNATURE_SIZE;
    if bytes.len() < sig_end {
        anyhow::bail!("Archive TAMPERED: file truncated before signature");
    }

    let prefix_hash = Blake3Hash::new(&bytes[..sig_end]);

    let trailer = &bytes[sig_end..];
    let mut json_text: Option<String> = None;
    if !trailer.is_empty() {
        let mut ar = tar::Archive::new(Cursor::new(trailer));
        for entry in ar.entries()? {
            let mut entry = entry?;
            if entry.path()?.to_string_lossy() == EMBEDDED_HASH_JSON_NAME {
                let mut s = String::new();
                entry.read_to_string(&mut s)?;
                json_text = Some(s);
                break;
            }
        }
    }
    let json_text = json_text
        .ok_or_else(|| anyhow::anyhow!("No embedded .hash.json found in archive"))?;

    let file: HashJsonFile = serde_json::from_str(&json_text)
        .context("Failed to parse embedded .hash.json (corrupt or malformed)")?;

    if prefix_hash.to_hex() != file.hash {
        anyhow::bail!(
            "Archive TAMPERED: hash mismatch — expected {}, got {}",
            file.hash,
            prefix_hash.to_hex()
        );
    }

    let data = HashJsonData {
        archive: file.archive,
        hash: file.hash,
        key_id: file.key_id,
        created: file.created,
    };
    let data_json = serde_json::to_vec(&data).context("Failed to re-serialize hash.json data")?;

    let signature_bytes = hex::decode(&file.signature).context("Failed to decode signature")?;
    if signature_bytes.len() != 64 {
        anyhow::bail!(
            "Archive TAMPERED: signature invalid (wrong length: {})",
            signature_bytes.len()
        );
    }
    let mut sig_array = [0u8; 64];
    sig_array.copy_from_slice(&signature_bytes);

    if !KeyPair::verify(pubkey, &data_json, &sig_array) {
        anyhow::bail!("Archive TAMPERED: signature invalid on embedded .hash.json");
    }
    Ok(())
}
