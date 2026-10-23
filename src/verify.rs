use anyhow::{Context, Result};
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use serde::{Deserialize, Serialize};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use crate::format::ArchiveReader;
use crate::hash::{Blake3Hash, hash_file, compute_public_key_hash};
use crate::keys::{import_public_key, KeyStorage};

/// Result of archive verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the archive is valid (signature + hashes match)
    pub valid: bool,
    /// List of errors encountered during verification
    pub errors: Vec<String>,
    /// List of warnings (non-fatal issues)
    pub warnings: Vec<String>,
    /// Number of files verified
    pub files_verified: usize,
    /// Number of files with hash mismatches
    pub hash_mismatches: usize,
    /// Number of files with missing data
    pub missing_files: usize,
    /// Whether the signature is valid
    pub signature_valid: bool,
    /// Whether the public key hash matches
    pub key_hash_matches: bool,
}

impl Default for VerificationResult {
    fn default() -> Self {
        Self {
            valid: false,
            errors: Vec::new(),
            warnings: Vec::new(),
            files_verified: 0,
            hash_mismatches: 0,
            missing_files: 0,
            signature_valid: false,
            key_hash_matches: false,
        }
    }
}

/// Verify an archive's signature and optionally its contents
pub fn verify_archive(
    archive_path: &Path,
    pubkey_path: Option<&Path>,
    verify_hashes: bool,
) -> Result<VerificationResult> {
    let mut result = VerificationResult::default();

    // Open the archive
    let mut reader = match ArchiveReader::open(archive_path) {
        Ok(r) => r,
        Err(e) => {
            result.errors.push(format!("Failed to open archive: {}", e));
            return Ok(result);
        }
    };

    // Load public key
    let public_key = match load_public_key(&reader, pubkey_path) {
        Ok(key) => key,
        Err(e) => {
            result.errors.push(format!("Failed to load public key: {}", e));
            return Ok(result);
        }
    };

    // Verify public key hash matches header
    let expected_key_hash = compute_public_key_hash(&public_key);
    result.key_hash_matches = expected_key_hash.as_bytes() == &reader.header.public_key_hash;
    if !result.key_hash_matches {
        result.errors.push("Public key hash does not match archive header".to_string());
    }

    // Verify Ed25519 signature over manifest + index JSON
    result.signature_valid = verify_signature(&reader, &public_key)?;
    if !result.signature_valid {
        result.errors.push("Signature verification failed".to_string());
    }

    // Optionally verify file hashes
    if verify_hashes {
        verify_file_hashes(&mut reader, &mut result)?;
    }

    // Overall validity
    result.valid = result.signature_valid
        && result.key_hash_matches
        && result.hash_mismatches == 0
        && result.missing_files == 0
        && result.errors.is_empty();

    Ok(result)
}

/// Load public key from various sources
fn load_public_key(_reader: &ArchiveReader, pubkey_path: Option<&Path>) -> Result<[u8; 32]> {
    if let Some(path) = pubkey_path {
        import_public_key(path)
    } else {
        let storage = KeyStorage::new()?;
        let keypair = storage.load_keypair()?;
        Ok(keypair.public_key_bytes())
    }
}

/// Verify Ed25519 signature over manifest + index JSON
fn verify_signature(reader: &ArchiveReader, public_key: &[u8; 32]) -> Result<bool> {
    // Reconstruct the signed data: manifest JSON + index JSON
    let manifest_bytes = reader.manifest.to_json()?;
    let index_bytes = reader.index.to_json()?;

    // The signature is over the concatenation of manifest + index
    let mut signed_data = Vec::with_capacity(manifest_bytes.len() + index_bytes.len());
    signed_data.extend_from_slice(&manifest_bytes);
    signed_data.extend_from_slice(&index_bytes);

    // Read the signature from the archive
    let signature = reader.read_signature()?;

    // Verify using ed25519-dalek
    let verifying_key = VerifyingKey::from_bytes(public_key)?;
    let sig = Signature::from_bytes(&signature);
    Ok(verifying_key.verify(&signed_data, &sig).is_ok())
}

/// Verify file hashes match manifest
fn verify_file_hashes(reader: &mut ArchiveReader, result: &mut VerificationResult) -> Result<()> {
    let entries: Vec<_> = reader.manifest.entries.clone();
    for entry in &entries {
        result.files_verified += 1;

        // Get file data from archive
        let data = match reader.get_file_data(entry) {
            Ok(d) => d,
            Err(e) => {
                result.errors.push(format!("Failed to read file '{}': {}", entry.path, e));
                result.missing_files += 1;
                continue;
            }
        };

        // Compute hash of extracted data
        let computed_hash = Blake3Hash::new(&data);

        // Compare with manifest
        if computed_hash.as_bytes() != entry.blake3_hash.as_bytes() {
            result.errors.push(format!(
                "Hash mismatch for '{}': expected {}, got {}",
                entry.path,
                entry.blake3_hash.to_hex(),
                computed_hash.to_hex()
            ));
            result.hash_mismatches += 1;
        }
    }

    // Check for xattr preservation
    verify_xattrs(reader, result)?;

    Ok(())
}

/// Verify extended attributes are preserved
fn verify_xattrs(reader: &mut ArchiveReader, result: &mut VerificationResult) -> Result<()> {
    for entry in &reader.manifest.entries {
        if !entry.xattrs.is_empty() {
            result.warnings.push(format!(
                "File '{}' has {} extended attributes (not verified without extraction)",
                entry.path,
                entry.xattrs.len()
            ));
        }
    }
    Ok(())
}

/// Verify an archive extracted to a directory matches the manifest
pub fn verify_extracted_archive(
    archive_path: &Path,
    extracted_path: &Path,
    pubkey_path: Option<&Path>,
) -> Result<VerificationResult> {
    let mut result = VerificationResult::default();

    let reader = ArchiveReader::open(archive_path)?;

    // Load public key
    let public_key = load_public_key(&reader, pubkey_path)?;

    // Verify signature
    result.signature_valid = verify_signature(&reader, &public_key)?;
    if !result.signature_valid {
        result.errors.push("Signature verification failed".to_string());
    }

    // Verify key hash
    let expected_key_hash = compute_public_key_hash(&public_key);
    result.key_hash_matches = expected_key_hash.as_bytes() == &reader.header.public_key_hash;
    if !result.key_hash_matches {
        result.errors.push("Public key hash does not match archive header".to_string());
    }

    // Verify each file in extracted directory
    for entry in &reader.manifest.entries {
        result.files_verified += 1;
        let dest_path = extracted_path.join(&entry.path);

        if !dest_path.exists() {
            result.errors.push(format!("Missing file in extraction: {}", entry.path));
            result.missing_files += 1;
            continue;
        }

        // Verify file hash
        let computed_hash = hash_file(&dest_path).context(format!("Failed to hash {}", entry.path))?;
        if computed_hash.as_bytes() != entry.blake3_hash.as_bytes() {
            result.errors.push(format!(
                "Hash mismatch for '{}': expected {}, got {}",
                entry.path,
                entry.blake3_hash.to_hex(),
                computed_hash.to_hex()
            ));
            result.hash_mismatches += 1;
        }

        // Verify permissions
        let metadata = std::fs::metadata(&dest_path)?;
        let mode = metadata.permissions().mode() & 0o777;
        if mode != (entry.mode & 0o777) {
            result.warnings.push(format!(
                "Permission mismatch for '{}': expected {:o}, got {:o}",
                entry.path, entry.mode & 0o777, mode
            ));
        }
    }

    result.valid = result.signature_valid
        && result.key_hash_matches
        && result.hash_mismatches == 0
        && result.missing_files == 0
        && result.errors.is_empty();

    Ok(result)
}

/// Sign an existing archive (add/replace signature)
pub fn sign_archive(archive_path: &Path) -> Result<()> {
    let reader = ArchiveReader::open(archive_path)?;
    let storage = KeyStorage::new()?;
    let keypair = storage.load_keypair()?;

    // Reconstruct signed data
    let manifest_bytes = reader.manifest.to_json()?;
    let index_bytes = reader.index.to_json()?;
    let mut signed_data = Vec::with_capacity(manifest_bytes.len() + index_bytes.len());
    signed_data.extend_from_slice(&manifest_bytes);
    signed_data.extend_from_slice(&index_bytes);

    // Sign
    let signature = keypair.sign(&signed_data);

    // Write signature to archive (after index)
    use std::io::{Seek, SeekFrom, Write};
    let mut file = std::fs::OpenOptions::new().write(true).open(archive_path)?;
    let sig_offset = reader.header.index_offset + reader.header.index_size;
    file.seek(SeekFrom::Start(sig_offset))?;
    file.write_all(&signature)?;
    file.flush()?;

    // Update header with new public key hash
    let public_key_hash = keypair.public_key_hash();
    let mut header = reader.header;
    header.public_key_hash = *public_key_hash.as_bytes();
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&header.to_bytes())?;
    file.flush()?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_verification_result_default() {
        let result = VerificationResult::default();
        assert!(!result.valid);
        assert_eq!(result.files_verified, 0);
    }

    #[test]
    fn test_verify_nonexistent_archive() {
        let result = verify_archive(Path::new("/nonexistent.vfsx.tar.zst"), None, false).unwrap();
        assert!(!result.valid);
        assert!(!result.errors.is_empty());
    }
}
