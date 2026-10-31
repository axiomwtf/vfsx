use anyhow::Result;
use crate::format::ArchiveReader;

/// What a successful verification checked.
#[derive(Debug, Clone, Default)]
pub struct VerificationResult {
    /// Files whose data was checked against their hashes
    pub files_verified: usize,
    /// Files stored in the base archive of a delta; their hashes are signed
    /// here and checked when the delta is extracted with its base
    pub files_in_base: usize,
}

/// Verify the signature of an archive and the hash of every file it stores.
pub fn verify_archive(reader: &mut ArchiveReader, pubkey: &[u8; 32]) -> Result<VerificationResult> {
    reader.verify_signature(pubkey)?;
    let mut result = VerificationResult::default();
    let entries = reader.manifest.entries.clone();
    for entry in entries.iter().filter(|e| e.is_file()) {
        if entry.in_base() {
            result.files_in_base += 1;
        } else {
            reader.file_data(entry)?;
            result.files_verified += 1;
        }
    }
    Ok(result)
}
