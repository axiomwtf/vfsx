use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;
use crate::compression::{CompressionType, Compressor, Decompressor};
use crate::hash::{Blake3Hash, HASH_SIZE};
use crate::keys::KeyStorage;

pub const MAGIC: &[u8; 4] = b"VFSX";
pub const VERSION: u16 = 1;
pub const HEADER_SIZE: usize = 128;

/// The magic bytes for signature verification
pub const SIG_MAGIC: &[u8; 4] = b"SIG!";
/// Size of an Ed25519 signature
pub const SIGNATURE_SIZE: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VfsxHeader {
    pub magic: [u8; 4],
    pub version: u16,
    pub flags: u32,
    pub timestamp: u64,
    pub manifest_offset: u64,
    pub manifest_size: u64,
    pub index_offset: u64,
    pub index_size: u64,
    pub payload_offset: u64,
    pub payload_size: u64,
    pub public_key_hash: [u8; HASH_SIZE],
}

impl VfsxHeader {
    pub fn new(
        flags: u32,
        timestamp: u64,
        manifest_offset: u64,
        manifest_size: u64,
        index_offset: u64,
        index_size: u64,
        payload_offset: u64,
        payload_size: u64,
        public_key_hash: Blake3Hash,
    ) -> Self {
        Self {
            magic: *MAGIC,
            version: VERSION,
            flags,
            timestamp,
            manifest_offset,
            manifest_size,
            index_offset,
            index_size,
            payload_offset,
            payload_size,
            public_key_hash: *public_key_hash.as_bytes(),
        }
    }

    pub fn verify_magic(&self) -> Result<()> {
        if &self.magic != MAGIC {
            anyhow::bail!("Invalid magic bytes: expected VFSX, got {:?}", self.magic);
        }
        if self.version != VERSION {
            anyhow::bail!("Unsupported version: {}", self.version);
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(HEADER_SIZE);
        buf.extend_from_slice(&self.magic);
        buf.extend_from_slice(&self.version.to_le_bytes());
        buf.extend_from_slice(&self.flags.to_le_bytes());
        buf.extend_from_slice(&self.timestamp.to_le_bytes());
        buf.extend_from_slice(&self.manifest_offset.to_le_bytes());
        buf.extend_from_slice(&self.manifest_size.to_le_bytes());
        buf.extend_from_slice(&self.index_offset.to_le_bytes());
        buf.extend_from_slice(&self.index_size.to_le_bytes());
        buf.extend_from_slice(&self.payload_offset.to_le_bytes());
        buf.extend_from_slice(&self.payload_size.to_le_bytes());
        buf.extend_from_slice(&self.public_key_hash);
        // Pad to exactly HEADER_SIZE (128 bytes). Current size = 4+2+4+8*6+32 = 90 bytes.
        while buf.len() < HEADER_SIZE {
            buf.push(0);
        }
        buf.truncate(HEADER_SIZE);
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE {
            anyhow::bail!("Header too small: {} < {}", bytes.len(), HEADER_SIZE);
        }

        let mut offset = 0;

        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[offset..offset + 4]);
        offset += 4;

        let version = u16::from_le_bytes(bytes[offset..offset + 2].try_into()?);
        offset += 2;

        let flags = u32::from_le_bytes(bytes[offset..offset + 4].try_into()?);
        offset += 4;

        let timestamp = u64::from_le_bytes(bytes[offset..offset + 8].try_into()?);
        offset += 8;

        let manifest_offset = u64::from_le_bytes(bytes[offset..offset + 8].try_into()?);
        offset += 8;

        let manifest_size = u64::from_le_bytes(bytes[offset..offset + 8].try_into()?);
        offset += 8;

        let index_offset = u64::from_le_bytes(bytes[offset..offset + 8].try_into()?);
        offset += 8;

        let index_size = u64::from_le_bytes(bytes[offset..offset + 8].try_into()?);
        offset += 8;

        let payload_offset = u64::from_le_bytes(bytes[offset..offset + 8].try_into()?);
        offset += 8;

        let payload_size = u64::from_le_bytes(bytes[offset..offset + 8].try_into()?);
        offset += 8;

        let mut public_key_hash = [0u8; HASH_SIZE];
        public_key_hash.copy_from_slice(&bytes[offset..offset + HASH_SIZE]);
        Ok(Self {
            magic,
            version,
            flags,
            timestamp,
            manifest_offset,
            manifest_size,
            index_offset,
            index_size,
            payload_offset,
            payload_size,
            public_key_hash,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u64,
    pub mtime_nsec: u32,
    pub size: u64,
    pub blake3_hash: Blake3Hash,
    pub xattrs: BTreeMap<String, Vec<u8>>,
    pub chunk_refs: Vec<ChunkRef>,
    pub is_symlink: bool,
    pub symlink_target: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRef {
    pub hash: Blake3Hash,
    pub offset: u64,
    pub length: u64,
    pub compression: CompressionType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub entries: Vec<FileEntry>,
    pub base_archive_hash: Option<Blake3Hash>,
    pub parent_hash: Option<Blake3Hash>,
    pub created_at: u64,
    pub total_size: u64,
    pub total_files: u64,
}

impl Manifest {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            base_archive_hash: None,
            parent_hash: None,
            created_at: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            total_size: 0,
            total_files: 0,
        }
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("Failed to serialize manifest")
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).context("Failed to deserialize manifest")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexEntry {
    pub hash: Blake3Hash,
    pub offset: u64,
    pub length: u64,
    pub compression: CompressionType,
    pub reference_count: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Index {
    pub entries: BTreeMap<String, IndexEntry>,
}

impl Index {
    pub fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
        }
    }

    pub fn add(&mut self, hash: Blake3Hash, offset: u64, length: u64, compression: CompressionType) {
        let key = hash.to_hex();
        self.entries
            .entry(key)
            .and_modify(|e| e.reference_count += 1)
            .or_insert(IndexEntry {
                hash,
                offset,
                length,
                compression,
                reference_count: 1,
            });
    }

    pub fn get(&self, hash: &Blake3Hash) -> Option<&IndexEntry> {
        self.entries.get(&hash.to_hex())
    }

    pub fn to_json(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).context("Failed to serialize index")
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        serde_json::from_slice(bytes).context("Failed to deserialize index")
    }

}

pub struct ArchiveWriter {
    source_dir: PathBuf,
    output_path: PathBuf,
    compression: Compressor,
    base_archive: Option<Box<ArchiveReader>>,
    keypair: Option<KeyPair>,
}

impl ArchiveWriter {
    /// Create a new ArchiveWriter - returns Self (not Result)
    pub fn new(
        source_dir: PathBuf,
        output_path: PathBuf,
        compression_type: CompressionType,
        level: i32,
    ) -> Self {
        Self {
            source_dir,
            output_path,
            compression: Compressor::new(compression_type, Some(level)),
            base_archive: None,
            keypair: None,
        }
    }

    /// Set a base archive for incremental/delta creation
    pub fn with_base(mut self, base_path: &Path) -> Result<Self> {
        self.base_archive = Some(Box::new(ArchiveReader::open(base_path)?));
        Ok(self)
    }

    /// Attach a keypair for signing
    pub fn with_keypair(mut self, keypair: KeyPair) -> Self {
        self.keypair = Some(keypair);
        self
    }

    /// Write the archive to disk
    pub fn write(&mut self) -> Result<()> {
        // Auto-load keypair if not set
        if self.keypair.is_none() {
            let storage = KeyStorage::new()?;
            self.keypair = Some(storage.load_keypair()?);
        }

        let mut file = File::create(&self.output_path).context("Failed to create output file")?;
        let mut writer = BufWriter::new(&mut file);

        // Write placeholder header (128 bytes)
        let placeholder_header = VfsxHeader::new(
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            0,
            Blake3Hash([0u8; HASH_SIZE]),
        );
        writer.write_all(&placeholder_header.to_bytes())?;

        // Write payload (compressed tar stream with all files)
        let payload_start = writer.stream_position()?;
        let (compressed_payload, manifest, index) = self.write_payload()?;
        writer.write_all(&compressed_payload)?;
        let payload_end = writer.stream_position()?;
        let actual_payload_size = payload_end - payload_start;

        // Write manifest JSON
        let manifest_bytes = manifest.to_json()?;
        let manifest_start = writer.stream_position()?;
        writer.write_all(&manifest_bytes)?;
        let _manifest_end = writer.stream_position()?;
        let manifest_size = _manifest_end - manifest_start;

        // Write index JSON
        let index_bytes = index.to_json()?;
        let index_start = writer.stream_position()?;
        writer.write_all(&index_bytes)?;
        let _index_end = writer.stream_position()?;
        let index_size = _index_end - index_start;

        // keypair is guaranteed Some at this point
        let kp = self.keypair.as_ref().expect("keypair auto-loaded");
        let public_key_hash = kp.public_key_hash();

        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let flags = 1u32;

        let header = VfsxHeader::new(
            flags,
            timestamp,
            manifest_start,
            manifest_size,
            index_start,
            index_size,
            payload_start,
            actual_payload_size,
            public_key_hash,
        );

        // Seek back and write real header
        writer.seek(SeekFrom::Start(0))?;
        writer.write_all(&header.to_bytes())?;
        writer.flush()?;

        // Write signature
        let mut signed_data = Vec::with_capacity(manifest_bytes.len() + index_bytes.len());
        signed_data.extend_from_slice(&manifest_bytes);
        signed_data.extend_from_slice(&index_bytes);
        let signature = kp.sign(&signed_data);
        writer.seek(SeekFrom::End(0))?;
        writer.write_all(&signature)?;
        writer.flush()?;
        drop(writer);

        // Embed the signed .hash.json as a trailer after the signature
        crate::hashjson::embed_hash_json(&self.output_path, kp)?;

        Ok(())
    }

    fn write_payload(&self) -> Result<(Vec<u8>, Manifest, Index)> {
        let mut manifest = Manifest::new();
        if let Some(base) = &self.base_archive {
            manifest.base_archive_hash = Some(Blake3Hash::from_file(&base.archive_path)?);
        }
        let mut index = Index::new();
        let mut total_size = 0u64;
        let mut total_files = 0u64;

        let source_dir = &self.source_dir;
        let compression_type = self.compression.compression_type;

        // Build tar into an in-memory buffer so we can compress the whole payload
        let mut tar_buf: Vec<u8> = Vec::new();
        // Track the write position in tar_buf manually, since tar_builder
        // holds a mutable borrow of tar_buf.
        let mut tar_pos: u64 = 0;

        let mut dirs = Vec::new();
        let mut files = Vec::new();

        for entry in WalkDir::new(source_dir)
            .follow_links(false)
            .sort_by(|a, b| a.file_name().cmp(b.file_name()))
        {
            let entry = entry?;
            let path = entry.path();
            let rel_path = path.strip_prefix(source_dir)?.to_path_buf();

            // Skip the output file itself to avoid self-inclusion
            if path == &self.output_path {
                continue;
            }

            if entry.file_type().is_dir() {
                // Skip the root source directory itself (empty relative path)
                if rel_path.as_os_str().is_empty() {
                    continue;
                }
                dirs.push(rel_path);
            } else if entry.file_type().is_file() {
                files.push(rel_path);
            }
        }

        dirs.sort();
        files.sort();

        {
            let mut tar_builder = tar::Builder::new(&mut tar_buf);

            for dir_path in &dirs {
                let full_path = source_dir.join(dir_path);
                let meta = full_path.metadata()?;
                let mut header = tar::Header::new_gnu();
                header.set_mode(meta.mode());
                header.set_uid(meta.uid() as u64);
                header.set_gid(meta.gid() as u64);
                header.set_mtime(meta.mtime() as u64);
                header.set_entry_type(tar::EntryType::Directory);
                header.set_path(dir_path)?;
                header.set_size(0);
                header.set_cksum();
                tar_builder.append(&mut header, std::io::empty())?;
                // Directory entry: one 512-byte header, no data, no padding (size 0)
                tar_pos += 512;
            }

            for file_path in &files {
                let full_path = source_dir.join(file_path);
                let meta = full_path.metadata()?;
                let hash = Blake3Hash::from_file(&full_path)?;

                // Check if this file exists in the base archive (reference/dedup)
                let is_reference = if let Some(base) = &self.base_archive {
                    if base.index.get(&hash).is_some() {
                        manifest.entries.push(FileEntry {
                            path: file_path.to_string_lossy().to_string(),
                            mode: meta.mode(),
                            uid: meta.uid(),
                            gid: meta.gid(),
                            mtime: meta.mtime() as u64,
                            mtime_nsec: meta.mtime_nsec() as u32,
                            size: meta.len(),
                            blake3_hash: hash.clone(),
                            xattrs: Self::read_xattrs(&full_path)?,
                            chunk_refs: vec![ChunkRef {
                                hash: hash.clone(),
                                offset: 0,
                                length: 0,
                                compression: compression_type,
                            }],
                            is_symlink: false,
                            symlink_target: None,
                        });
                        total_size += meta.len();
                        total_files += 1;
                        index.add(hash.clone(), 0, 0, compression_type);
                        true
                    } else {
                        false
                    }
                } else {
                    false
                };

                if !is_reference {
                    let mut file = File::open(&full_path)?;
                    let mut tar_header = tar::Header::new_gnu();
                    tar_header.set_mode(meta.mode());
                    tar_header.set_uid(meta.uid() as u64);
                    tar_header.set_gid(meta.gid() as u64);
                    tar_header.set_mtime(meta.mtime() as u64);
                    tar_header.set_size(meta.len());
                    tar_header.set_path(file_path)?;
                    tar_header.set_entry_type(tar::EntryType::Regular);
                    tar_header.set_cksum();

                    // Position within the tar buffer where this file's header starts
                    let data_start = tar_pos;
                    tar_builder.append(&mut tar_header, &mut file)?;
                    // file_size is the actual file data length; tar pads to 512 boundary
                    let file_size = meta.len();
                    let padded_size = (file_size + 511) & !511;
                    // Advance past the 512-byte header + padded file data
                    tar_pos += 512 + padded_size;

                    // data_start is the position of the tar header; actual file data
                    // starts after the 512-byte header
                    let data_offset = data_start + 512;
                    let data_size = file_size;

                    let chunk_ref = ChunkRef {
                        offset: data_offset,
                        length: data_size,
                        compression: compression_type,
                        hash: hash.clone(),
                    };

                    manifest.entries.push(FileEntry {
                        path: file_path.to_string_lossy().to_string(),
                        mode: meta.mode(),
                        uid: meta.uid(),
                        gid: meta.gid(),
                        mtime: meta.mtime() as u64,
                        mtime_nsec: meta.mtime_nsec() as u32,
                        size: meta.len(),
                        blake3_hash: hash.clone(),
                        xattrs: Self::read_xattrs(&full_path)?,
                        chunk_refs: vec![chunk_ref],
                        is_symlink: false,
                        symlink_target: None,
                    });
                    total_size += meta.len();
                    total_files += 1;
                    index.add(hash, data_offset, data_size, compression_type);
                }
            }

            // Finish the tar archive (writes end-of-archive marker: two 512-byte blocks)
            tar_builder.into_inner()?;
        }

        manifest.total_size = total_size;
        manifest.total_files = total_files;

        // Compress the complete tar payload
        let compressed = self.compression.compress(&tar_buf)?;

        Ok((compressed, manifest, index))
    }

    fn read_xattrs(path: &Path) -> Result<BTreeMap<String, Vec<u8>>> {
        let mut xattrs = BTreeMap::new();
        #[cfg(target_os = "linux")]
        {
            for name in xattr::list(path)? {
                if let Ok(Some(value)) = xattr::get(path, &name) {
                    xattrs.insert(name.to_string_lossy().to_string(), value);
                }
            }
        }
        Ok(xattrs)
    }
}

pub struct ArchiveReader {
    pub header: VfsxHeader,
    pub manifest: Manifest,
    pub index: Index,
    pub archive_path: PathBuf,
    pub decompression: Decompressor,
}

impl ArchiveReader {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let file = File::open(path).context("Failed to open archive")?;
        let mut reader = BufReader::new(file);

        let mut header_bytes = vec![0u8; HEADER_SIZE];
        reader.read_exact(&mut header_bytes)?;
        let header = VfsxHeader::from_bytes(&header_bytes)?;
        header.verify_magic()?;

        let compression_type = CompressionType::from_extension(path);
        reader.seek(SeekFrom::Start(header.manifest_offset))?;
        let mut manifest_bytes = vec![0u8; header.manifest_size as usize];
        reader.read_exact(&mut manifest_bytes)?;
        let manifest = Manifest::from_json(&manifest_bytes)?;

        reader.seek(SeekFrom::Start(header.index_offset))?;
        let mut index_bytes = vec![0u8; header.index_size as usize];
        reader.read_exact(&mut index_bytes)?;
        let index = Index::from_json(&index_bytes)?;

        let decompression = Decompressor::new(compression_type);

        Ok(Self {
            header,
            manifest,
            index,
            archive_path: path.to_path_buf(),
            decompression,
        })
    }

    pub fn list_entries(&self) -> &[FileEntry] {
        &self.manifest.entries
    }

    pub fn extract_to<P: AsRef<Path>>(&mut self, dest_dir: P, force: bool) -> Result<()> {
        let dest_dir = dest_dir.as_ref();
        std::fs::create_dir_all(dest_dir)?;

        // Read the compressed payload and decompress it
        let mut file = File::open(&self.archive_path)?;
        file.seek(SeekFrom::Start(self.header.payload_offset))?;
        let mut compressed = vec![0u8; self.header.payload_size as usize];
        file.read_exact(&mut compressed)?;
        let decompressed = self.decompression.decompress(&compressed)?;

        let has_refs = self.manifest.entries.iter().any(|e| {
            e.chunk_refs.first().map_or(false, |c| c.offset == 0 && c.length == 0)
        });
        if has_refs {
            anyhow::bail!(
                "archive references files stored in its base archive; extract it with the chain extractor (incremental) instead"
            );
        }

        // Feed the decompressed tar stream to tar::Archive
        let cursor = std::io::Cursor::new(decompressed);
        let mut archive = tar::Archive::new(cursor);
        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?;
            let dest_path = dest_dir.join(&path);

            if let Some(parent) = dest_path.parent() {
                std::fs::create_dir_all(parent)?;
            }

            if dest_path.exists() && !force && dest_path.is_file() {
                anyhow::bail!("File already exists: {}", dest_path.display());
            }

            entry.unpack(&dest_path)?;
        }

        // Apply metadata from manifest
        for entry in &self.manifest.entries {
            let dest_path = dest_dir.join(&entry.path);
            if dest_path.exists() && dest_path.is_file() {
                let mut perms = std::fs::metadata(&dest_path)?.permissions();
                use std::os::unix::fs::PermissionsExt;
                perms.set_mode(entry.mode);
                std::fs::set_permissions(&dest_path, perms)?;
            }
        }

        Ok(())
    }

    pub fn read_signature(&self) -> Result<[u8; SIGNATURE_SIZE]> {
        let mut file = std::fs::File::open(&self.archive_path)
            .context("Failed to open archive for signature reading")?;
        let sig_offset = self.header.index_offset + self.header.index_size;
        file.seek(SeekFrom::Start(sig_offset)).context("Failed to seek to signature")?;
        let mut sig_bytes = [0u8; SIGNATURE_SIZE];
        file.read_exact(&mut sig_bytes).context("Failed to read signature")?;
        Ok(sig_bytes)
    }

    pub fn get_file_data(&mut self, entry: &FileEntry) -> Result<Vec<u8>> {
        if entry.chunk_refs.is_empty() {
            anyhow::bail!("No chunk refs for entry: {}", entry.path);
        }

        let chunk = &entry.chunk_refs[0];

        // Reference entries have no inline data (offset 0, length 0).
        // Empty files also have length 0 but a real offset, so they read as empty.
        if chunk.length == 0 && chunk.offset == 0 {
            anyhow::bail!("Reference entry has no inline data: {}", entry.path);
        }

        // Decompress the entire payload
        let mut file = File::open(&self.archive_path)?;
        file.seek(SeekFrom::Start(self.header.payload_offset))?;
        let mut compressed = vec![0u8; self.header.payload_size as usize];
        file.read_exact(&mut compressed)?;
        let decompressed = self.decompression.decompress(&compressed)?;

        // chunk.offset already points directly at the file data within the decompressed
        // payload (write_payload stores data_start + 512, where data_start is the tar
        // header position).
        let data_offset = chunk.offset as usize;
        let data_end = data_offset + chunk.length as usize;

        if data_end > decompressed.len() {
            anyhow::bail!("Chunk data out of bounds for entry: {}", entry.path);
        }

        let data = decompressed[data_offset..data_end].to_vec();
        Ok(data)
    }

}

impl Default for Manifest {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Index {
    fn default() -> Self {
        Self::new()
    }
}

impl Default for Blake3Hash {
    fn default() -> Self {
        Self([0u8; HASH_SIZE])
    }
}

/// Create a vfsx archive from a source directory
pub fn create_archive<P: AsRef<Path>, Q: AsRef<Path>>(
    source_dir: P,
    output_path: Q,
) -> Result<()> {
    let mut writer = ArchiveWriter::new(
        source_dir.as_ref().to_path_buf(),
        output_path.as_ref().to_path_buf(),
        CompressionType::Zstd,
        3,
    );
    writer.write()
}

/// Extract a vfsx archive to a destination directory
pub fn extract_archive<P: AsRef<Path>, Q: AsRef<Path>>(
    archive_path: P,
    dest_dir: Q,
) -> Result<()> {
    let mut reader = ArchiveReader::open(archive_path)?;
    reader.extract_to(dest_dir, false)
}
/// Ed25519 keypair for signing and verification
#[derive(Clone)]
pub struct KeyPair {
    pub signing_key: ed25519_dalek::SigningKey,
    pub verifying_key: ed25519_dalek::VerifyingKey,
}

impl KeyPair {
    /// Create a new keypair from a seed (32 bytes)
    pub fn from_seed(seed: &[u8; 32]) -> Result<Self> {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        Ok(Self { signing_key, verifying_key })
    }

    /// Generate a new random keypair
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        use rand::RngCore;
        let mut csprng = OsRng;
        let mut secret_bytes = [0u8; 32];
        csprng.fill_bytes(&mut secret_bytes);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&secret_bytes);
        let verifying_key = signing_key.verifying_key();
        Self { signing_key, verifying_key }
    }

    /// Get the public key as raw 32 bytes
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    /// Get the private key seed as raw 32 bytes
    pub fn private_key_seed(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    /// Compute blake3 hash of the public key
    pub fn public_key_hash(&self) -> Blake3Hash {
        let pubkey = self.public_key_bytes();
        Blake3Hash::new(&pubkey)
    }

    /// Sign data with the private key
    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer as _;
        let signature: ed25519_dalek::Signature = self.signing_key.sign(data);
        signature.to_bytes()
    }

    /// Verify a signature against data using the public key
    pub fn verify(pubkey: &[u8; 32], data: &[u8], sig: &[u8; 64]) -> bool {
        use ed25519_dalek::Verifier as _;
        let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(pubkey) else {
            return false;
        };
        let signature = ed25519_dalek::Signature::from_bytes(sig);
        verifying_key.verify(data, &signature).is_ok()
    }
}
