use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{self, File, OpenOptions, Permissions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use walkdir::WalkDir;
use crate::compression::{CompressionType, Compressor};
use crate::hash::{Blake3Hash, HASH_SIZE};

pub const MAGIC: &[u8; 4] = b"VFSX";
pub const VERSION: u16 = 2;
pub const HEADER_SIZE: usize = 128;
/// Size of an Ed25519 signature
pub const SIGNATURE_SIZE: usize = 64;

pub const FLAG_HAS_SIGNATURE: u32 = 1;
pub const FLAG_IS_DELTA: u32 = 1 << 1;
const KNOWN_FLAGS: u32 = FLAG_HAS_SIGNATURE | FLAG_IS_DELTA;

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
    pub fn verify_magic(&self) -> Result<()> {
        if &self.magic != MAGIC {
            bail!("Invalid magic bytes: expected VFSX, got {:?}", self.magic);
        }
        if self.version != VERSION {
            bail!("Unsupported archive version {} (this vfsx reads version {})", self.version, VERSION);
        }
        if self.flags & !KNOWN_FLAGS != 0 {
            bail!("Unknown header flags: {:#x}", self.flags);
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
        buf.resize(HEADER_SIZE, 0);
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < HEADER_SIZE {
            bail!("Header too small: {} < {}", bytes.len(), HEADER_SIZE);
        }
        let u16_at = |o: usize| u16::from_le_bytes([bytes[o], bytes[o + 1]]);
        let u32_at = |o: usize| u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
        let u64_at = |o: usize| {
            let mut b = [0u8; 8];
            b.copy_from_slice(&bytes[o..o + 8]);
            u64::from_le_bytes(b)
        };
        let mut magic = [0u8; 4];
        magic.copy_from_slice(&bytes[0..4]);
        let mut public_key_hash = [0u8; HASH_SIZE];
        public_key_hash.copy_from_slice(&bytes[66..66 + HASH_SIZE]);
        Ok(Self {
            magic,
            version: u16_at(4),
            flags: u32_at(6),
            timestamp: u64_at(10),
            manifest_offset: u64_at(18),
            manifest_size: u64_at(26),
            index_offset: u64_at(34),
            index_size: u64_at(42),
            payload_offset: u64_at(50),
            payload_size: u64_at(58),
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
    #[serde(default)]
    pub is_dir: bool,
    pub is_symlink: bool,
    pub symlink_target: Option<String>,
}

impl FileEntry {
    pub fn is_file(&self) -> bool {
        !self.is_dir && !self.is_symlink
    }

    /// Whether the data of this file lives in the base archive.
    pub fn in_base(&self) -> bool {
        self.chunk_refs.first().is_some_and(ChunkRef::is_base_ref)
    }

    fn mtime(&self) -> SystemTime {
        UNIX_EPOCH + Duration::new(self.mtime, self.mtime_nsec.min(999_999_999))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChunkRef {
    pub hash: Blake3Hash,
    pub offset: u64,
    pub length: u64,
    pub compression: CompressionType,
}

impl ChunkRef {
    /// A reference to the base archive has no inline data: offset 0 and
    /// length 0. Inline data never starts at offset 0 (a tar header comes
    /// first), so an inline empty file is never mistaken for one.
    pub fn is_base_ref(&self) -> bool {
        self.offset == 0 && self.length == 0
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Manifest {
    pub entries: Vec<FileEntry>,
    pub base_archive_hash: Option<Blake3Hash>,
    pub created_at: u64,
    pub total_size: u64,
    pub total_files: u64,
}

impl Manifest {
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
            base_archive_hash: None,
            created_at: unix_now(),
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

impl Default for Manifest {
    fn default() -> Self {
        Self::new()
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

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Index {
    pub entries: BTreeMap<String, IndexEntry>,
}

impl Index {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, hash: Blake3Hash, offset: u64, length: u64, compression: CompressionType) {
        self.entries
            .entry(hash.to_hex())
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

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn padded(len: u64) -> u64 {
    (len + 511) & !511
}

pub struct ArchiveWriter {
    source_dir: PathBuf,
    output_path: PathBuf,
    compression: Compressor,
    follow_links: bool,
    base: Option<(Blake3Hash, Index)>,
    keypair: KeyPair,
}

impl ArchiveWriter {
    pub fn new(
        source_dir: PathBuf,
        output_path: PathBuf,
        compression_type: CompressionType,
        level: i32,
        keypair: KeyPair,
    ) -> Self {
        Self {
            source_dir,
            output_path,
            compression: Compressor::new(compression_type, Some(level)),
            follow_links: false,
            base: None,
            keypair,
        }
    }

    /// Archive what symlinks point to instead of the symlinks themselves.
    pub fn follow_links(mut self, follow: bool) -> Self {
        self.follow_links = follow;
        self
    }

    /// Store files the base archive already holds as references to it.
    pub fn with_base(mut self, base_path: &Path) -> Result<Self> {
        let base = ArchiveReader::open(base_path)?;
        self.base = Some((Blake3Hash::new(&base.bytes), base.index));
        Ok(self)
    }

    /// Write the archive. The file is built next to the output under a
    /// temporary name and renamed into place, so a failed run never leaves
    /// a partial archive behind.
    pub fn write(&self) -> Result<()> {
        let (payload, manifest, index) = self.build_payload()?;
        let compressed = self.compression.compress(&payload)?;
        let manifest_bytes = manifest.to_json()?;
        let index_bytes = index.to_json()?;

        let payload_offset = HEADER_SIZE as u64;
        let manifest_offset = payload_offset + compressed.len() as u64;
        let index_offset = manifest_offset + manifest_bytes.len() as u64;
        let mut flags = FLAG_HAS_SIGNATURE;
        if manifest.base_archive_hash.is_some() {
            flags |= FLAG_IS_DELTA;
        }
        let header = VfsxHeader {
            magic: *MAGIC,
            version: VERSION,
            flags,
            timestamp: manifest.created_at,
            manifest_offset,
            manifest_size: manifest_bytes.len() as u64,
            index_offset,
            index_size: index_bytes.len() as u64,
            payload_offset,
            payload_size: compressed.len() as u64,
            public_key_hash: *self.keypair.public_key_hash().as_bytes(),
        };

        let mut out = Vec::with_capacity(
            HEADER_SIZE + compressed.len() + manifest_bytes.len() + index_bytes.len() + SIGNATURE_SIZE,
        );
        out.extend_from_slice(&header.to_bytes());
        out.extend_from_slice(&compressed);
        out.extend_from_slice(&manifest_bytes);
        out.extend_from_slice(&index_bytes);
        // One signature over every byte before it: header, payload,
        // manifest and index.
        let signature = self.keypair.sign(&out);
        out.extend_from_slice(&signature);

        let parent = match self.output_path.parent() {
            Some(p) if !p.as_os_str().is_empty() => p,
            _ => Path::new("."),
        };
        let mut tmp = tempfile::NamedTempFile::new_in(parent)
            .with_context(|| format!("Failed to create output in {}", parent.display()))?;
        tmp.write_all(&out)?;
        tmp.as_file().set_permissions(Permissions::from_mode(0o644))?;
        tmp.as_file().sync_all()?;
        tmp.persist(&self.output_path)
            .map_err(|e| e.error)
            .with_context(|| format!("Failed to write {}", self.output_path.display()))?;
        Ok(())
    }

    fn build_payload(&self) -> Result<(Vec<u8>, Manifest, Index)> {
        let output_canon = canonical_output(&self.output_path);
        let mut dirs = Vec::new();
        let mut files = Vec::new();
        let mut links = Vec::new();

        for entry in WalkDir::new(&self.source_dir)
            .follow_links(self.follow_links)
            .sort_by_file_name()
        {
            let entry = entry?;
            let rel = entry.path().strip_prefix(&self.source_dir)?.to_path_buf();
            if rel.as_os_str().is_empty() {
                continue;
            }
            let rel_str = rel
                .to_str()
                .with_context(|| format!("Path is not valid UTF-8: {}", entry.path().display()))?
                .to_string();
            let meta = entry.metadata()?;
            let ft = entry.file_type();
            if ft.is_dir() {
                dirs.push((rel_str, entry.into_path(), meta));
            } else if ft.is_file() {
                if output_canon.is_some() && fs::canonicalize(entry.path()).ok() == output_canon {
                    continue;
                }
                files.push((rel_str, entry.into_path(), meta));
            } else if ft.is_symlink() {
                links.push((rel_str, entry.into_path(), meta));
            } else {
                eprintln!("warning: skipping special file {}", entry.path().display());
            }
        }

        let compression_type = self.compression.compression_type;
        let mut manifest = Manifest::new();
        let mut index = Index::new();
        let mut stored: HashMap<Blake3Hash, (u64, u64)> = HashMap::new();
        let mut uses_base = false;
        let mut builder = tar::Builder::new(Vec::new());

        let entry_for = |path: String, meta: &fs::Metadata, full: &Path| -> FileEntry {
            FileEntry {
                path,
                mode: meta.mode(),
                uid: meta.uid(),
                gid: meta.gid(),
                mtime: meta.mtime().max(0) as u64,
                mtime_nsec: meta.mtime_nsec().max(0) as u32,
                size: 0,
                blake3_hash: Blake3Hash::default(),
                xattrs: read_xattrs(full),
                chunk_refs: Vec::new(),
                is_dir: false,
                is_symlink: false,
                symlink_target: None,
            }
        };
        let tar_header = |meta: &fs::Metadata, kind: tar::EntryType, size: u64| {
            let mut h = tar::Header::new_gnu();
            h.set_mode(meta.mode() & 0o7777);
            h.set_uid(meta.uid() as u64);
            h.set_gid(meta.gid() as u64);
            h.set_mtime(meta.mtime().max(0) as u64);
            h.set_entry_type(kind);
            h.set_size(size);
            h
        };

        for (rel, full, meta) in &dirs {
            let mut h = tar_header(meta, tar::EntryType::Directory, 0);
            builder.append_data(&mut h, rel, std::io::empty())?;
            let mut e = entry_for(rel.clone(), meta, full);
            e.is_dir = true;
            manifest.entries.push(e);
        }

        for (rel, full, meta) in &files {
            let data = fs::read(full).with_context(|| format!("Failed to read {}", full.display()))?;
            let len = data.len() as u64;
            let hash = Blake3Hash::new(&data);
            let in_base = len > 0
                && self
                    .base
                    .as_ref()
                    .and_then(|(_, base_index)| base_index.get(&hash))
                    .is_some_and(|ie| ie.length == len);
            let (offset, length) = if let Some(&at) = stored.get(&hash) {
                at
            } else if in_base {
                uses_base = true;
                (0, 0)
            } else {
                let mut h = tar_header(meta, tar::EntryType::Regular, len);
                builder.append_data(&mut h, rel, data.as_slice())?;
                let offset = builder.get_ref().len() as u64 - padded(len);
                stored.insert(hash.clone(), (offset, len));
                (offset, len)
            };
            index.add(hash.clone(), offset, length, compression_type);
            let mut e = entry_for(rel.clone(), meta, full);
            e.size = len;
            e.blake3_hash = hash.clone();
            e.chunk_refs = vec![ChunkRef { hash, offset, length, compression: compression_type }];
            manifest.entries.push(e);
            manifest.total_size += len;
            manifest.total_files += 1;
        }

        for (rel, full, meta) in &links {
            let target = fs::read_link(full)?;
            let target_str = target
                .to_str()
                .with_context(|| format!("Symlink target is not valid UTF-8: {}", full.display()))?
                .to_string();
            let mut h = tar_header(meta, tar::EntryType::Symlink, 0);
            builder.append_link(&mut h, rel, &target)?;
            let mut e = entry_for(rel.clone(), meta, full);
            e.xattrs.clear();
            e.is_symlink = true;
            e.symlink_target = Some(target_str);
            manifest.entries.push(e);
        }

        if uses_base {
            manifest.base_archive_hash = self.base.as_ref().map(|(h, _)| h.clone());
        }
        let payload = builder.into_inner()?;
        Ok((payload, manifest, index))
    }
}

fn canonical_output(output: &Path) -> Option<PathBuf> {
    let parent = match output.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };
    Some(fs::canonicalize(parent).ok()?.join(output.file_name()?))
}

fn read_xattrs(path: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut xattrs = BTreeMap::new();
    if let Ok(names) = xattr::list(path) {
        for name in names {
            if let Ok(Some(value)) = xattr::get(path, &name) {
                xattrs.insert(name.to_string_lossy().to_string(), value);
            }
        }
    }
    xattrs
}

pub struct ArchiveReader {
    pub header: VfsxHeader,
    pub manifest: Manifest,
    pub index: Index,
    pub archive_path: PathBuf,
    bytes: Vec<u8>,
    payload: Option<Vec<u8>>,
}

impl ArchiveReader {
    /// Open an archive. Every offset in the header is checked against the
    /// file before anything is read from it.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        let bytes = fs::read(path).with_context(|| format!("Failed to open archive {}", path.display()))?;
        if bytes.len() < HEADER_SIZE + SIGNATURE_SIZE {
            bail!("Not a vfsx archive: {} is too small", path.display());
        }
        let header = VfsxHeader::from_bytes(&bytes[..HEADER_SIZE])?;
        header.verify_magic()?;

        let end = |offset: u64, size: u64| offset.checked_add(size).context("Corrupt header: offsets overflow");
        let payload_end = end(header.payload_offset, header.payload_size)?;
        let manifest_end = end(header.manifest_offset, header.manifest_size)?;
        let index_end = end(header.index_offset, header.index_size)?;
        if header.payload_offset != HEADER_SIZE as u64
            || header.manifest_offset != payload_end
            || header.index_offset != manifest_end
            || index_end.checked_add(SIGNATURE_SIZE as u64) != Some(bytes.len() as u64)
        {
            bail!("Corrupt header: sections do not match the size of {}", path.display());
        }

        let manifest = Manifest::from_json(&bytes[header.manifest_offset as usize..manifest_end as usize])?;
        let index = Index::from_json(&bytes[header.index_offset as usize..index_end as usize])?;
        Ok(Self {
            header,
            manifest,
            index,
            archive_path: path.to_path_buf(),
            bytes,
            payload: None,
        })
    }

    fn signed_len(&self) -> usize {
        (self.header.index_offset + self.header.index_size) as usize
    }

    pub fn is_delta(&self) -> bool {
        self.header.flags & FLAG_IS_DELTA != 0
    }

    pub fn compression(&self) -> CompressionType {
        let start = self.header.payload_offset as usize;
        CompressionType::sniff(&self.bytes[start..self.header.manifest_offset as usize])
    }

    /// Check that `pubkey` signed this archive. The signature covers every
    /// byte of the file before it.
    pub fn verify_signature(&self, pubkey: &[u8; 32]) -> Result<()> {
        if Blake3Hash::new(pubkey).as_bytes() != &self.header.public_key_hash {
            bail!(
                "Archive was signed by a different key (key id {})",
                hex::encode(self.header.public_key_hash)
            );
        }
        let signed = self.signed_len();
        let mut sig = [0u8; SIGNATURE_SIZE];
        sig.copy_from_slice(&self.bytes[signed..signed + SIGNATURE_SIZE]);
        if !KeyPair::verify(pubkey, &self.bytes[..signed], &sig) {
            bail!("Signature invalid: the archive was tampered with or is corrupted");
        }
        Ok(())
    }

    fn payload(&mut self) -> Result<&[u8]> {
        if self.payload.is_none() {
            // Upper bound of the tar stream the manifest describes: each
            // entry is at most a long-name header, a header and its data.
            let limit = self.manifest.entries.iter().fold(2048u64, |acc, e| {
                let target = e.symlink_target.as_ref().map_or(0, |t| t.len() as u64);
                acc.saturating_add(2048)
                    .saturating_add(padded(e.path.len() as u64))
                    .saturating_add(padded(target))
                    .saturating_add(padded(e.size))
            });
            let start = self.header.payload_offset as usize;
            let end = self.header.manifest_offset as usize;
            self.payload = Some(crate::compression::decompress(&self.bytes[start..end], limit)?);
        }
        Ok(self.payload.as_deref().unwrap_or_default())
    }

    fn slice(&mut self, offset: u64, length: u64, hash: &Blake3Hash, what: &str) -> Result<Vec<u8>> {
        let payload = self.payload()?;
        let end = offset.checked_add(length).filter(|&e| e <= payload.len() as u64);
        let Some(end) = end else {
            bail!("Data of {} is out of bounds: archive is corrupted", what);
        };
        let data = payload[offset as usize..end as usize].to_vec();
        if &Blake3Hash::new(&data) != hash {
            bail!("Hash mismatch for {}: archive is corrupted", what);
        }
        Ok(data)
    }

    /// The data of a file stored in this archive, checked against its hash.
    pub fn file_data(&mut self, entry: &FileEntry) -> Result<Vec<u8>> {
        let chunk = entry
            .chunk_refs
            .first()
            .with_context(|| format!("No data for {}", entry.path))?;
        if chunk.is_base_ref() {
            bail!("{} is stored in the base archive", entry.path);
        }
        if chunk.length != entry.size {
            bail!("Size mismatch for {}: archive is corrupted", entry.path);
        }
        self.slice(chunk.offset, chunk.length, &entry.blake3_hash, &entry.path)
    }

    /// The data stored under `hash`, used when this is the base of a delta.
    pub fn data_for_hash(&mut self, hash: &Blake3Hash) -> Result<Vec<u8>> {
        let (offset, length) = match self.index.get(hash) {
            Some(ie) if !(ie.offset == 0 && ie.length == 0) => (ie.offset, ie.length),
            _ => bail!("Base archive does not hold {}", hash),
        };
        self.slice(offset, length, hash, &hash.to_hex())
    }

    /// Extract into `dest`. Paths are checked before anything is written,
    /// nothing is written through a symlink, files are checked against
    /// their hashes, and symlinks are created last. Returns warnings for
    /// metadata that could not be restored.
    pub fn extract_to(
        &mut self,
        dest: &Path,
        force: bool,
        mut base: Option<&mut ArchiveReader>,
    ) -> Result<Vec<String>> {
        let entries = self.manifest.entries.clone();
        if entries.iter().any(FileEntry::in_base) {
            let expected = self
                .manifest
                .base_archive_hash
                .clone()
                .context("Archive references a base archive but does not name it")?;
            let b = base
                .as_deref_mut()
                .context("This is a delta archive: pass its base archive with --base")?;
            if Blake3Hash::new(&b.bytes) != expected {
                bail!("{} is not the base this archive was made from", b.archive_path.display());
            }
        }

        let mut seen = HashSet::new();
        let mut rels = Vec::with_capacity(entries.len());
        for e in &entries {
            let rel = safe_relative_path(&e.path)?;
            if !seen.insert(rel.clone()) {
                bail!("Duplicate path in archive: {}", e.path);
            }
            rels.push(rel);
        }

        fs::create_dir_all(dest)
            .with_context(|| format!("Failed to create {}", dest.display()))?;
        let mut warnings = Vec::new();

        for (_, rel) in entries.iter().zip(&rels).filter(|(e, _)| e.is_dir) {
            let path = prepare(dest, rel)?;
            match fs::symlink_metadata(&path) {
                Ok(m) if m.is_dir() => {}
                Ok(_) => bail!("{} exists and is not a directory", path.display()),
                Err(_) => fs::create_dir(&path)
                    .with_context(|| format!("Failed to create {}", path.display()))?,
            }
        }

        for (e, rel) in entries.iter().zip(&rels).filter(|(e, _)| e.is_file()) {
            let data = if e.in_base() {
                match base.as_deref_mut() {
                    Some(b) => b.data_for_hash(&e.blake3_hash)?,
                    None => bail!("This is a delta archive: pass its base archive with --base"),
                }
            } else {
                self.file_data(e)?
            };
            let path = prepare(dest, rel)?;
            make_room(&path, force)?;
            let mut f = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&path)
                .with_context(|| format!("Failed to create {}", path.display()))?;
            f.write_all(&data)?;
            f.set_permissions(Permissions::from_mode(e.mode & 0o777))?;
            f.set_modified(e.mtime())?;
            restore_xattrs(&path, e, &mut warnings);
        }

        for (e, rel) in entries.iter().zip(&rels).filter(|(e, _)| e.is_symlink) {
            let target = e
                .symlink_target
                .as_deref()
                .with_context(|| format!("Symlink {} has no target", e.path))?;
            let path = prepare(dest, rel)?;
            make_room(&path, force)?;
            std::os::unix::fs::symlink(target, &path)
                .with_context(|| format!("Failed to create symlink {}", path.display()))?;
        }

        // Directory metadata last, deepest first, so a read-only directory
        // does not stop its own contents from being written.
        for (e, rel) in entries.iter().zip(&rels).filter(|(e, _)| e.is_dir).rev() {
            let path = dest.join(rel);
            restore_xattrs(&path, e, &mut warnings);
            if let Err(err) = File::open(&path).and_then(|d| d.set_modified(e.mtime())) {
                warnings.push(format!("{}: mtime not restored: {}", e.path, err));
            }
            fs::set_permissions(&path, Permissions::from_mode(e.mode & 0o777))?;
        }

        Ok(warnings)
    }
}

/// A manifest path as a relative path that cannot leave the destination.
fn safe_relative_path(path: &str) -> Result<PathBuf> {
    let p = Path::new(path);
    if path.is_empty() || !p.components().all(|c| matches!(c, Component::Normal(_))) {
        bail!("Unsafe path in archive: {:?}", path);
    }
    Ok(p.to_path_buf())
}

/// Create the parents of `rel` under `dest`, refusing to go through a
/// symlink or a non-directory. Returns the full path.
fn prepare(dest: &Path, rel: &Path) -> Result<PathBuf> {
    let mut cur = dest.to_path_buf();
    if let Some(parent) = rel.parent() {
        for comp in parent.components() {
            cur.push(comp);
            match fs::symlink_metadata(&cur) {
                Ok(m) if m.file_type().is_symlink() => {
                    bail!("Refusing to extract through symlink {}", cur.display())
                }
                Ok(m) if !m.is_dir() => bail!("{} is not a directory", cur.display()),
                Ok(_) => {}
                Err(_) => fs::create_dir(&cur)
                    .with_context(|| format!("Failed to create {}", cur.display()))?,
            }
        }
    }
    Ok(dest.join(rel))
}

/// Remove an existing file or symlink at `path` when `force` is set.
fn make_room(path: &Path, force: bool) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(_) => Ok(()),
        Ok(m) if m.is_dir() => bail!("{} exists and is a directory", path.display()),
        Ok(_) if !force => bail!("{} already exists (use --force to overwrite)", path.display()),
        Ok(_) => fs::remove_file(path).with_context(|| format!("Failed to replace {}", path.display())),
    }
}

fn restore_xattrs(path: &Path, entry: &FileEntry, warnings: &mut Vec<String>) {
    for (name, value) in &entry.xattrs {
        if let Err(err) = xattr::set(path, name, value) {
            warnings.push(format!("{}: xattr {} not restored: {}", entry.path, name, err));
        }
    }
}

/// Ed25519 keypair for signing and verification
#[derive(Clone)]
pub struct KeyPair {
    pub signing_key: ed25519_dalek::SigningKey,
    pub verifying_key: ed25519_dalek::VerifyingKey,
}

impl KeyPair {
    pub fn from_seed(seed: &[u8; 32]) -> Self {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(seed);
        let verifying_key = signing_key.verifying_key();
        Self { signing_key, verifying_key }
    }

    pub fn generate() -> Self {
        use rand::RngCore;
        let mut seed = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut seed);
        Self::from_seed(&seed)
    }

    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.verifying_key.to_bytes()
    }

    pub fn private_key_seed(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }

    pub fn public_key_hash(&self) -> Blake3Hash {
        Blake3Hash::new(&self.public_key_bytes())
    }

    pub fn sign(&self, data: &[u8]) -> [u8; 64] {
        use ed25519_dalek::Signer as _;
        self.signing_key.sign(data).to_bytes()
    }

    /// Strict verification: rejects weak keys and malleable signatures.
    pub fn verify(pubkey: &[u8; 32], data: &[u8], sig: &[u8; 64]) -> bool {
        let Ok(verifying_key) = ed25519_dalek::VerifyingKey::from_bytes(pubkey) else {
            return false;
        };
        let signature = ed25519_dalek::Signature::from_bytes(sig);
        verifying_key.verify_strict(data, &signature).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive(dir: &Path, kp: &KeyPair) -> PathBuf {
        let out = dir.join("a.vfsx.tar.zst");
        ArchiveWriter::new(dir.join("src"), out.clone(), CompressionType::Zstd, 3, kp.clone())
            .write()
            .unwrap();
        out
    }

    /// Rewrite the manifest of a signed archive and sign it again, the way
    /// an attacker with their own key would.
    fn forge(path: &Path, kp: &KeyPair, f: impl FnOnce(&mut Manifest)) {
        let reader = ArchiveReader::open(path).unwrap();
        let mut manifest = reader.manifest.clone();
        f(&mut manifest);
        let payload = &reader.bytes[HEADER_SIZE..reader.header.manifest_offset as usize];
        let m = manifest.to_json().unwrap();
        let i = reader.index.to_json().unwrap();
        let mut header = reader.header;
        header.manifest_size = m.len() as u64;
        header.index_offset = header.manifest_offset + m.len() as u64;
        header.index_size = i.len() as u64;
        let mut out = header.to_bytes();
        out.extend_from_slice(payload);
        out.extend_from_slice(&m);
        out.extend_from_slice(&i);
        let sig = kp.sign(&out);
        out.extend_from_slice(&sig);
        fs::write(path, out).unwrap();
    }

    fn setup(files: &[(&str, &[u8])]) -> (tempfile::TempDir, KeyPair) {
        let dir = tempfile::tempdir().unwrap();
        for (name, data) in files {
            let p = dir.path().join("src").join(name);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, data).unwrap();
        }
        (dir, KeyPair::generate())
    }

    #[test]
    fn round_trip_and_signature() {
        let (dir, kp) = setup(&[("a.txt", b"hello"), ("sub/b.txt", b"hello")]);
        let path = archive(dir.path(), &kp);
        let mut r = ArchiveReader::open(&path).unwrap();
        r.verify_signature(&kp.public_key_bytes()).unwrap();
        assert!(r.verify_signature(&KeyPair::generate().public_key_bytes()).is_err());
        r.extract_to(&dir.path().join("x"), false, None).unwrap();
        assert_eq!(fs::read(dir.path().join("x/sub/b.txt")).unwrap(), b"hello");
    }

    #[test]
    fn rejects_path_traversal() {
        for evil in ["../evil.txt", "/tmp/vfsx_evil.txt", "a/../../evil.txt", ""] {
            let (dir, kp) = setup(&[("a.txt", b"hello")]);
            let path = archive(dir.path(), &kp);
            forge(&path, &kp, |m| m.entries.iter_mut().for_each(|e| e.path = evil.to_string()));
            let mut r = ArchiveReader::open(&path).unwrap();
            assert!(r.extract_to(&dir.path().join("x"), false, None).is_err(), "{evil}");
            assert!(!dir.path().join("evil.txt").exists());
        }
    }

    #[test]
    fn never_writes_through_symlinks() {
        let (dir, kp) = setup(&[("link/f.txt", b"hello")]);
        let path = archive(dir.path(), &kp);
        let outside = dir.path().join("outside");
        fs::create_dir(&outside).unwrap();

        // A symlink already in the destination is not followed.
        let dest = dir.path().join("x");
        fs::create_dir(&dest).unwrap();
        std::os::unix::fs::symlink(&outside, dest.join("link")).unwrap();
        let mut r = ArchiveReader::open(&path).unwrap();
        assert!(r.extract_to(&dest, true, None).is_err());

        // Nor is a symlink the archive itself plants before a file under it.
        forge(&path, &kp, |m| {
            let mut link = m.entries.iter().find(|e| e.is_dir).unwrap().clone();
            link.is_dir = false;
            link.is_symlink = true;
            link.symlink_target = Some(outside.to_string_lossy().into_owned());
            m.entries.retain(|e| !e.is_dir);
            m.entries.insert(0, link);
        });
        let mut r = ArchiveReader::open(&path).unwrap();
        assert!(r.extract_to(&dir.path().join("y"), true, None).is_err());
        assert!(!outside.join("f.txt").exists());
    }

    #[test]
    fn bounds_decompression_by_manifest() {
        let big = vec![0u8; 1 << 20];
        let (dir, kp) = setup(&[("big", &big)]);
        let path = archive(dir.path(), &kp);
        forge(&path, &kp, |m| m.entries.iter_mut().for_each(|e| e.size = 1));
        let mut r = ArchiveReader::open(&path).unwrap();
        assert!(r.extract_to(&dir.path().join("x"), false, None).is_err());
    }

    #[test]
    fn rejects_trailing_and_truncated_bytes() {
        let (dir, kp) = setup(&[("a.txt", b"hello")]);
        let path = archive(dir.path(), &kp);
        let mut bytes = fs::read(&path).unwrap();
        bytes.push(0);
        fs::write(&path, &bytes).unwrap();
        assert!(ArchiveReader::open(&path).is_err());
        bytes.truncate(bytes.len() - 2);
        fs::write(&path, &bytes).unwrap();
        assert!(ArchiveReader::open(&path).is_err());
    }
}
