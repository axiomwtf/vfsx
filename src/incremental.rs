use anyhow::{Context, Result};
use blake3;
use std::collections::{BTreeMap, HashMap};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::format::{ArchiveReader, Index, VfsxHeader, HEADER_SIZE};
use crate::hash::{Blake3Hash, hash_file, HASH_SIZE};
use crate::blobstore::deduplicate_file;
use serde::{Serialize, Deserialize};

pub const VFSX_MAGIC: &[u8; 4] = b"VFSX";

pub struct BaseArchive {
    pub header: VfsxHeader,
    pub parent_hash: Option<Blake3Hash>,
    pub manifest: crate::format::Manifest,
    pub index: Index,
    pub archive_path: PathBuf,
}

impl BaseArchive {
    pub fn open(path: &Path) -> Result<Self> {
        let reader = ArchiveReader::open(path)?;
        Ok(Self {
            header: reader.header,
            parent_hash: None,
            manifest: reader.manifest,
            index: reader.index,
            archive_path: path.to_path_buf(),
        })
    }

    fn parse_header(bytes: &[u8]) -> Result<VfsxHeader> {
        if bytes.len() < HEADER_SIZE {
            anyhow::bail!("header too small");
        }
        if &bytes[0..4] != VFSX_MAGIC {
            anyhow::bail!("invalid magic bytes");
        }

        let version = u16::from_le_bytes([bytes[4], bytes[5]]);
        let flags = u32::from_le_bytes([bytes[6], bytes[7], bytes[8], bytes[9]]);
        let timestamp = u64::from_le_bytes([
            bytes[10], bytes[11], bytes[12], bytes[13],
            bytes[14], bytes[15], bytes[16], bytes[17],
        ]);
        let manifest_offset = u64::from_le_bytes([
            bytes[18], bytes[19], bytes[20], bytes[21],
            bytes[22], bytes[23], bytes[24], bytes[25],
        ]);
        let manifest_size = u64::from_le_bytes([
            bytes[26], bytes[27], bytes[28], bytes[29],
            bytes[30], bytes[31], bytes[32], bytes[33],
        ]);
        let index_offset = u64::from_le_bytes([
            bytes[34], bytes[35], bytes[36], bytes[37],
            bytes[38], bytes[39], bytes[40], bytes[41],
        ]);
        let index_size = u64::from_le_bytes([
            bytes[42], bytes[43], bytes[44], bytes[45],
            bytes[46], bytes[47], bytes[48], bytes[49],
        ]);
        let payload_offset = u64::from_le_bytes([
            bytes[52], bytes[53], bytes[54], bytes[55],
            bytes[56], bytes[57], bytes[58], bytes[59],
        ]);
        let payload_size = u64::from_le_bytes([
            bytes[60], bytes[61], bytes[62], bytes[63],
            bytes[64], bytes[65], bytes[66], bytes[67],
        ]);
        let mut public_key_hash = [0u8; HASH_SIZE];
        public_key_hash.copy_from_slice(&bytes[68..100]);

        let _parent_hash = if bytes[100] == 1 {
            let mut hash_bytes = [0u8; HASH_SIZE];
            hash_bytes.copy_from_slice(&bytes[101..133]);
            Some(Blake3Hash(hash_bytes))
        } else {
            None
        };

        Ok(VfsxHeader {
            magic: *VFSX_MAGIC,
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

    pub fn compute_hash(&self) -> Blake3Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(&self.header.magic);
        hasher.update(&self.header.version.to_le_bytes());
        hasher.update(&self.header.flags.to_le_bytes());
        hasher.update(&self.header.timestamp.to_le_bytes());
        hasher.update(&self.header.manifest_offset.to_le_bytes());
        hasher.update(&self.header.manifest_size.to_le_bytes());
        hasher.update(&self.header.index_offset.to_le_bytes());
        hasher.update(&self.header.index_size.to_le_bytes());
        hasher.update(&self.header.public_key_hash);
        if let Some(parent) = &self.parent_hash {
            hasher.update(parent.as_bytes());
        }
        Blake3Hash::new(hasher.finalize().as_bytes())
    }

    pub fn get_file_hash(&self, path: &str) -> Option<&Blake3Hash> {
        self.manifest.entries.iter()
            .find(|f| f.path == path)
            .map(|f| &f.blake3_hash)
    }

    pub fn extract_file(&self, path: &str, output_dir: &Path) -> Result<()> {
        let entry = self.manifest.entries.iter()
            .find(|f| f.path == path)
            .context("file not in manifest")?;

        let index_entry = self.index.entries.get(&entry.blake3_hash.to_hex())
            .context("file not in index")?;

        let mut archive_file = fs::File::open(&self.archive_path)
            .context("open archive for extraction")?;

        archive_file.seek(SeekFrom::Start(index_entry.offset))
            .context("seek to file data")?;

        let mut data = vec![0u8; index_entry.length as usize];
        archive_file.read_exact(&mut data)
            .context("read file data")?;

        let out_path = output_dir.join(&entry.path);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)
                .context("create output directory")?;
        }
        fs::write(&out_path, &data).context("write extracted file")?;

        Ok(())
    }

    pub fn extract_all(&self, output_dir: &Path) -> Result<()> {
        for entry in &self.manifest.entries {
            self.extract_file(&entry.path, output_dir)
                .context(format!("extract file {}", entry.path))?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Compression {
    Zstd,
    Xz,
    Gzip,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaFileEntry {
    pub path: String,
    pub hash: Blake3Hash,
    pub action: DeltaAction,
    pub size: u64,
    pub mode: u32,
    pub mtime: u64,
    pub xattrs: HashMap<String, Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DeltaAction {
    Reference,
    Include,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaManifest {
    pub parent_hash: Blake3Hash,
    pub files: Vec<DeltaFileEntry>,
    pub total_size: u64,
    pub included_count: usize,
    pub referenced_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaArchive {
    pub manifest: DeltaManifest,
    pub payload_offset: u64,
    pub payload_size: u64,
}

pub struct DeltaCreate {
    base: BaseArchive,
    new_dir: PathBuf,
    output: PathBuf,
    #[allow(dead_code)]
    compression: Compression,
}

impl DeltaCreate {
    pub fn create(self) -> Result<DeltaArchive> {
        let mut delta_files = Vec::new();
        let mut included_count = 0;
        let mut referenced_count = 0;
        let mut total_size = 0u64;
        let mut payload_data = Vec::new();

        let base_hashes: HashMap<String, &Blake3Hash> = self.base.manifest.entries.iter()
            .map(|f| (f.path.clone(), &f.blake3_hash))
            .collect();

        for entry in WalkDir::new(&self.new_dir).into_iter().filter_map(|e| e.ok()) {
            let path = entry.path();
            if !path.is_file() {
                continue;
            }

            let relative = path.strip_prefix(&self.new_dir)
                .context("strip prefix")?;
            let relative_str = relative.to_string_lossy().to_string();

            let hash = hash_file(path).context("hash file")?;
            let metadata = fs::metadata(path).context("get metadata")?;
            let size = metadata.len();
            let mtime = metadata.modified()
                .context("get mtime")?
                .duration_since(std::time::UNIX_EPOCH)
                .context("mtime duration")?
                .as_secs();

            let mode = if cfg!(unix) {
                use std::os::unix::fs::MetadataExt;
                metadata.mode()
            } else {
                0o644
            };

            let mut xattrs = HashMap::new();
            #[cfg(target_os = "linux")]
            {
                use xattr::{list, get};
                if let Ok(attrs) = list(path) {
                    for attr in attrs {
                        if let Ok(Some(value)) = get(path, &attr) {
                            if let Some(key) = attr.to_str() {
                                xattrs.insert(key.to_string(), value);
                            }
                        }
                    }
                }
            }
            if let Some(base_hash) = base_hashes.get(&relative_str) {
                if **base_hash == hash {
                    delta_files.push(DeltaFileEntry {
                        path: relative_str,
                        hash: hash.clone(),
                        action: DeltaAction::Reference,
                        size,
                        mode,
                        mtime,
                        xattrs,
                    });
                    referenced_count += 1;
                    continue;
                }
            }

            let mut file_data = Vec::new();
            fs::File::open(path).context("open new file")?.read_to_end(&mut file_data)
                .context("read new file")?;

            deduplicate_file(&hash, path).context("deduplicate new file")?;

            payload_data.extend_from_slice(&file_data);

            delta_files.push(DeltaFileEntry {
                path: relative_str,
                hash: hash.clone(),
                action: DeltaAction::Include,
                size,
                mode,
                mtime,
                xattrs,
            });
            included_count += 1;
            total_size += size;
        }

        let delta_manifest = DeltaManifest {
            parent_hash: self.base.compute_hash(),
            files: delta_files,
            total_size,
            included_count,
            referenced_count,
        };

        let manifest_bytes = serde_json::to_vec(&delta_manifest).context("serialize delta manifest")?;

        let payload_offset = HEADER_SIZE as u64;
        let manifest_offset = payload_offset + payload_data.len() as u64;
        let manifest_size = manifest_bytes.len() as u64;
        let index = Index { entries: BTreeMap::new() };
        let index_bytes = serde_json::to_vec(&index).context("serialize index")?;
        let index_offset = manifest_offset + manifest_size;
        let index_size = index_bytes.len() as u64;
        let payload_size = payload_data.len() as u64;

        let header = VfsxHeader::new(
            0,
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .context("get timestamp")?
                .as_secs(),
            manifest_offset,
            manifest_size,
            index_offset,
            index_size,
            payload_offset,
            payload_size,
            Blake3Hash(self.base.header.public_key_hash),
        );

        let mut output_file = fs::File::create(&self.output).context("create output")?;

        let mut header_bytes = [0u8; 128];
        header_bytes[0..4].copy_from_slice(VFSX_MAGIC);
        header_bytes[4..6].copy_from_slice(&header.version.to_le_bytes());
        header_bytes[6..10].copy_from_slice(&header.flags.to_le_bytes());
        header_bytes[10..18].copy_from_slice(&header.timestamp.to_le_bytes());
        header_bytes[18..26].copy_from_slice(&header.manifest_offset.to_le_bytes());
        header_bytes[26..34].copy_from_slice(&header.manifest_size.to_le_bytes());
        header_bytes[34..42].copy_from_slice(&header.index_offset.to_le_bytes());
        header_bytes[42..50].copy_from_slice(&header.index_size.to_le_bytes());
        header_bytes[50..82].copy_from_slice(&header.public_key_hash);
        header_bytes[82] = 1;
        let parent_hash_bytes = self.base.compute_hash();
        header_bytes[83..115].copy_from_slice(parent_hash_bytes.as_bytes());

        output_file.write_all(&header_bytes).context("write header")?;
        output_file.write_all(&payload_data).context("write payload")?;
        output_file.write_all(&manifest_bytes).context("write manifest")?;
        output_file.write_all(&index_bytes).context("write index")?;

        Ok(DeltaArchive {
            manifest: delta_manifest,
            payload_offset,
            payload_size: payload_data.len() as u64,
        })
    }
}

pub struct DeltaExtract {
    delta_path: PathBuf,
    base: BaseArchive,
    output_dir: PathBuf,
}

impl DeltaExtract {
    pub fn new(delta_path: PathBuf, base: BaseArchive, output_dir: PathBuf) -> Self {
        Self { delta_path, base, output_dir }
    }

    pub fn extract(self) -> Result<()> {
        let mut delta_file = fs::File::open(&self.delta_path).context("open delta archive")?;

        let mut header_bytes = [0u8; 128];
        delta_file.read_exact(&mut header_bytes).context("read delta header")?;
        let _delta_header = BaseArchive::parse_header(&header_bytes)?;
        let _delta_parent_hash = if header_bytes[100] == 1 {
            let hash_bytes = &header_bytes[101..133];
            Some(Blake3Hash(hash_bytes.try_into().unwrap()))
        } else {
            None
        };

        let manifest_offset = u64::from_le_bytes(header_bytes[18..26].try_into().unwrap());
        let manifest_size = u64::from_le_bytes(header_bytes[26..34].try_into().unwrap());
        let index_offset = u64::from_le_bytes(header_bytes[34..42].try_into().unwrap());

        let mut manifest_bytes = vec![0u8; manifest_size as usize];
        delta_file.seek(SeekFrom::Start(manifest_offset)).context("seek to delta manifest")?;
        delta_file.read_exact(&mut manifest_bytes).context("read delta manifest")?;
        let delta_manifest: DeltaManifest = serde_json::from_slice(&manifest_bytes).context("parse delta manifest")?;

        let mut payload_data = vec![0u8; index_offset as usize - 128];
        delta_file.seek(SeekFrom::Start(128)).context("seek to payload")?;
        delta_file.read_exact(&mut payload_data).context("read payload")?;

        let mut payload_cursor = std::io::Cursor::new(&payload_data);

        for entry in &delta_manifest.files {
            let out_path = self.output_dir.join(&entry.path);
            if let Some(parent) = out_path.parent() {
                fs::create_dir_all(parent).context("create output dir")?;
            }

            match entry.action {
                DeltaAction::Reference => {
                    self.base.extract_file(&entry.path, &self.output_dir)
                        .context("extract referenced file")?;
                }
                DeltaAction::Include => {
                    let mut file_data = vec![0u8; entry.size as usize];
                    payload_cursor.read_exact(&mut file_data).context("read included file")?;
                    fs::write(&out_path, &file_data).context("write included file")?;

                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        let mut perms = fs::metadata(&out_path)?.permissions();
                        perms.set_mode(entry.mode);
                        fs::set_permissions(&out_path, perms)?;
                    }

                    #[cfg(target_os = "linux")]
                    {
                        for (key, value) in &entry.xattrs {
                            xattr::set(&out_path, key, value).ok();
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

pub struct SnapshotChain {
    archives: Vec<PathBuf>,
}

impl SnapshotChain {
    pub fn new(archive: PathBuf) -> Result<Self> {
        let mut archives = Vec::new();
        let mut current = archive;

        loop {
            let base = BaseArchive::open(&current).context("open archive in chain")?;
            archives.push(current.clone());

            if let Some(parent_hash) = &base.parent_hash {
                let parent_path = Self::find_parent_archive(parent_hash)?;
                current = parent_path;
            } else {
                break;
            }
        }

        archives.reverse();

        Ok(Self { archives })
    }

    fn find_parent_archive(parent_hash: &Blake3Hash) -> Result<PathBuf> {
        let cache_dir = dirs::home_dir()
            .expect("home dir")
            .join(".cache/vfsx/archives");

        if let Ok(entries) = fs::read_dir(&cache_dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map(|e| e == "vfsx").unwrap_or(false) {
                    let base = BaseArchive::open(&path).ok();
                    if let Some(base) = base {
                        if base.compute_hash() == *parent_hash {
                            return Ok(path);
                        }
                    }
                }
            }
        }

        anyhow::bail!("parent archive not found for hash: {}", parent_hash.to_hex())
    }

    pub fn extract(&self, output_dir: &Path) -> Result<()> {
        let mut current_base: Option<BaseArchive> = None;

        for (i, archive_path) in self.archives.iter().enumerate() {
            let base = BaseArchive::open(archive_path).context("open archive in chain")?;

            if i == 0 {
                base.extract_all(output_dir).context("extract base archive")?;
                current_base = Some(base);
            } else {
                let delta_extract = DeltaExtract::new(
                    archive_path.clone(),
                    current_base.unwrap(),
                    output_dir.to_path_buf(),
                );
                delta_extract.extract().context("extract delta in chain")?;
                current_base = Some(base);
            }
        }

        Ok(())
    }
}
