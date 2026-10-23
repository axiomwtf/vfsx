use anyhow::{Context, Result};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use crate::hash::Blake3Hash;

pub const BLOB_STORE_DIR: &str = ".cache/vfsx/blobs";

fn blob_store_root() -> PathBuf {
    dirs::home_dir()
        .expect("could not find home directory")
        .join(BLOB_STORE_DIR)
}

fn blob_path(hash: &Blake3Hash) -> PathBuf {
    let hex = hash.to_hex();
    let (first2, rest) = hex.split_at(2);
    blob_store_root().join(first2).join(format!("{}.blob", rest))
}

pub fn ensure_blob_store() -> Result<PathBuf> {
    let root = blob_store_root();
    fs::create_dir_all(&root).context("create blob store root")?;
    Ok(root)
}

pub fn get(hash: &Blake3Hash) -> Result<Option<PathBuf>> {
    let path = blob_path(hash);
    if path.exists() {
        Ok(Some(path))
    } else {
        Ok(None)
    }
}

pub fn put(hash: &Blake3Hash, data: &[u8]) -> Result<()> {
    let path = blob_path(hash);
    if path.exists() {
        return Ok(());
    }
    fs::create_dir_all(path.parent().unwrap()).context("create blob subdir")?;
    let mut file = fs::File::create(&path).context("create blob file")?;
    file.write_all(data).context("write blob data")?;
    Ok(())
}

pub fn put_file(hash: &Blake3Hash, src_path: &Path) -> Result<()> {
    let path = blob_path(hash);
    if path.exists() {
        return Ok(());
    }
    fs::create_dir_all(path.parent().unwrap()).context("create blob subdir")?;
    fs::copy(src_path, &path).context("copy file to blob store")?;
    Ok(())
}

pub fn deduplicate(hash: &Blake3Hash, data: &[u8]) -> Result<bool> {
    if get(hash)?.is_some() {
        return Ok(true);
    }
    put(hash, data)?;
    Ok(false)
}

pub fn deduplicate_file(hash: &Blake3Hash, src_path: &Path) -> Result<bool> {
    if get(hash)?.is_some() {
        return Ok(true);
    }
    put_file(hash, src_path)?;
    Ok(false)
}

pub fn read_blob(hash: &Blake3Hash) -> Result<Vec<u8>> {
    let path = blob_path(hash);
    let mut file = fs::File::open(&path).context("open blob file")?;
    let mut data = Vec::new();
    file.read_to_end(&mut data).context("read blob data")?;
    Ok(data)
}

pub fn gc(referenced_hashes: &[Blake3Hash]) -> Result<usize> {
    let root = blob_store_root();
    if !root.exists() {
        return Ok(0);
    }
    let mut referenced_set = std::collections::HashSet::new();
    for h in referenced_hashes {
        referenced_set.insert(h.to_hex());
    }
    let mut removed = 0;
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        let subdir = entry.path();
        if !subdir.is_dir() {
            continue;
        }
        for blob_entry in fs::read_dir(&subdir)? {
            let blob_entry = blob_entry?;
            let blob_path = blob_entry.path();
            if !blob_path.is_file() {
                continue;
            }
            let file_name = blob_entry.file_name();
            let file_name_str = file_name.to_string_lossy();
            if !file_name_str.ends_with(".blob") {
                continue;
            }
            let hash_hex = format!("{}{}", subdir.file_name().unwrap().to_string_lossy(), &file_name_str[..file_name_str.len() - 5]);
            if !referenced_set.contains(&hash_hex) {
                fs::remove_file(&blob_path).context("remove unreferenced blob")?;
                removed += 1;
            }
        }
    }
    Ok(removed)
}

pub fn list_all_blobs() -> Result<Vec<Blake3Hash>> {
    let root = blob_store_root();
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut blobs = Vec::new();
    for entry in fs::read_dir(&root)? {
        let entry = entry?;
        let subdir = entry.path();
        if !subdir.is_dir() {
            continue;
        }
        for blob_entry in fs::read_dir(&subdir)? {
            let blob_entry = blob_entry?;
            let blob_path = blob_entry.path();
            if !blob_path.is_file() {
                continue;
            }
            let file_name = blob_entry.file_name();
            let file_name_str = file_name.to_string_lossy();
            if !file_name_str.ends_with(".blob") {
                continue;
            }
            let hash_hex = format!("{}{}", subdir.file_name().unwrap().to_string_lossy(), &file_name_str[..file_name_str.len() - 5]);
            if let Ok(hash) = Blake3Hash::from_hex(&hash_hex) {
                blobs.push(hash);
            }
        }
    }
    Ok(blobs)
}

pub fn blob_size(hash: &Blake3Hash) -> Result<u64> {
    let path = blob_path(hash);
    let metadata = fs::metadata(&path).context("get blob metadata")?;
    Ok(metadata.len())
}