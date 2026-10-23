use std::hash::Hash;

use anyhow::{Context, Result};
use blake3;
use hex;
use std::io::{Read, Seek, SeekFrom};

pub const HASH_SIZE: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize, Hash)]
pub struct Blake3Hash(pub [u8; HASH_SIZE]);

impl Blake3Hash {
    pub fn new(bytes: &[u8]) -> Self {
        let hash = blake3::hash(bytes);
        let mut arr = [0u8; HASH_SIZE];
        arr.copy_from_slice(hash.as_bytes());
        Self(arr)
    }

    pub fn from_reader<R: Read>(reader: &mut R) -> Result<Self> {
        let mut hasher = blake3::Hasher::new();
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        Ok(Self(*hasher.finalize().as_bytes()))
    }

    pub fn from_file(path: &std::path::Path) -> Result<Self> {
        let mut file = std::fs::File::open(path)
            .with_context(|| format!("Failed to open file: {}", path.display()))?;
        Self::from_reader(&mut file)
    }

    pub fn from_file_range(path: &std::path::Path, offset: u64, length: u64) -> Result<Self> {
        let mut file = std::fs::File::open(path)
            .with_context(|| format!("Failed to open file: {}", path.display()))?;
        file.seek(SeekFrom::Start(offset))?;
        let mut hasher = blake3::Hasher::new();
        let mut buf = [0u8; 64 * 1024];
        let mut remaining = length;
        while remaining > 0 {
            let to_read = std::cmp::min(buf.len() as u64, remaining) as usize;
            let n = file.read(&mut buf[..to_read])?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            remaining -= n as u64;
        }
        Ok(Self(*hasher.finalize().as_bytes()))
    }

    pub fn as_bytes(&self) -> &[u8; HASH_SIZE] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(s: &str) -> Result<Self> {
        let bytes = hex::decode(s)?;
        if bytes.len() != HASH_SIZE {
            anyhow::bail!("Invalid hash length: expected {}, got {}", HASH_SIZE, bytes.len());
        }
        let mut arr = [0u8; HASH_SIZE];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl std::fmt::Display for Blake3Hash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

impl std::str::FromStr for Blake3Hash {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self> {
        Self::from_hex(s)
    }
}

pub fn hash_bytes(bytes: &[u8]) -> Blake3Hash {
    Blake3Hash::new(bytes)
}

pub fn hash_file(path: &std::path::Path) -> Result<Blake3Hash> {
    Blake3Hash::from_file(path)
}

pub fn compute_public_key_hash(pubkey: &[u8; 32]) -> Blake3Hash {
    Blake3Hash::new(pubkey)
}