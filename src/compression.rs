use anyhow::{bail, Result};
use flate2::write::GzEncoder;
use flate2::Compression as GzCompression;
use std::io::{Read, Write};
use xz2::write::XzEncoder;
use zstd::stream::write::Encoder as ZstdEncoder;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum CompressionType {
    Zstd,
    Xz,
    Gzip,
    None,
}

impl CompressionType {
    /// Detect the compression of a payload from its magic bytes, so an
    /// archive reads the same whatever its file is called.
    pub fn sniff(data: &[u8]) -> Self {
        if data.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
            CompressionType::Zstd
        } else if data.starts_with(&[0xFD, b'7', b'z', b'X', b'Z', 0x00]) {
            CompressionType::Xz
        } else if data.starts_with(&[0x1F, 0x8B]) {
            CompressionType::Gzip
        } else {
            CompressionType::None
        }
    }

    pub fn extension(&self) -> &'static str {
        match self {
            CompressionType::Zstd => "zst",
            CompressionType::Xz => "xz",
            CompressionType::Gzip => "gz",
            CompressionType::None => "",
        }
    }

    pub fn default_level(&self) -> i32 {
        match self {
            CompressionType::Zstd => 3,
            CompressionType::Xz | CompressionType::Gzip => 6,
            CompressionType::None => 0,
        }
    }
}

pub struct Compressor {
    pub compression_type: CompressionType,
    level: i32,
}

impl Compressor {
    pub fn new(compression_type: CompressionType, level: Option<i32>) -> Self {
        let level = level.unwrap_or_else(|| compression_type.default_level());
        Self { compression_type, level }
    }

    pub fn compress(&self, input: &[u8]) -> Result<Vec<u8>> {
        match self.compression_type {
            CompressionType::Zstd => {
                let mut encoder = ZstdEncoder::new(Vec::new(), self.level)?;
                encoder.write_all(input)?;
                Ok(encoder.finish()?)
            }
            CompressionType::Xz => {
                let mut encoder = XzEncoder::new(Vec::new(), self.level.clamp(0, 9) as u32);
                encoder.write_all(input)?;
                Ok(encoder.finish()?)
            }
            CompressionType::Gzip => {
                let mut encoder =
                    GzEncoder::new(Vec::new(), GzCompression::new(self.level.clamp(0, 9) as u32));
                encoder.write_all(input)?;
                Ok(encoder.finish()?)
            }
            CompressionType::None => Ok(input.to_vec()),
        }
    }
}

/// Decompress `input`, refusing to produce more than `limit` bytes so a
/// small archive cannot expand into an unbounded allocation.
pub fn decompress(input: &[u8], limit: u64) -> Result<Vec<u8>> {
    let reader: Box<dyn Read + '_> = match CompressionType::sniff(input) {
        CompressionType::Zstd => Box::new(zstd::stream::read::Decoder::new(input)?),
        CompressionType::Xz => Box::new(xz2::read::XzDecoder::new(input)),
        CompressionType::Gzip => Box::new(flate2::read::GzDecoder::new(input)),
        CompressionType::None => Box::new(input),
    };
    let mut out = Vec::new();
    reader.take(limit.saturating_add(1)).read_to_end(&mut out)?;
    if out.len() as u64 > limit {
        bail!("payload decompresses to more than the manifest allows ({} bytes)", limit);
    }
    Ok(out)
}
