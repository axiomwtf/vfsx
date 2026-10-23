use anyhow::Result;
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
    pub fn from_extension(path: &std::path::Path) -> Self {
        let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
        match ext {
            "zst" => CompressionType::Zstd,
            "xz" => CompressionType::Xz,
            "gz" => CompressionType::Gzip,
            _ => CompressionType::None,
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
}

pub struct Compressor {
    pub compression_type: CompressionType,
    level: i32,
}

impl Compressor {
    pub fn new(compression_type: CompressionType, level: Option<i32>) -> Self {
        let level = level.unwrap_or_else(|| match compression_type {
            CompressionType::Zstd => 3,
            CompressionType::Xz => 6,
            CompressionType::Gzip => 6,
            CompressionType::None => 0,
        });
        Self { compression_type, level }
    }

    pub fn compress(&self, input: &[u8]) -> Result<Vec<u8>> {
        match self.compression_type {
            CompressionType::Zstd => self.compress_zstd(input),
            CompressionType::Xz => self.compress_xz(input),
            CompressionType::Gzip => self.compress_gzip(input),
            CompressionType::None => Ok(input.to_vec()),
        }
    }

    pub fn compress_to_writer<W: Write>(&self, input: &[u8], mut writer: W) -> Result<()> {
        match self.compression_type {
            CompressionType::Zstd => {
                let mut encoder = ZstdEncoder::new(&mut writer, self.level)?;
                encoder.write_all(input)?;
                encoder.finish()?;
            }
            CompressionType::Xz => {
                let level: u32 = self.level.try_into().unwrap_or(6);
                let mut encoder = XzEncoder::new(&mut writer, level);
                encoder.write_all(input)?;
                encoder.finish()?;
            }
            CompressionType::Gzip => {
                let mut encoder = GzEncoder::new(&mut writer, GzCompression::new(self.level as u32));
                encoder.write_all(input)?;
                encoder.finish()?;
            }
            CompressionType::None => {
                writer.write_all(input)?;
            }
        }
        Ok(())
    }

    fn compress_zstd(&self, input: &[u8]) -> Result<Vec<u8>> {
        let mut encoder = ZstdEncoder::new(Vec::new(), self.level)?;
        encoder.write_all(input)?;
        Ok(encoder.finish()?)
    }

    fn compress_xz(&self, input: &[u8]) -> Result<Vec<u8>> {
        let level: u32 = self.level.try_into().unwrap_or(6);
        let mut encoder = XzEncoder::new(Vec::new(), level);
        encoder.write_all(input)?;
        Ok(encoder.finish()?)
    }

    fn compress_gzip(&self, input: &[u8]) -> Result<Vec<u8>> {
        let mut encoder = GzEncoder::new(Vec::new(), GzCompression::new(self.level as u32));
        encoder.write_all(input)?;
        Ok(encoder.finish()?)
    }
}

pub struct Decompressor {
    compression_type: CompressionType,
}

impl Decompressor {
    pub fn new(compression_type: CompressionType) -> Self {
        Self { compression_type }
    }

    pub fn decompress(&self, input: &[u8]) -> Result<Vec<u8>> {
        match self.compression_type {
            CompressionType::Zstd => self.decompress_zstd(input),
            CompressionType::Xz => self.decompress_xz(input),
            CompressionType::Gzip => self.decompress_gzip(input),
            CompressionType::None => Ok(input.to_vec()),
        }
    }

    pub fn decompress_from_reader<R: Read>(&self, mut reader: R) -> Result<Vec<u8>> {
        match self.compression_type {
            CompressionType::Zstd => {
                let mut decoder = zstd::stream::read::Decoder::new(reader)?;
                let mut out = Vec::new();
                decoder.read_to_end(&mut out)?;
                Ok(out)
            }
            CompressionType::Xz => {
                let mut decoder = xz2::read::XzDecoder::new(reader);
                let mut out = Vec::new();
                decoder.read_to_end(&mut out)?;
                Ok(out)
            }
            CompressionType::Gzip => {
                let mut decoder = flate2::read::GzDecoder::new(reader);
                let mut out = Vec::new();
                decoder.read_to_end(&mut out)?;
                Ok(out)
            }
            CompressionType::None => {
                let mut out = Vec::new();
                reader.read_to_end(&mut out)?;
                Ok(out)
            }
        }
    }

    fn decompress_zstd(&self, input: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = zstd::stream::read::Decoder::new(input)?;
        let mut out = Vec::new();
        decoder.read_to_end(&mut out)?;
        Ok(out)
    }

    fn decompress_xz(&self, input: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = xz2::read::XzDecoder::new(input);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out)?;
        Ok(out)
    }

    fn decompress_gzip(&self, input: &[u8]) -> Result<Vec<u8>> {
        let mut decoder = flate2::read::GzDecoder::new(input);
        let mut out = Vec::new();
        decoder.read_to_end(&mut out)?;
        Ok(out)
    }
}