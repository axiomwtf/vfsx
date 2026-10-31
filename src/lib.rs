pub mod cli;
pub mod compression;
pub mod format;
pub mod hash;
pub mod keys;
pub mod verify;

pub use compression::{CompressionType, Compressor};
pub use format::{
    ArchiveReader, ArchiveWriter, ChunkRef, FileEntry, Index, IndexEntry, KeyPair, Manifest, VfsxHeader,
    HEADER_SIZE, MAGIC, SIGNATURE_SIZE, VERSION,
};
pub use hash::{Blake3Hash, HASH_SIZE};
pub use keys::{read_key_archive, KeyMetadata, KeyStorage};
pub use verify::{verify_archive, VerificationResult};
