pub mod blobstore;
pub mod compression;
pub mod format;
pub mod hash;
pub mod hashjson;
pub mod incremental;
pub mod keys;
pub mod cli;
pub mod verify;
pub use blobstore::{
    ensure_blob_store, get, put, put_file, deduplicate, deduplicate_file, read_blob, gc,
    list_all_blobs, blob_size,
};

pub use compression::{CompressionType, Compressor, Decompressor};
pub use format::{
    ArchiveReader, ArchiveWriter, ChunkRef, FileEntry, Index, IndexEntry, Manifest,
    VfsxHeader, HEADER_SIZE, MAGIC, VERSION, SIGNATURE_SIZE, SIG_MAGIC, KeyPair,
};
pub use hash::{Blake3Hash, HASH_SIZE, compute_public_key_hash, hash_bytes, hash_file};
pub use hashjson::{create_hash_json, verify_hash_json, HashJsonData, HashJsonFile, sidecar_path};
pub use keys::{KeyStorage, KeyMetadata, sign_data, verify_signature, get_public_key_hash, export_public_key, import_public_key};
pub use incremental::{
    BaseArchive, Compression, DeltaArchive, DeltaCreate, DeltaExtract, DeltaAction,
    DeltaFileEntry, DeltaManifest, SnapshotChain,
};
pub use verify::{VerificationResult, verify_archive, verify_extracted_archive, sign_archive};
