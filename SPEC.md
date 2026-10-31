# vfsx Format Specification
**Version:** 0.2.0
**Ownership:** vfsx is owned by AXIOM ![Axiom Logo](./axiom.svg)
---

## 1. Overview

vfsx is a signed, content-addressed virtual filesystem archive format. A single directory is packed into a `.vfsx.tar.*` archive containing a fixed-size header, tar payload, JSON manifest, JSON index, and one Ed25519 signature over every byte before it.

**The output is a single file:** `dir.vfsx.tar.zst` (or `.vfsx.tar.xz`, `.vfsx.tar.gz`). No separate manifest, index, signature, or hash files, and no external store: an archive is readable on its own (a delta also needs its base archive, named by hash).

---

## 2. File Extension

All vfsx archives use a compound extension: `.vfsx.tar.zst`, `.vfsx.tar.xz`, or `.vfsx.tar.gz`.

The `.vfsx` component is **part of the stem**, not an independent extension. For a directory `foo/`, the archive is `foo.vfsx.tar.zst`.

---

## 3. Archive Structure

```
┌─────────────────────────────────────────────────────────────┐
│ VFSX Header (fixed 128 bytes, little-endian)               │
├─────────────────────────────────────────────────────────────┤
│ Payload: compressed tar stream (GNU format)                 │
│  - Directories (depth-first pre-order), files, symlinks     │
│  - A file whose content is already stored is not repeated  │
├─────────────────────────────────────────────────────────────┤
│ Manifest (JSON)                                             │
├─────────────────────────────────────────────────────────────┤
│ Index (JSON)                                                │
├─────────────────────────────────────────────────────────────┤
│ Signature (64 bytes Ed25519)                                │
│  Signed data: every byte from offset 0 to the signature    │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Header (128 bytes, little-endian)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | `magic` | `b"VFSX"` (0x56 0x46 0x53 0x58) |
| 4 | 2 | `version` | Format version (current: 2) |
| 6 | 4 | `flags` | Bit flags (see below) |
| 10 | 8 | `timestamp` | Unix timestamp (seconds) |
| 18 | 8 | `manifest_offset` | Byte offset from start of file |
| 26 | 8 | `manifest_size` | Size of manifest JSON in bytes |
| 34 | 8 | `index_offset` | Byte offset from start of file |
| 42 | 8 | `index_size` | Size of index JSON in bytes |
| 50 | 8 | `payload_offset` | Byte offset from start of file |
| 58 | 8 | `payload_size` | Size of tar payload in bytes |
| 66 | 32 | `public_key_hash` | blake3 hash of Ed25519 public key |
| 98 | 30 | `padding` | Zero padding to 128 bytes |

### Flags (u32, bitfield)

| Bit | Name | Meaning |
|-----|------|---------|
| 0 | `HAS_SIGNATURE` | Archive is signed (always 1 in v1) |
| 1 | `IS_DELTA` | Archive is a delta (requires base) |
| 2-31 | Reserved | Must be 0 |

Sections are contiguous: `payload_offset` is 128, the manifest follows the payload, the index follows the manifest, and the file ends exactly 64 bytes (the signature) after the index. Readers reject any other layout, including trailing bytes.

---

## 5. Manifest

The manifest is a JSON object stored after the tar payload.

### Schema

```json
{
  "entries": [
    {
      "path": "relative/path",
      "mode": 33188,
      "uid": 1000,
      "gid": 1000,
      "mtime": 1700000000,
      "mtime_nsec": 0,
      "size": 12345,
      "blake3_hash": "a1b2c3d4e5f6...",
      "xattrs": {},
      "chunk_refs": [
        {
          "hash": "a1b2c3d4e5f6...",
          "offset": 128,
          "length": 12345,
          "compression": 0
        }
      ],
      "is_dir": false,
      "is_symlink": false,
      "symlink_target": null
    }
  ],
  "base_archive_hash": null,
  "created_at": 1700000000,
  "total_size": 12345,
  "total_files": 6
}
```

### Field Details

- `path`: Relative path from archive root, no leading `./`
- `mode`: Full st_mode bits (file type + permissions)
- `blake3_hash`: 64-char lowercase hex; all zeros for directories and symlinks
- `xattrs`: Map of xattr name → raw bytes (base64 in the binary archive)
- `chunk_refs`: One entry for files; empty for directories and symlinks. `offset` is the start of the file's data in the decompressed payload. `offset: 0, length: 0` means the data is in the base archive (inline data never starts at 0)
- `is_dir` / `is_symlink`: Type flags
- `symlink_target`: Present if `is_symlink` is true
- `base_archive_hash`: blake3 of the whole base archive file; set only when the archive references it

---

## 6. Index

The index is a JSON object stored after the manifest.

### Schema

```json
{
  "entries": {
    "a1b2c3d4e5f6...": {
      "hash": "a1b2c3d4e5f6...",
      "offset": 128,
      "length": 12345,
      "compression": 0,
      "reference_count": 1
    }
  }
}
```

- Key: 64-char hex blake3 hash
- `offset`: Byte offset from start of tar payload
- `length`: Uncompressed length in bytes
- `compression`: Same enum as header
- `reference_count`: Number of times this blob is referenced

---

## 7. Compression

### Enum Values

| Value | Algorithm | Flag |
|-------|-----------|------|
| 0 | Zstandard | `--zst` / `-c zstd` |
| 1 | LZMA2 (xz) | `--xz` / `-c xz` |
| 2 | Gzip | `--gz` / `-c gzip` |

Default: Zstandard at level 3. Readers detect the compression from the payload's magic bytes, not from the file name.

---

## 8. Signature

The signature is 64 bytes (Ed25519) and is the last thing in the file.

**Signed data:** every byte of the file before the signature — header, payload, manifest and index.

**Verification:**
```rust
ed25519_dalek::VerifyingKey::from_bytes(&pubkey)?
    .verify_strict(&file[..file.len() - 64], &Signature::from_bytes(&sig))?;
```

The header's `public_key_hash` (blake3 of public key) identifies the signing key; verification fails if it does not match the key used.

---

## 9. Key Format

### Private Key Storage

`~/.config/vfsx/keys/identity.priv` — 32 bytes: Ed25519 seed

### Public Key Storage

`~/.config/vfsx/keys/identity.pub` — 32 bytes: raw Ed25519 public key

### Imported Keys

`~/.config/vfsx/keys/trusted/<key_id>.pub` — 32 bytes each, written by `vfsx key import`. `verify` and `extract` look up the archive's key id here (and the local identity) when no `-k` is given.

### Public Key Export (`key.vfsx`)

A valid vfsx archive, signed by the key it contains, containing:
```
key.vfsx (vfsx archive)
├── pubkey.bin        # 32 bytes raw public key
└── metadata.json     # {
                       #   "algorithm": "Ed25519",
                       #   "created_timestamp": 1700000000,
                       #   "key_id": "blake3(pubkey) as hex",
                       #   "owner": "user@host"
                       # }
```

The `key_id` is the blake3 hash of the raw public key (32 bytes → 64 hex chars).

---

## 10. Incremental (Reference + Delta)

**Creation** (`vfsx create DIR --base BASE`):
1. Open the base archive and load its index
2. For each file, if the base stores data with the same blake3 hash and length, write a chunk ref with `offset: 0, length: 0` instead of the data
3. If any file was referenced, set `IS_DELTA` and `base_archive_hash` = blake3 of the base archive file

**Extraction** (`vfsx extract DELTA --base BASE`):
1. Check blake3 of `BASE` equals `base_archive_hash` (the manifest is signed, so this binds the base)
2. Referenced files are read from the base archive by hash; all others from the delta

A base must itself store the data it is referenced for; deltas do not chain.

---

## 11. CLI

```
vfsx create [DIR] [-o OUTPUT] [-c zstd|xz|gzip] [--level N] [--base ARCHIVE] [--follow-links]
vfsx extract ARCHIVE [-C DIR] [--force] [--base ARCHIVE] [-k KEY]
vfsx list ARCHIVE [--json] [--detail]
vfsx verify ARCHIVE [-k KEY]
vfsx key gen [--force]
vfsx key export [-o FILE] [--owner NAME]
vfsx key import KEY
vfsx key show
```

- `-c, --compression` — compression algorithm (default: `zstd`)
- `--level N` — compression level (zstd: 1–22, xz/gzip: 1–9)
- `--base ARCHIVE` — base archive for delta creation and extraction
- `-k, --key KEY` — public key archive; defaults to the local identity or an imported key matching the archive

---

## 12. Extraction

Extraction is driven by the manifest:
- Every path must be relative with only normal components (no `/`, `..`, `.`, or empty paths); duplicates are rejected
- Nothing is written through a symlink: an existing symlink or non-directory on the way to a path is an error, and symlinks from the archive are created after all files
- Every file is checked against its blake3 hash before it is written
- Permissions are restored as `mode & 0777` (no setuid/setgid/sticky); mtime and xattrs are restored where possible
- Existing files are only replaced with `--force`; existing directories are never replaced
- The decompressed payload may not exceed the size the manifest describes

Exit status is 0 on success and 1 on any error (2 for invalid arguments).

---

## 13. Examples

### Create and Verify

```bash
# Create archive (generates key on first run)
vfsx create ./project -o project.vfsx.tar.zst

# Export public key
vfsx key export -o mykey.vfsx --owner "alice@laptop"

# Verify
vfsx verify project.vfsx.tar.zst -k mykey.vfsx
# → ✓ Signature verified successfully
#   Files verified: N
```

### Incremental Backup

```bash
# Full backup
vfsx create /home/user -o backup.vfsx.tar.zst

# Incremental (delta from base)
vfsx create /home/user -o backup_day2.vfsx.tar.zst --base backup.vfsx.tar.zst

# Extract the delta with its base
vfsx extract backup_day2.vfsx.tar.zst -C /restore --base backup.vfsx.tar.zst
```

---

## 14. Security Considerations

- **Signing key:** Protect `~/.config/vfsx/keys/identity.priv`. Anyone with this key can forge signatures.
- **Key rotation:** `vfsx key gen --force` creates new keypair. Old archives verify with old public key.
- **Verification:** `vfsx extract -k key.vfsx` verifies the signature before writing anything; without a known key it warns and only checks file hashes.
- **Confidentiality:** Archives are signed, not encrypted. Encrypt sensitive data before archiving.

---

*End of Specification*