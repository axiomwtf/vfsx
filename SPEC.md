# vfsx Format Specification
**Version:** 0.1.0
**Ownership:** vfsx is owned by AXIOM ![Axiom Logo](./axiom.svg)
---

## 1. Overview

vfsx is a signed, content-addressed virtual filesystem archive format. A single directory is packed into a `.vfsx.tar.*` archive containing a fixed-size header, tar payload, JSON manifest, JSON index, and an Ed25519 signature appended after the index.

**The output is a single file:** `dir.vfsx.tar.zst` (or `.vfsx.tar.xz`, `.vfsx.tar.gz`). No separate manifest, index, or signature files.

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
│ Payload: tar stream (GNU format)                              │
│  - Directories first (depth-first pre-order)                │
│  - Files sorted by blake3 hash (ascending)                  │
├─────────────────────────────────────────────────────────────┤
│ Manifest (JSON)                                             │
├─────────────────────────────────────────────────────────────┤
│ Index (JSON)                                                │
├─────────────────────────────────────────────────────────────┤
│ Signature (64 bytes Ed25519)                                │
│  Signed data: manifest_json || index_json                   │
└─────────────────────────────────────────────────────────────┘
```

---

## 4. Header (128 bytes, little-endian)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 | `magic` | `b"VFSX"` (0x56 0x46 0x53 0x58) |
| 4 | 2 | `version` | Format version (current: 1) |
| 6 | 2 | `reserved` | Must be 0 |
| 8 | 4 | `flags` | Bit flags (see below) |
| 12 | 8 | `timestamp` | Unix timestamp (seconds) |
| 20 | 8 | `manifest_offset` | Byte offset from start of file |
| 28 | 8 | `manifest_size` | Size of manifest JSON in bytes |
| 36 | 8 | `index_offset` | Byte offset from start of file |
| 44 | 8 | `index_size` | Size of index JSON in bytes |
| 52 | 8 | `payload_offset` | Byte offset from start of file |
| 60 | 8 | `payload_size` | Size of tar payload in bytes |
| 68 | 32 | `public_key_hash` | blake3 hash of Ed25519 public key |
| 100 | 28 | `padding` | Zero padding to 128 bytes |

### Flags (u32, bitfield)

| Bit | Name | Meaning |
|-----|------|---------|
| 0 | `HAS_SIGNATURE` | Archive is signed (always 1 in v1) |
| 1 | `IS_DELTA` | Archive is a delta (requires base) |
| 2 | `HAS_PARENT` | Parent hash field is valid |
| 3-31 | Reserved | Must be 0 |

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
      "blake3_hash": {
        "0": 1, "1": 2, "2": 3, "...": "...", "31": 42
      },
      "xattrs": {},
      "chunk_refs": [
        {
          "hash": "...same format...",
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
  "parent_hash": null,
  "created_at": 1700000000,
  "total_size": 12345,
  "total_files": 6
}
```

### Field Details

- `path`: Relative path from archive root, no leading `./`
- `mode`: Full st_mode bits (file type + permissions)
- `blake3_hash`: Serialized as a map of index → byte value by serde
- `xattrs`: Map of xattr name → raw bytes (base64 in the binary archive)
- `chunk_refs`: Always present for files; empty for directories
- `is_dir` / `is_symlink`: Type flags
- `symlink_target`: Present if `is_symlink` is true
- `base_archive_hash`: Set for delta archives referencing a base
- `parent_hash`: Set for snapshot chain archives

---

## 6. Index

The index is a JSON object stored after the manifest.

### Schema

```json
{
  "entries": {
    "a1b2c3d4e5f6...": {
      "hash": {"0":1,"1":2,...},
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

Default: Zstandard at level 3.

---

## 8. Signature

The signature is 64 bytes (Ed25519) appended after the index.

**Signed data:** `manifest_json_bytes || index_json_bytes`

**Verification:**
```rust
ed25519_dalek::VerifyingKey::from_bytes(&pubkey)?
    .verify(&signed_data, &Signature::from_bytes(&sig))?;
```

The header's `public_key_hash` (blake3 of public key) allows quick key identification without carrying the full public key.

---

## 9. Key Format

### Private Key Storage

`~/.config/vfsx/keys/identity.priv` — 32 bytes: Ed25519 seed

### Public Key Storage

`~/.config/vfsx/keys/identity.pub` — 32 bytes: raw Ed25519 public key

### Public Key Export (`key.vfsx`)

A valid vfsx archive containing:
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

## 10. Incremental Models

### 10.1 Reference + Delta (`--base`)

**Creation:**
1. Open base archive, load its manifest and index
2. Walk new directory, compute blake3 for each file
3. For each file:
   - If hash exists in base index → `action: "reference"` in delta manifest
   - Else → `action: "include"`, add to delta payload
4. Write delta archive with `IS_DELTA` flag and `base_archive_hash`

**Extraction:**
1. Open delta, read manifest
2. For each entry:
   - `reference` → extract from base archive (using base's index)
   - `include` → extract from delta payload

### 10.2 Snapshot Chain

Each archive header carries `parent_hash` (blake3 of parent archive).

**Creation:** Set `parent_hash` to hash of previous archive.

**Extraction:** Recursive — extract parent first, then apply delta.

### 10.3 Global Blob Store

`~/.cache/vfsx/blobs/<first2>/<rest>.blob`

- Directory sharding: first 2 hex chars of blake3 = subdirectory
- Content-addressed, shared across all archives
- `vfsx create` checks blob store first; if exists, reference by hash

---

## 11. CLI

```
vfsx create [DIR] [-o OUTPUT] [-c ZSTD|XZ|GZIP] [--level N] [--base ARCHIVE] [--follow-links] [--progress]
vfsx extract ARCHIVE [-C DIR] [--force] [--progress]
vfsx list ARCHIVE [--json] [--detail]
vfsx verify ARCHIVE -k KEY [--strict]
vfsx key gen [--force]
vfsx key export -o FILE [--owner NAME]
vfsx key import KEY
vfsx key show
vfsx mount ARCHIVE MOUNT_POINT [--force] [--allow-other]
```

- `-c, --compression` — compression algorithm (default: `zstd`)
- `--level N` — compression level (zstd: 1–22, xz/gzip: 1–9)
- `--base ARCHIVE` — base archive for incremental/delta creation
- `-v, --verbose` — verbose output (repeat for more verbosity)

---

## 12. Error Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Generic error |
| 2 | Invalid arguments |
| 3 | Archive not found / unreadable |
| 4 | Invalid archive format (bad magic, version) |
| 5 | Corrupted archive (hash mismatch) |
| 6 | Signature verification failed |
| 7 | Key not found / invalid |
| 8 | Base archive not found / incompatible |
| 9 | I/O error |
| 10 | Permission denied |

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

# Extract (auto-replays parent chain)
vfsx extract backup_day2.vfsx.tar.zst -C /restore
```

---

## 14. Security Considerations

- **Signing key:** Protect `~/.config/vfsx/keys/identity.priv`. Anyone with this key can forge signatures.
- **Key rotation:** `vfsx key gen --force` creates new keypair. Old archives verify with old public key.
- **Verification:** Always verify before extracting untrusted archives: `vfsx verify archive.vfsx.tar.zst -k key.vfsx`.
- **Blob store:** Content-addressed; no confidentiality. Encrypt sensitive data before archiving.

---

*End of Specification*