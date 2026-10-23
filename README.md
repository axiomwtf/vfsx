<p align="center">
  <img src="./axiom.svg" alt="Axiom" width="320">
</p>

# vfsx

**One directory in. One verified archive out.**

vfsx is a **signed, content-addressed virtual filesystem archive** by [Axiom](https://github.com/axiomwtf). A single directory is packed into a `.vfsx.tar.*` archive with an Ed25519 signature, embedded manifest, and content-addressed index. Verify integrity with one command — no separate signature or manifest files.

> **Status:** `0.1.0` — early development.

## Why

- **One output, always verified.** The result is a single `.vfsx.tar.*` file. Every archive carries its manifest, index, and an Ed25519 signature. Verification is a single command.
- **No separate tooling.** Manifest, index, and signature are packed inside the archive. Nothing leaks to disk.
- **Keys on first run.** `vfsx create` auto-generates your Ed25519 identity at `~/.config/vfsx/keys/`. Export the public key as a `.vfsx` archive for others to verify yours.
- **Extended attributes preserved.** xattrs, permissions, mtime — all captured and restored.
- **Incremental support.** Create delta archives with `--base`, chain snapshots, and deduplicate via a global blob store.

## Example

```bash
# First run — generates your signing key automatically
vfsx create ./myproject -o myproject.vfsx.tar.zst

# Export your public key for others to verify your archives
vfsx key export -o mykey.vfsx --owner "me@laptop"

# Someone else verifies your archive
vfsx verify myproject.vfsx.tar.zst -k mykey.vfsx

# Extract
vfsx extract myproject.vfsx.tar.zst -C /restore/here

# List contents
vfsx list myproject.vfsx.tar.zst --json
```

## Compression

| Flag | Algorithm | Default Level |
|------|-----------|---------------|
| `--zst` | Zstandard | 3 (default) |
| `--xz` | LZMA2 | 6 |
| `--gz` | Gzip | 6 |

Override level: `vfsx create dir -o out.vfsx.tar.zst --zst --level 19`

## Archive Format

```
┌─────────────────────────────────────┐
│ VFSX Header (fixed 128 bytes)       │
│  Magic: "VFSX" (4 bytes)            │
│  Version: u16                       │
│  Flags: u32                         │
│  Timestamp: u64 (unix seconds)      │
│  Manifest offset/size: u64×2        │
│  Index offset/size: u64×2        │
│  Payload offset/size: u64×2        │
│  Pubkey hash: 32 bytes (blake3)     │
│  (rest: zero padding)               │
├─────────────────────────────────────┤
│ Payload: tar stream                  │
│  Directories first, then files      │
│  Files sorted by blake3 hash        │
├─────────────────────────────────────┤
│ Manifest (JSON)                      │
│  File entries: path, mode, uid, gid │
│  mtime, mtime_nsec, size, blake3    │
│  xattrs, chunk_refs, is_dir, symlink│
├─────────────────────────────────────┤
│ Index (JSON)                         │
│  blake3_hash → (offset, len, comp)  │
├─────────────────────────────────────┤
│ Signature (64 bytes Ed25519)        │
│  Over manifest_json + index_json    │
└─────────────────────────────────────┘
```

The `.vfsx` in the filename is **part of the stem**, not just an extension: `dir.vfsx.tar.zst`. This distinguishes vfsx archives from plain tarballs.

## Incremental

### Reference + Delta

```bash
vfsx create ./updated -o update.vfsx.tar.zst --base original.vfsx.tar.zst
```

The delta archive references unchanged files by hash from the base. Extraction pulls referenced files from the base archive automatically.

### Snapshot Chain

Each archive header carries a `parent_hash`. `vfsx extract` replays the chain from the oldest parent to newest.

### Global Blob Store

`~/.cache/vfsx/blobs/<first2>/<rest>.blob` — content-addressed storage shared across all archives. Identical files are never stored twice.

## Key Management

```
~/.config/vfsx/keys/
├── identity.pub   # 32 bytes raw Ed25519 public key
└── identity.priv  # 32 bytes seed (signing key)
```

```bash
vfsx key gen             # generate keypair (auto-runs on first create)
vfsx key export -o mykey.vfsx --owner "alice@laptop"  # export as vfsx archive
vfsx key import mykey.vfsx   # import pubkey for verification
vfsx key show           # show public key + hash
```

`key.vfsx` is a valid vfsx archive containing:
- `pubkey.bin` — raw 32-byte Ed25519 public key
- `metadata.json` — `{ "algorithm": "Ed25519", "key_id": "<blake3>", "created_timestamp": N, "owner": "..." }`

## CLI Reference

```
vfsx create [DIR] [-o OUTPUT] [-c ZSTD|XZ|GZIP] [--level N] [--base ARCHIVE] [--follow-links] [--progress]
vfsx extract ARCHIVE [-C DIR] [--force] [--progress]
vfsx list ARCHIVE [--json] [--detail]
vfsx verify ARCHIVE -k KEY [--strict]
vfsx key gen [--force]
vfsx key export -o FILE [--owner NAME]
vfsx key import KEY
vfsx key show
vfsx mount ARCHIVE MOUNT_POINT [--force] [--allow-other]   # requires --features fuse
```

**Options:**
- `-c, --compression` — compression algorithm (default: `zstd`)
- `--level N` — compression level (zstd: 1–22, xz/gzip: 1–9)
- `--base ARCHIVE` — base archive for incremental/delta creation
- `-v, --verbose` — verbose output (repeat for more verbosity)

## Building from Source

```bash
cargo build --release
```

Rust edition 2024. The binary is `target/release/vfsx`.

## Spec

The full format specification is in [`SPEC.md`](./SPEC.md).

## License

MPL-2.0