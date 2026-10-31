<p align="center">
  <img src="./axiom.svg" alt="Axiom" width="320">
</p>

# vfsx

**One directory in. One verified archive out.**

vfsx is a **signed, content-addressed virtual filesystem archive** by [Axiom](https://github.com/axiomwtf). A single directory is packed into a `.vfsx.tar.*` archive with an Ed25519 signature, embedded manifest, and content-addressed index. Verify integrity with one command — no separate signature or manifest files.

> **Status:** `0.2.0` — early development.

## Why

- **One output, always verified.** The result is a single `.vfsx.tar.*` file. Every archive carries its manifest, index, and an Ed25519 signature. Verification is a single command.
- **No sidecars.** Manifest, index, and signature are packed inside the archive. Nothing else is written next to it, and nothing outside it is needed to read it.
- **Keys on first run.** `vfsx create` auto-generates your Ed25519 identity at `~/.config/vfsx/keys/`. Export the public key as a `.vfsx` archive for others to verify yours.
- **Extended attributes preserved.** xattrs, permissions, mtime and symlinks — all captured and restored.
- **Deduplicated.** Identical files inside an archive are stored once.
- **Incremental support.** Create delta archives with `--base` that store only what the base doesn't already hold.
- **Safe to extract.** Paths that would leave the destination are refused, nothing is written through a symlink, and every file is checked against its hash.

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
| `-c zstd` | Zstandard | 3 (default) |
| `-c xz` | LZMA2 | 6 |
| `-c gzip` | Gzip | 6 |

Override level: `vfsx create dir -o out.vfsx.tar.zst -c zstd --level 19`

The compression is read from the payload itself, so a renamed archive still opens.

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
│ Payload: compressed tar stream      │
│  Directories, files, then symlinks  │
│  Identical files stored once        │
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
│  Over every byte before it          │
└─────────────────────────────────────┘
```

The `.vfsx` in the filename is **part of the stem**, not just an extension: `dir.vfsx.tar.zst`. This distinguishes vfsx archives from plain tarballs.

## Incremental

```bash
vfsx create ./updated -o update.vfsx.tar.zst --base original.vfsx.tar.zst
vfsx extract update.vfsx.tar.zst -C /restore --base original.vfsx.tar.zst
```

The delta archive stores only files the base doesn't hold and references the rest by hash. Its signed manifest records the blake3 hash of the base archive, so extraction refuses any other base.

## Key Management

```
~/.config/vfsx/keys/
├── identity.pub   # 32 bytes raw Ed25519 public key
├── identity.priv  # 32 bytes seed (signing key, mode 0600)
└── trusted/       # imported public keys, <key_id>.pub
```

```bash
vfsx key gen             # generate keypair (auto-runs on first create)
vfsx key export -o mykey.vfsx --owner "alice@laptop"  # export as vfsx archive
vfsx key import mykey.vfsx   # trust a key: verify/extract find it without -k
vfsx key show           # show public key + hash
```

`key.vfsx` is a valid vfsx archive, signed by the key it carries, containing:
- `pubkey.bin` — raw 32-byte Ed25519 public key
- `metadata.json` — `{ "algorithm": "Ed25519", "key_id": "<blake3>", "created_timestamp": N, "owner": "..." }`

## CLI Reference

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

**Options:**
- `-c, --compression` — compression algorithm (default: `zstd`)
- `--level N` — compression level (zstd: 1–22, xz/gzip: 1–9)
- `--base ARCHIVE` — base archive for delta creation and extraction
- `-k, --key KEY` — public key archive; without it, your own key or an imported key matching the archive is used. `extract` warns and skips the signature check if no key is found.

## Building from Source

```bash
cargo build --release
```

Rust edition 2024. The binary is `target/release/vfsx`.

## Spec

The full format specification is in [`SPEC.md`](./SPEC.md).

## License

MPL-2.0