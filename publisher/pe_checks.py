"""Basic, read-only preflight for prebuilt Windows PE files.

This does NOT establish that an EXE is safe, correctly branded, or signed by Microsoft.
It only prevents accidentally uploading an empty, truncated, or non-PE asset.
"""
from __future__ import annotations
import hashlib
from pathlib import Path
import struct

MIN_EXE_BYTES = 10_000
MAX_EXE_BYTES = 600 * 1024 * 1024


def inspect_exe(path):
    path = Path(path)
    if not path.is_file():
        raise ValueError(f"EXE file not found: {path}")
    size = path.stat().st_size
    if size < MIN_EXE_BYTES:
        raise ValueError(
            f"EXE is only {size:,} bytes (minimum {MIN_EXE_BYTES:,}). "
            "This is often an empty/incomplete download, web page, shortcut or wrong asset. "
            "Build the actual Windows EXE and choose that file."
        )
    if size > MAX_EXE_BYTES:
        raise ValueError(f"EXE is {size:,} bytes, over the {MAX_EXE_BYTES:,} byte safety limit")
    with path.open('rb') as handle:
        head = handle.read(64)
        if len(head) != 64 or head[:2] != b'MZ':
            raise ValueError(f"{path.name} is not a Windows EXE (MZ header missing)")
        pe_offset = struct.unpack_from('<I', head, 0x3C)[0]
        if pe_offset < 64 or pe_offset + 26 > size:
            raise ValueError(f"{path.name} has an invalid Windows PE header offset")
        handle.seek(pe_offset)
        pe_head = handle.read(26)
    if pe_head[:4] != b'PE\0\0':
        raise ValueError(f"{path.name} is not a valid Windows PE executable (PE signature missing)")
    machine, section_count, _, _, _, opt_size, _ = struct.unpack_from('<HHIIIHH', pe_head, 4)
    magic = struct.unpack_from('<H', pe_head, 24)[0]
    if machine not in (0x8664, 0x14c, 0xAA64) or not 1 <= section_count <= 96 or opt_size < 96 or magic not in (0x10B, 0x20B):
        raise ValueError(f"{path.name} has an invalid/unsupported Windows PE structure")
    digest = hashlib.sha256()
    with path.open('rb') as handle:
        for block in iter(lambda: handle.read(1024*1024), b''):
            digest.update(block)
    return {'size': size, 'sha256': digest.hexdigest(), 'machine': hex(machine)}
