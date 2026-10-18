#!/usr/bin/env python3
"""boot1 (ancast image) handling for the SLC.

boot0 loads boot1 from one of two slots, each one NAND block (128 KiB) at
the start of the SLC: block 0 is the primary, block 1 the backup copy. Their
versions are recorded in the SEEPROM (boot1_params / boot1_copy_params);
syncing those with the image is left to minute when flashing.

The ancast header at 0x1A0 holds the body size, a SHA-1 of the body and the
version; the body starts at 0x200.
"""

import hashlib
import struct
from .nand import CLUSTER_SIZE

BOOT1_SLOT_SIZE = 0x20000  # one NAND block
BOOT1_SLOT_CLUSTERS = BOOT1_SLOT_SIZE // CLUSTER_SIZE
BOOT1_SLOT_BLOCKS = (0, 1)  # primary, backup

ANCAST_MAGIC = bytes.fromhex("efa282d9")
ANCAST_HEADER = 0x1A0
ANCAST_BODY = 0x200

def parse_boot1(data):
    """Validate a boot1 image; returns (version, image) with the image trimmed
    to header + body. Raises ValueError if it isn't a valid boot1."""
    if len(data) < ANCAST_BODY or data[:4] != ANCAST_MAGIC:
        raise ValueError(f"not an ancast image (magic {data[:4].hex()}, expected {ANCAST_MAGIC.hex()})")
    body_size, = struct.unpack_from(">I", data, ANCAST_HEADER + 0xC)
    body_hash = data[ANCAST_HEADER + 0x10:ANCAST_HEADER + 0x24]
    version, = struct.unpack_from(">I", data, ANCAST_HEADER + 0x24)
    end = ANCAST_BODY + body_size
    if end > BOOT1_SLOT_SIZE:
        raise ValueError(f"body size 0x{body_size:x} doesn't fit in a boot1 slot")
    if len(data) < end:
        raise ValueError(f"truncated: {len(data)} bytes, header says 0x{end:x}")
    calc = hashlib.sha1(data[ANCAST_BODY:end]).digest()
    if calc != body_hash:
        raise ValueError(f"body hash mismatch (header {body_hash.hex()}, calculated {calc.hex()})")
    return version, bytes(data[:end])

def read_boot1_slots(nand):
    """Reads both slots from an SLC; returns [(version, image) or ValueError, ...]."""
    slots = []
    for block in BOOT1_SLOT_BLOCKS:
        first = block * BOOT1_SLOT_CLUSTERS
        data = b"".join(nand.get_cluster(c) for c in range(first, first + BOOT1_SLOT_CLUSTERS))
        try:
            slots.append(parse_boot1(data))
        except ValueError as e:
            slots.append(e)
    return slots

def read_boot1(nand):
    """Returns a valid (version, image) from an SLC, preferring the primary slot.
    Prints a warning for a bad or differing slot; raises if neither is valid."""
    slots = read_boot1_slots(nand)
    for block, slot in zip(BOOT1_SLOT_BLOCKS, slots):
        if isinstance(slot, ValueError):
            print(f"Warning: boot1 slot in block {block} is invalid: {slot}")
        else:
            print(f"boot1 slot in block {block}: v{slot[0]}, hash ok")
    valid = [s for s in slots if not isinstance(s, ValueError)]
    if not valid:
        raise ValueError("no valid boot1 in either slot")
    if len(valid) == 2 and valid[0] != valid[1]:
        print(f"Warning: boot1 slots differ (v{valid[0][0]} vs v{valid[1][0]}); using block {BOOT1_SLOT_BLOCKS[0]}")
    return valid[0]

def write_boot1(nand, image, bad_blocks=()):
    """Writes a boot1 image into both slots, zero-padded to the slot size like
    on a real console. Slots on bad blocks are skipped."""
    usable = [b for b in BOOT1_SLOT_BLOCKS if b not in bad_blocks]
    if not usable:
        raise ValueError("both boot1 slots are on bad blocks")
    for block in set(BOOT1_SLOT_BLOCKS) - set(usable):
        print(f"Warning: boot1 slot in block {block} is a bad block, writing only the other slot")
    padded = image.ljust(BOOT1_SLOT_SIZE, b"\x00")
    for block in usable:
        first = block * BOOT1_SLOT_CLUSTERS
        for i in range(BOOT1_SLOT_CLUSTERS):
            nand.set_cluster(first + i, padded[i * CLUSTER_SIZE:(i + 1) * CLUSTER_SIZE])
