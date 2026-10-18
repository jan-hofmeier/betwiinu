#!/usr/bin/env python3

import argparse
import os
import sys
from slctools.nand import *
from slctools.boot1 import read_boot1

def extract_file(nand, entry, output_path):
    entry_full_path = f"{entry.path}{entry.name}"
    print(f"Extracting file: {entry_full_path} ({entry.size} bytes) -> {output_path}")
    parent_dir = os.path.dirname(output_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)

    clusters = entry.get_cluster_chain()
    bytes_left = entry.size
    with open(output_path, "wb") as f:
        for cluster in clusters:
            if entry.name == "scfm.img":
                data = nand.get_cluster(cluster)
            else:
                data = nand.decrypt_cluster(cluster)
            if bytes_left < len(data):
                data = data[:bytes_left]
            f.write(data)
            bytes_left -= len(data)
            if bytes_left <= 0:
                break
    return 1

def extract_directory(nand, entry, output_dir):
    entry_full_path = f"{entry.path}{entry.name}" or "/"
    print(f"Extracting folder: {entry_full_path} -> {output_dir}")
    os.makedirs(output_dir, exist_ok=True)
    file_count = 0
    dir_count = 1
    for child in entry.children():
        child_out = os.path.join(output_dir, child.name)
        if child.is_file():
            file_count += extract_file(nand, child, child_out)
        else:
            sub_files, sub_dirs = extract_directory(nand, child, child_out)
            file_count += sub_files
            dir_count += sub_dirs
    return file_count, dir_count

def extract_boot1(nand, output_path):
    print(f"Extracting boot1 -> {output_path}")
    try:
        version, image = read_boot1(nand)
    except ValueError as e:
        print(f"Error: {e}")
        sys.exit(1)
    parent_dir = os.path.dirname(output_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(image)
    print(f"Wrote boot1 v{version} ({len(image)} bytes)")

ISFSHAX_GENERATION_FIRST = 0xffff7fff
ISFSHAX_MAGIC = b"HAXX"
ISFSHAX_INFO_OFFSET = 0x3FFEC  # after header, FAT and FST

def find_isfshax_slots(nand):
    """Superblock slots used by isfshax. isfshax marks them bad in the FAT to
    keep IOSU away, so they aren't really bad - unless isfshax itself flagged
    one as bad in its info structure."""
    start = TOTAL_CLUSTER - NUM_SUPER * CLUSTER_PER_SUPER
    for slot in range(NUM_SUPER):
        cluster = start + slot * CLUSTER_PER_SUPER
        header = nand.get_cluster(cluster)
        if header[:4] != b"SFS!" or struct.unpack(">I", header[4:8])[0] < ISFSHAX_GENERATION_FIRST:
            continue
        info = read_superblock(nand, cluster)[ISFSHAX_INFO_OFFSET:ISFSHAX_INFO_OFFSET + 8]
        if info[:4] == ISFSHAX_MAGIC:
            # isfshax_slot: bad (bit 7), ecc_correctable (bit 6), slot (bits 0-5)
            used = {s & 0x3f for s in info[4:8] if not s & 0x80}
            print(f"isfshax found, its superblock slots {sorted(used)} are not counted as bad")
            return used
    return set()

def find_fat_bad_blocks(nand):
    """Blocks with clusters marked bad in the FAT of the newest superblock
    (e.g. found bad by IOSU at runtime), excluding isfshax's slots."""
    try:
        superblock = SFFS(read_superblock(nand, find_newest_superblock(nand)))
    except ValueError:
        print("No SFFS superblock found (chip not used in a Wii U yet?), only checking spare markers")
        return set()
    start = TOTAL_CLUSTER - NUM_SUPER * CLUSTER_PER_SUPER
    isfshax_clusters = {start + slot * CLUSTER_PER_SUPER + i
                        for slot in find_isfshax_slots(nand) for i in range(CLUSTER_PER_SUPER)}
    return {c // 8 for c in range(TOTAL_CLUSTER)
            if superblock.fat.get_cluster_entry(c) == FAT_CLUSTER_BAD and c not in isfshax_clusters}

def extract_bad_blocks(nand, output_path):
    print(f"Scanning for bad blocks -> {output_path}")
    num_blocks = int(getattr(nand, "blocks", 4096))
    spare_bad = {block for block in range(num_blocks) if nand.is_bad_block(block)}
    fat_bad = find_fat_bad_blocks(nand)

    parent_dir = os.path.dirname(output_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)
    with open(output_path, "w") as f:
        f.write("# Bad blocks list extracted from SLC image\n")
        for block in sorted(spare_bad | fat_bad):
            source = " ".join(name for name, s in (("spare", spare_bad), ("FAT", fat_bad)) if block in s)
            f.write(f"0x{block:04X}  # {source}\n")
    print(f"Found {len(spare_bad | fat_bad)} bad block(s): {len(spare_bad)} marked in spare, {len(fat_bad)} in FAT.")
    return len(spare_bad | fat_bad)

def find_entry_by_path(root_entry, target_path):
    cleaned = target_path.strip("/")
    if not cleaned:
        return root_entry
    parts = [p for p in cleaned.split("/") if p]
    curr = root_entry
    for part in parts:
        found = None
        for child in curr.children():
            if child.name == part:
                found = child
                break
        if not found:
            return None
        curr = found
    return curr

def find_entry_recursive(entry, target_name):
    if entry.name == target_name:
        return entry
    for child in entry.children():
        res = find_entry_recursive(child, target_name)
        if res:
            return res
    return None

def find_target_entry(root_entry, target_path):
    # 1. Try exact path match
    entry = find_entry_by_path(root_entry, target_path)
    if entry:
        return entry

    # 2. Fallback to recursive name match
    target_name = os.path.basename(target_path.strip("/"))
    if target_name:
        entry = find_entry_recursive(root_entry, target_name)
        if entry:
            return entry

    return None

def write_permissions(root_entry, output_path):
    """Writes mode/attr/uid/gid of every FST entry, so build_slc.py can repack
    the tree with exactly the metadata it had."""
    print(f"Writing FST metadata -> {output_path}")
    parent_dir = os.path.dirname(output_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)
    with open(output_path, "w") as f:
        f.write("# FST metadata extracted from SLC image: mode attr uid gid path\n")
        def walk(entry, path):
            f.write(f"0x{entry.mode:02x} 0x{entry.attr:02x} 0x{entry.uid:08x} 0x{entry.gid:04x} {path or '/'}\n")
            if not entry.is_file():
                for child in entry.children():
                    walk(child, f"{path}/{child.name}")
        walk(root_entry, "")

def main():
    parser = argparse.ArgumentParser(
        description="Extract files, folders, boot1, bad blocks or the complete filesystem from a Wii U SLC image",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Layout of the output (rebuild) directory:
  <dir>/slc/              SFFS files and folders (input for build_slc.py)
  <dir>/boot1.bin         boot1 image
  <dir>/bad_blocks.txt    bad block list
  <dir>/permissions.txt   FST metadata of every entry (complete extraction only)

Examples:
  # Extract everything from input/SLC.RAW (with input/otp.bin) into rebuild/
  python3 extract_slc.py --all

  # Only boot1 and the bad blocks (no otp.bin needed)
  python3 extract_slc.py boot1 bad_blocks

  # Specific files or folders, into rebuild/slc/...
  python3 extract_slc.py /sys/config /scfm.img

  # Explicit paths
  python3 extract_slc.py --image SLC.RAW --otp otp.bin --boot1 boot1.bin --bad-blocks bad_blocks.txt
"""
    )
    parser.add_argument("--image", "-i", default="input/SLC.RAW", help="Input SLC.RAW file (default: input/SLC.RAW)")
    parser.add_argument("--otp", "-k", default=None, help="OTP of the console the dump belongs to (default: input/otp.bin if it exists; not needed for boot1 or bad blocks)")
    parser.add_argument("--output-dir", "-o", "--output", default="rebuild", help="Rebuild directory to extract into (default: rebuild)")
    parser.add_argument("--all", "-a", "--extract-all", action="store_true", help="Extract complete SLC (all SFFS files/folders, FST metadata, boot1, bad blocks)")
    parser.add_argument("--extract", "-e", action="append", default=[], help="Specific file(s) or folder(s) to extract from SFFS")
    parser.add_argument("paths", nargs="*", help="Specific file(s), folder(s), boot1, or bad_blocks to extract")

    # Specific component overrides
    parser.add_argument("--boot1", nargs="?", const="", default=None, help="Extract boot1 (optionally to this path instead of <dir>/boot1.bin)")
    parser.add_argument("--scfm", nargs="?", const="", default=None, help="Extract scfm.img (optionally to this path instead of <dir>/slc/scfm.img)")
    parser.add_argument("--bad-blocks", nargs="?", const="", default=None, help="Extract the bad block list (optionally to this path instead of <dir>/bad_blocks.txt)")

    args = parser.parse_args()
    slc_dir = os.path.join(args.output_dir, "slc")

    otp_path = args.otp
    if otp_path is None and os.path.exists("input/otp.bin"):
        otp_path = "input/otp.bin"
    otp_key = otp_hmac = None
    if otp_path:
        print(f"Reading OTP keys from {otp_path}...")
        with open(otp_path, 'rb') as f:
            f.seek(0x170)
            otp_key = f.read(0x10)
            f.seek(0x1E0)
            otp_hmac = f.read(0x14)
    else:
        print("No otp.bin: skipping key setup (boot1/bad-blocks extraction doesn't need it; SFFS file content does).")

    print(f"Opening NAND image {args.image}...")
    nand = NANDFormatSpare(args.image)
    nand.set_keys(otp_key, otp_hmac)

    user_targets = list(args.extract) + list(args.paths)
    do_all = args.all

    # If no specific targets or components were requested, default to --all
    if not do_all and not user_targets and args.boot1 is None and args.scfm is None and args.bad_blocks is None:
        print("No specific target requested. Extracting complete SLC image...")
        do_all = True

    # Bad blocks
    if args.bad_blocks is not None or do_all or "bad_blocks" in user_targets or "bad_blocks.txt" in user_targets:
        extract_bad_blocks(nand, args.bad_blocks or os.path.join(args.output_dir, "bad_blocks.txt"))

    # Boot1
    if args.boot1 is not None or do_all or "boot1" in user_targets or "boot1.bin" in user_targets:
        extract_boot1(nand, args.boot1 or os.path.join(args.output_dir, "boot1.bin"))

    # Dedicated --scfm flag
    if args.scfm is not None:
        user_targets.append("scfm.img")

    # SFFS targets
    sffs_targets = []
    if do_all:
        sffs_targets.append("/")

    for t in user_targets:
        if t in ["boot1", "boot1.bin", "bad_blocks", "bad_blocks.txt"]:
            continue
        elif t in ["/", ".", "all", "*"]:
            if "/" not in sffs_targets:
                sffs_targets.append("/")
        else:
            if t not in sffs_targets:
                sffs_targets.append(t)

    if sffs_targets:
        if not otp_path:
            print("Error: extracting SFFS files/folders requires --otp (file content is encrypted).")
            sys.exit(1)
        print("Loading SFFS filesystem...")
        superblock_cluster = find_newest_superblock(nand)
        latest_superblock = SFFS(read_superblock(nand, superblock_cluster))
        root_entry = SFFS_entry(latest_superblock.fst, latest_superblock.fat, 0, "")

        if find_isfshax_slots(nand):
            print("Warning: this SLC has isfshax. If the console relies on it, restore a repacked image only with the latest minute - it keeps the installed isfshax, older versions overwrite it and the console bricks.")

        total_files = 0
        total_dirs = 0

        for target_path in sffs_targets:
            entry = find_target_entry(root_entry, target_path)
            if not entry:
                print(f"Error: Target '{target_path}' not found in SFFS filesystem!")
                continue

            out_path = os.path.join(slc_dir, (entry.path + entry.name).lstrip("/"))
            if args.scfm and entry.name == "scfm.img":
                out_path = args.scfm

            if entry.is_file():
                total_files += extract_file(nand, entry, out_path)
            else:
                f_count, d_count = extract_directory(nand, entry, out_path)
                total_files += f_count
                total_dirs += d_count

        if "/" in sffs_targets:
            write_permissions(root_entry, os.path.join(args.output_dir, "permissions.txt"))

        print(f"Extraction complete: {total_files} file(s), {total_dirs} directory(ies) extracted.")
    else:
        print("Extraction complete.")

if __name__ == "__main__":
    main()
