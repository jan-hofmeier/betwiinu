#!/usr/bin/env python3

import argparse
import os
import sys
from nand import *

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
    print(f"Extracting boot1.bin (clusters 0-0x3f) -> {output_path}")
    parent_dir = os.path.dirname(output_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)
    with open(output_path, "wb") as f:
        for cluster in range(0, 0x40):
            f.write(nand.get_cluster(cluster))

def extract_bad_blocks(nand, output_path):
    print(f"Scanning for bad blocks -> {output_path}")
    bad_blocks = []
    num_blocks = int(getattr(nand, "blocks", 4096))
    for block in range(num_blocks):
        if nand.is_bad_block(block):
            bad_blocks.append(block)

    parent_dir = os.path.dirname(output_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)
    with open(output_path, "w") as f:
        f.write("# Bad blocks list extracted from SLC image\n")
        for block in bad_blocks:
            f.write(f"0x{block:04X}\n")
    print(f"Found {len(bad_blocks)} bad block(s).")
    return len(bad_blocks)

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

def resolve_output_path(base_dir, rel_path, is_file=False, is_single_target=False):
    if not rel_path:
        return base_dir
    if is_single_target and base_dir != ".":
        # If user specified a file-like output_dir path (e.g. -o /tmp/cos.xml) for a single file target
        if is_file and os.path.splitext(base_dir)[1] != "" and not os.path.isdir(base_dir):
            return base_dir
    return os.path.join(base_dir, rel_path)

def main():
    parser = argparse.ArgumentParser(
        description="Extract files, folders, boot1, or complete filesystem from a Wii U SLC image",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Examples:
  # Extract complete SLC (all files/folders, boot1, bad blocks) to current directory
  python extract_slc.py --image SLC.RAW --otp otp.bin --all

  # Extract complete SLC to a specific output directory
  python extract_slc.py --image SLC.RAW --otp otp.bin --all -o ./extracted_slc

  # Extract specific files or folders
  python extract_slc.py --image SLC.RAW --otp otp.bin -e /sys/config -o ./extracted_slc
  python extract_slc.py --image SLC.RAW --otp otp.bin /sys/config /scfm.img boot1

  # Legacy / raw component extraction
  python extract_slc.py --image SLC.RAW --otp otp.bin --boot1 boot1.bin --scfm scfm.img --bad-blocks bad_blocks.txt
"""
    )
    parser.add_argument("--image", "-i", required=True, help="Input SLC.RAW file")
    parser.add_argument("--otp", "-k", required=False, default=None, help="OTP bin file containing keys (not needed for --boot1 or --bad-blocks only, since those aren't encrypted)")
    parser.add_argument("--output-dir", "-o", "--output", default=".", help="Base directory for extracted files/folders (default: .)")
    parser.add_argument("--all", "-a", "--extract-all", action="store_true", help="Extract complete SLC (all SFFS files/folders, boot1, bad blocks)")
    parser.add_argument("--extract", "-e", action="append", default=[], help="Specific file(s) or folder(s) to extract from SFFS")
    parser.add_argument("paths", nargs="*", help="Specific file(s), folder(s), boot1, or bad_blocks to extract")

    # Specific component overrides
    parser.add_argument("--boot1", nargs="?", const="boot1.bin", default=None, help="Output path for boot1.bin (clusters 0-0x3f)")
    parser.add_argument("--scfm", nargs="?", const="scfm.img", default=None, help="Output path for scfm.img")
    parser.add_argument("--bad-blocks", nargs="?", const="bad_blocks.txt", default=None, help="Output path for bad blocks list")

    args = parser.parse_args()

    otp_key = otp_hmac = None
    if args.otp:
        print("Reading OTP keys...")
        with open(args.otp, 'rb') as f:
            f.seek(0x170)
            otp_key = f.read(0x10)
            f.seek(0x1E0)
            otp_hmac = f.read(0x14)
    else:
        print("No --otp given: skipping key setup (boot1/bad-blocks extraction doesn't need it; SFFS file content does).")

    print("Opening NAND image...")
    nand = NANDFormatSpare(args.image)
    nand.set_keys(otp_key, otp_hmac)

    user_targets = list(args.extract) + list(args.paths)
    do_all = args.all

    # If no specific targets or components were requested, default to --all
    if not do_all and not user_targets and args.boot1 is None and args.scfm is None and args.bad_blocks is None:
        print("No specific target requested. Extracting complete SLC image...")
        do_all = True

    # Bad blocks
    if args.bad_blocks is not None:
        extract_bad_blocks(nand, args.bad_blocks)
    elif do_all or "bad_blocks" in user_targets or "bad_blocks.txt" in user_targets:
        extract_bad_blocks(nand, os.path.join(args.output_dir, "bad_blocks.txt"))

    # Boot1
    if args.boot1 is not None:
        extract_boot1(nand, args.boot1)
    elif do_all or "boot1" in user_targets or "boot1.bin" in user_targets:
        extract_boot1(nand, os.path.join(args.output_dir, "boot1.bin"))

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
        if not args.otp:
            print("Error: extracting SFFS files/folders requires --otp (file content is encrypted).")
            sys.exit(1)
        print("Loading SFFS filesystem...")
        superblock_cluster = find_newest_superblock(nand)
        latest_superblock = SFFS(read_superblock(nand, superblock_cluster))
        root_entry = SFFS_entry(latest_superblock.fst, latest_superblock.fat, 0, "")

        is_single_target = (len(sffs_targets) == 1 and not do_all)
        total_files = 0
        total_dirs = 0

        for target_path in sffs_targets:
            entry = find_target_entry(root_entry, target_path)
            if not entry:
                print(f"Error: Target '{target_path}' not found in SFFS filesystem!")
                continue

            rel_path = (entry.path + entry.name).lstrip("/")
            out_path = resolve_output_path(args.output_dir, rel_path, is_file=entry.is_file(), is_single_target=is_single_target)
            
            # Special override if --scfm was explicitly set
            if args.scfm and (target_path == "scfm.img" or entry.name == "scfm.img"):
                out_path = args.scfm

            if entry.is_file():
                total_files += extract_file(nand, entry, out_path)
            else:
                f_count, d_count = extract_directory(nand, entry, out_path)
                total_files += f_count
                total_dirs += d_count

        print(f"Extraction complete: {total_files} file(s), {total_dirs} directory(ies) extracted.")
    else:
        print("Extraction complete.")

if __name__ == "__main__":
    main()

