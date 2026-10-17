#!/usr/bin/env python3

import os
import sys
import struct
import hashlib
import hmac
import re
import argparse
from nand import *

def allocate_clusters(fat, size, start_cluster=0x40):
    clusters_needed = (size + CLUSTER_SIZE - 1) // CLUSTER_SIZE
    if clusters_needed == 0:
        return []
    
    allocated = []
    # Find free clusters. In our FAT, a free cluster has value 0x0000.
    max_cluster = TOTAL_CLUSTER - NUM_SUPER * CLUSTER_PER_SUPER
    
    current_cluster = start_cluster
    while len(allocated) < clusters_needed:
        if current_cluster >= max_cluster:
            raise Exception(f"Not enough free clusters (needed {clusters_needed}, got {len(allocated)})")
        
        val = struct.unpack(">H", fat[current_cluster*2:current_cluster*2+2])[0]
        if val == 0x0000:
            allocated.append(current_cluster)
        current_cluster += 1
        
    # Build chain
    for i in range(len(allocated) - 1):
        struct.pack_into(">H", fat, allocated[i]*2, allocated[i+1])
    struct.pack_into(">H", fat, allocated[-1]*2, 0xFFFF) # end of chain
    
    return allocated

class FSTNode:
    def __init__(self, name, is_dir, path):
        self.name = name
        self.is_dir = is_dir
        self.path = path
        self.size = 0
        self.clusters = []
        self.children = []
        self.index = 0
        self.sub = 0xFFFF
        self.sib = 0xFFFF
        self.mode = 0x02 if is_dir else 0xc1
        self.attr = 0
        self.uid = 0
        self.gid = 0

PERMISSION_RULES = [
    # (regex_pattern, mode, attr, uid, gid)
    
    # 1. Custom config files (UID 0x100000f5)
    (r"^/sys/config/(cos|ums|cafe|p_acct\d+|NETCfg\d+|NETCmn|rmtCfg|btStd|wii_acct|AVMCfg|coppa|caffeine|spotpass|parent|hdmiEDID|im_cfg|DRCCfg|nn)\.xml$", 0xc1, 0x0, 0x100000f5, 0xff),
    (r"^/sys/prefs$", 0xc2, 0x0, 0x100000f5, 0x0),
    (r"^/tmp$", 0xc2, 0x0, 0x100000f5, 0xff),
    
    # 2. Custom system files (UID 0x100000fa)
    (r"^/sys/uhs$", 0xc2, 0x0, 0x100000fa, 0xff),
    (r"^/sys/uhs/devsel\.bin$", 0xc1, 0x0, 0x100000fa, 0xff),
    (r"^/sys/usb$", 0xc2, 0x0, 0x100000fa, 0x0),
    
    # 3. Security/Hardware files
    (r"^/sys/acp$", 0xc2, 0x0, 0x100000f6, 0x0),
    (r"^/sys/nsec$", 0xc2, 0x0, 0x100000f4, 0x0),
    (r"^/scfm\.img$", 0xc1, 0x0, 0x100000f1, 0xff),
    
    # 4. Title Root Directories (e.g. /sys/title/00050010/1000400a)
    (r"^/sys/title/[0-9a-fA-F]{8}/[0-9a-fA-F]{8}$", 0xc2, 0x0, 0x0, 0x0),
    
    # 5. Application Executables and Resources in code/ dirs
    (r"^/sys/title/[0-9a-fA-F]{8}/[0-9a-fA-F]{8}/code/.*\.(rpl|rpx|img|elf)$", 0x1, 0x0, 0x0, 0x0),
    (r"^/sys/title/[0-9a-fA-F]{8}/[0-9a-fA-F]{8}/code/(app\.xml|title\.fst|title\.tmd|deint\.txt|dmcu\.d\.hex|font\.bin|versions\.bin)$", 0x1, 0x0, 0x0, 0x0),
]

def get_permissions(rel_path, is_dir):
    for pattern, mode, attr, uid, gid in PERMISSION_RULES:
        if re.match(pattern, rel_path):
            return mode, attr, uid, gid
            
    # Default fallbacks
    mode = 0x02 if is_dir else 0xc1
    return mode, 0x0, 0x0, 0x0

def build_fst_tree(input_dir, fst, fat, scfm_path=None):
    def scan_dir(path, rel_path, name):
        node = FSTNode(name, os.path.isdir(path), path)
        
        mode, attr, uid, gid = get_permissions(rel_path, node.is_dir)
        node.mode = mode
        node.attr = attr
        node.uid = uid
        node.gid = gid
        
        if node.is_dir:
            for child_name in sorted(os.listdir(path)):
                # Skip scfm.img from input directory if we are providing it via --scfm
                if rel_path == "/" and child_name == "scfm.img" and scfm_path is not None:
                    continue
                child_path = os.path.join(path, child_name)
                child_rel = rel_path + ("/" if rel_path != "/" else "") + child_name
                node.children.append(scan_dir(child_path, child_rel, child_name))
        else:
            node.size = os.path.getsize(path)
            node.clusters = allocate_clusters(fat, node.size)
            if node.clusters:
                node.sub = node.clusters[0]
            else:
                node.sub = 0xFFFF
        return node
    
    # Root node has name '/'
    root_node = scan_dir(input_dir, "/", "/")
    
    if scfm_path:
        scfm_node = FSTNode("scfm.img", False, scfm_path)
        mode, attr, uid, gid = get_permissions("/scfm.img", False)
        scfm_node.mode = mode
        scfm_node.attr = attr
        scfm_node.uid = uid
        scfm_node.gid = gid
        scfm_node.size = os.path.getsize(scfm_path)
        scfm_node.clusters = allocate_clusters(fat, scfm_node.size)
        if scfm_node.clusters:
            scfm_node.sub = scfm_node.clusters[0]
        else:
            scfm_node.sub = 0xFFFF
        root_node.children.append(scfm_node)
        # Keep FST entries sorted alphabetically
        root_node.children.sort(key=lambda x: x.name)
    
    flat_nodes = []
    def flatten(node):
        node.index = len(flat_nodes)
        flat_nodes.append(node)
        
        if node.is_dir:
            if node.children:
                node.sub = len(flat_nodes)
                for i, child in enumerate(node.children):
                    flatten(child)
                for i in range(len(node.children) - 1):
                    node.children[i].sib = node.children[i+1].index
                node.children[-1].sib = 0xFFFF
            else:
                node.sub = 0xFFFF
                
    flatten(root_node)
    
    for node in flat_nodes:
        offset = node.index * 32
        name_padded = node.name.encode('utf-8').ljust(12, b'\x00')
        
        x3 = 0
        
        struct.pack_into(">12sBBHHIIHI", fst, offset,
                         name_padded, node.mode, node.attr, node.sub, node.sib,
                         node.size, node.uid, node.gid, x3)
                         
    return flat_nodes

def parse_bad_blocks_file(filepath):
    bad_blocks = set()
    if not filepath or not os.path.exists(filepath):
        return bad_blocks
    with open(filepath, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("//"):
                continue
            matches = re.findall(r"0x[0-9a-fA-F]+|\b[0-9a-fA-F]+\b", line)
            for m in matches:
                try:
                    if m.lower().startswith("0x"):
                        val = int(m, 16)
                    else:
                        val = int(m, 16)
                    bad_blocks.add(val)
                except ValueError:
                    pass
    return bad_blocks

def main():
    parser = argparse.ArgumentParser(description="Create a Wii U SLC image from a folder")
    parser.add_argument("--input-dir", required=True, help="Input directory")
    parser.add_argument("--output-image", required=True, help="Output SLC.RAW file")
    parser.add_argument("--otp", required=True, help="OTP bin file containing keys")
    parser.add_argument("--boot-image", required=False, help="Base image to copy boot1/boot2 from")
    parser.add_argument("--boot1", required=False, help="Extracted boot1.bin file to include (clusters 0-0x3f)")
    parser.add_argument("--scfm", required=False, help="Extracted scfm.img file to include (overrides input directory)")
    parser.add_argument("--bad-blocks", required=False, help="Bad blocks list file (minute format) to mark in NAND & skip in FAT")
    
    args = parser.parse_args()
    
    print("Reading OTP keys...")
    with open(args.otp, 'rb') as f:
        f.seek(0x170)
        otp_key = f.read(0x10)
        f.seek(0x1E0)
        otp_hmac = f.read(0x14)
        
    print("Creating empty output image...")
    with open(args.output_image, "wb") as f:
        for cluster in range(0, TOTAL_CLUSTER):
            f.write(b"\xff" * 0x4200)
            
    output_nand = NANDFormatSpare(args.output_image)
    output_nand.set_keys(otp_key, otp_hmac)
    
    if args.boot1:
        print(f"Copying boot1/boot2 from {args.boot1}...")
        with open(args.boot1, "rb") as f:
            boot1_data = f.read()
        for cluster in range(0, 0x40):
            cluster_data = boot1_data[cluster*CLUSTER_SIZE : (cluster+1)*CLUSTER_SIZE]
            if len(cluster_data) < CLUSTER_SIZE:
                cluster_data = cluster_data.ljust(CLUSTER_SIZE, b'\x00')
            output_nand.set_cluster(cluster, cluster_data)
    elif args.boot_image:
        print(f"Copying boot1/boot2 from {args.boot_image}...")
        boot_nand = NANDFormatSpare(args.boot_image)
        for cluster in range(0, 0x40):
            output_nand.set_cluster(cluster, boot_nand.get_cluster(cluster))
    else:
        print("No boot image or boot1 provided, leaving boot1/boot2 empty.")
        
    fat = bytearray(b"\x00" * 0x10000)
    fst = bytearray(b"\x00" * (6143 * 32))
    
    if args.bad_blocks:
        bad_blocks = parse_bad_blocks_file(args.bad_blocks)
        if bad_blocks:
            print(f"Applying {len(bad_blocks)} bad block(s) from {args.bad_blocks}...")
            for b in sorted(bad_blocks):
                print(f"Marking block 0x{b:04X} as bad...")
                output_nand.mark_bad_block(b)
                for c in range(b * 8, b * 8 + 8):
                    if c * 2 < len(fat):
                        struct.pack_into(">H", fat, c * 2, 0xFFF7)

    print("Building FST and FAT...")
    flat_nodes = build_fst_tree(args.input_dir, fst, fat, args.scfm)
    print(f"Total files/dirs: {len(flat_nodes)}")
    
    print("Encrypting files...")
    for node in flat_nodes:
        if not node.is_dir and node.size > 0:
            print(f"Writing {node.path} ({node.size} bytes)")
            with open(node.path, "rb") as f:
                data = f.read()
                
            for i, cluster in enumerate(node.clusters):
                cluster_data = data[i*CLUSTER_SIZE : (i+1)*CLUSTER_SIZE]
                cluster_data = cluster_data.ljust(CLUSTER_SIZE, b'\x00')
                
                if node.name == "scfm.img":
                    # scfm.img is unencrypted (raw plaintext) and not HMACed
                    output_nand.set_cluster(cluster, cluster_data)
                    cluster_hmac = b'\x00' * 20
                else:
                    output_nand.encrypt_cluster(cluster, cluster_data)
                    
                    name_padded = node.name.encode('utf-8').ljust(12, b'\x00')
                    uid = node.uid
                    x3 = 0
                    
                    hmac_buf1 = struct.pack(">I12s", node.uid, name_padded)
                    hmac_buf2 = struct.pack(">II", node.index, x3) + b"\x00"*0x24
                    hmac_extra = hmac_buf1 + struct.pack(">I", i) + hmac_buf2
                    
                    encrypted_cluster = encrypt_block(output_nand.aes_key, cluster_data)
                    digest_maker = hmac.new(output_nand.hmac_key, b'', hashlib.sha1)
                    digest_maker.update(hmac_extra)
                    digest_maker.update(encrypted_cluster)
                    cluster_hmac = digest_maker.digest()
                
                output_nand.set_cluster_hmac(cluster, cluster_hmac)
                
    print("Creating superblock...")
    superblock_buffer = bytearray(b"\x00" * 0x40000)
    struct.pack_into(">4s", superblock_buffer, 0x0, b"SFS!")
    version = 1
    struct.pack_into(">I", superblock_buffer, 0x4, version)
    
    superblock_buffer[0xC:0x1000C] = fat
    superblock_buffer[0x1000C:0x1000C + (6143 * 32)] = fst
    
    start_c = TOTAL_CLUSTER - NUM_SUPER * CLUSTER_PER_SUPER
    for slot in range(NUM_SUPER):
        superblock_cluster = start_c + slot * CLUSTER_PER_SUPER
        print(f"Writing superblock {version} to slot {slot} at cluster 0x{superblock_cluster:x}...")
        
        digest_maker = hmac.new(output_nand.hmac_key, b'', hashlib.sha1)
        hmac_extra = b"\x00"*18 + struct.pack(">H", superblock_cluster) + b"\x00"*44
        digest_maker.update(hmac_extra)
        digest_maker.update(superblock_buffer)
        calc_hmac = digest_maker.digest()
        
        for i in range(0x10):
            clusterno = superblock_cluster + i
            buff_off = i * CLUSTER_SIZE
            output_nand.set_cluster(clusterno, superblock_buffer[buff_off:buff_off+CLUSTER_SIZE])
            output_nand.update_cluster_ecc(clusterno)
            
        output_nand.set_cluster_hmac(superblock_cluster + 0xf, calc_hmac)
    
    print("Done!")

if __name__ == "__main__":
    main()
