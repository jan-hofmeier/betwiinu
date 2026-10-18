#!/usr/bin/env python3
"""Lists the FST entries (mode, attr, uid, gid) of an SLC dump. This is how
slc_permissions_list.txt was made, which the rules in build_slc.py are based on.

usage: python3 research/extract_perms.py <SLC.RAW> <otp.bin> [output.txt]
"""

import os
import struct
import sys
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from slctools.nand import *

def analyze_perms(nand_path, otp_path, out_path):
    nand = NANDFormatSpare(nand_path)
    with open(otp_path, "rb") as f:
        otp = f.read()
    nand.set_keys(otp[0x170:0x180], otp[0x1E0:0x1F4])
    fst = SFFS(read_superblock(nand, find_newest_superblock(nand))).fst

    with open(out_path, "w") as f:
        f.write(f"{'Idx'.ljust(4)} | {'Name'.ljust(15)} | {'Mode'} | {'Attr'} | {'UID'.ljust(10)} | {'GID'.ljust(6)} | {'Sub'} | {'Sib'}\n")
        f.write("-" * 80 + "\n")
        
        for i in range(len(fst)//32):
            buffer = fst[i*0x20:(i+1)*0x20]
            if buffer == b'\x00'*32: continue
            
            name = buffer[0:12].rstrip(b'\x00').decode("utf-8", "ignore")
            mode, attr, sub, sib, size, uid, gid, x3 = struct.unpack(">BBHHIIHI", buffer[12:])
            
            f.write(f"{str(i).ljust(4)} | {name.ljust(15)} | {hex(mode).ljust(4)} | {hex(attr).ljust(4)} | {hex(uid).ljust(10)} | {hex(gid).ljust(6)} | {sub} | {sib}\n")
            
    print(f"Full list written to {out_path}")

if __name__ == '__main__':
    if len(sys.argv) not in (3, 4):
        sys.exit(__doc__.strip().splitlines()[-1])
    analyze_perms(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) == 4 else "slc_permissions_list.txt")
