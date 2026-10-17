import struct
from nand import *

def analyze_perms(nand_path):
    nand = NANDFormatSpare(nand_path)
    highest_sb = None
    for c in range(TOTAL_CLUSTER - NUM_SUPER * CLUSTER_PER_SUPER, TOTAL_CLUSTER, CLUSTER_PER_SUPER):
        sb = SFFS(read_superblock(nand, c))
        if sb.version() == 107116: highest_sb = sb
    
    fst = highest_sb.fst
    
    with open("slc_permissions_list.txt", "w") as f:
        f.write(f"{'Idx'.ljust(4)} | {'Name'.ljust(15)} | {'Mode'} | {'Attr'} | {'UID'.ljust(10)} | {'GID'.ljust(6)} | {'Sub'} | {'Sib'}\n")
        f.write("-" * 80 + "\n")
        
        for i in range(len(fst)//32):
            buffer = fst[i*0x20:(i+1)*0x20]
            if buffer == b'\x00'*32: continue
            
            name = buffer[0:12].rstrip(b'\x00').decode("utf-8", "ignore")
            mode, attr, sub, sib, size, uid, gid, x3 = struct.unpack(">BBHHIIHI", buffer[12:])
            
            f.write(f"{str(i).ljust(4)} | {name.ljust(15)} | {hex(mode).ljust(4)} | {hex(attr).ljust(4)} | {hex(uid).ljust(10)} | {hex(gid).ljust(6)} | {sub} | {sib}\n")
            
    print("Full list written to slc_permissions_list.txt")

if __name__ == '__main__':
    analyze_perms("test/slc.bin")
