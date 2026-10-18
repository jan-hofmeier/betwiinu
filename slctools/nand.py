# Betwiin v1.0, Copyright 2009 Haxx Enterprises (bushing@gmail.com)
# Licensed to you under the terms of the GNU GPL v2.0; see http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

# pip3 install pycryptodome

import os, sys, struct, hashlib, hmac
from struct import unpack, pack
from Crypto.Cipher import AES

NUM_SUPER = 64
CLUSTER_PER_SUPER = 16
TOTAL_CLUSTER = 0x8000
PAGE_SIZE = 2048
PAGES_PER_CLUSTER = 8
CLUSTER_SIZE = PAGE_SIZE * PAGES_PER_CLUSTER

# FAT entry values (anything below is the next cluster of a chain)
FAT_CLUSTER_LAST = 0xFFFB      # last cluster of a chain
FAT_CLUSTER_RESERVED = 0xFFFC  # boot1 slots, superblocks
FAT_CLUSTER_BAD = 0xFFFD       # bad block
FAT_CLUSTER_EMPTY = 0xFFFE     # free

def pad(s,c,l):
	if len(s)<l:
		s += c * (l-len(s))
	return s

FILTER=''.join([(len(repr(chr(x)))==3) and chr(x) or '.' for x in range(256)])

def hexdump(src, length=16):
    result=[]
    for i in range(0, len(src), length):
       s = src[i:i+length]
       hexa = ' '.join(["%02X"%ord(x) for x in s])
       printable = s.translate(FILTER)
       result.append("%04X   %-*s   %s\n" % (i, length*3, hexa, printable))
    return ''.join(result)

def hexstring(src):
    return ''.join(["%02X"%ord(x) for x in src])

def decrypt_block(key, inblock):
	aes = AES.new(key, AES.MODE_CBC, b"\x00" * 16)
	return aes.decrypt(inblock)

def encrypt_block(key, inblock):
	aes = AES.new(key, AES.MODE_CBC, b"\x00" * 16)
	return aes.encrypt(inblock)
	
def CountBits(c):
    "Count the number of bits in the 8-bit integer c."
    count = 0
    mask = 1
    for i in range(8):
        count = count + ((mask & c) != 0)
        mask = mask << 1
    return count

def parity(c):
    "Compute the parity of the 8-bit integer c."
    return CountBits(c) % 2

def file_cluster_hmac(hmac_key, uid, name, fst_index, x3, chain_index, plaintext):
	"""HMAC of a file cluster. name is the 12-byte name field of the FST entry;
	the HMAC covers the decrypted cluster, not the encrypted one."""
	digest_maker = hmac.new(hmac_key, b'', hashlib.sha1)
	digest_maker.update(pack(">I12sIII", uid, name, chain_index, fst_index, x3) + b"\x00"*0x24)
	digest_maker.update(plaintext)
	return digest_maker.digest()

def superblock_hmac(hmac_key, cluster_no, superblock):
	"""HMAC of a superblock written at cluster_no."""
	digest_maker = hmac.new(hmac_key, b'', hashlib.sha1)
	digest_maker.update(b"\x00"*18 + pack(">H", cluster_no) + b"\x00"*44)
	digest_maker.update(superblock)
	return digest_maker.digest()

def all_zeros(data: bytes):
	for b in data:
		if b:
			return False
	return True

# Hamming ECC over a 512-byte chunk. Each ECC bit is the parity of a subset of
# the data bits: the low 3 bit pairs select bits within a byte, the upper 9 the
# byte index. Masking the chunk as one big integer and counting bits gives
# those parities without looping over every byte.
def _byte_mask(pattern):
	return int.from_bytes(bytes([pattern]) * 512, "big")

def _index_mask(j):
	return int.from_bytes(bytes(0xff if (i >> j) & 1 else 0 for i in range(512)), "big")

_ECC_MASKS = [_byte_mask(p) for p in (0xaa, 0xcc, 0xf0)] + [_index_mask(j) for j in range(9)]

def calc_ecc(data):
	n = int.from_bytes(data, "big")
	total = n.bit_count() & 1
	r0 = r1 = 0
	for j, mask in enumerate(_ECC_MASKS):
		p1 = (n & mask).bit_count() & 1
		r1 |= p1 << j
		r0 |= (total ^ p1) << j
	return struct.pack("<HH", r0, r1)

class NANDFormat:
	def page_is(self, page, value):
		data = self.get_page(page)
		for i in data:
			if ord(i) != value:
				return False
		return True

	def page_is_00(self, page):
		return self.page_is(page, 00)

	def page_is_ff(self, page):
		return self.page_is(page, 0xff)

	def calc_page_ecc(self, page):
		retval = bytearray()
		data = self.get_page(page)
#		if all_zeros(data):
			#print("Zero Page")
		for i in range(4):
			retval.extend(calc_ecc(data[512*i:512*(i+1)]))
		return retval

	def get_stored_ecc(self, page):
		return self.get_spare(page)[48:64]

	def check_page_ecc(self, page):
		calc_ecc = self.calc_page_ecc(page)
		stored_ecc = self.get_stored_ecc(page)
		if calc_ecc != stored_ecc:
			print("Page %x: ECC bad" % (page))
#		else:
#			print "Page %x: ECC ok" % (page)

	def update_page_ecc(self, pageno):
		ecc = self.calc_page_ecc(pageno)
		spare = b"\xff" + b"\x00"*47 + ecc
#		print "updating ECC for page %x:" % (pageno)
		self.set_spare(pageno, spare)
	
	def update_cluster_ecc(self, clusterno):
		for p in range(0, 8):
			self.update_page_ecc(clusterno * 8 + p)

	def get_cluster(self, cluster_no: int) -> bytearray:
		retval =  bytearray()
		for i in range(0,8):
			page = self.get_page(cluster_no * 8 + i)
			retval.extend(page)
		return retval

	def decrypt_cluster(self, cluster_no):
		return decrypt_block(self.aes_key, self.get_cluster(cluster_no))

	def set_cluster(self, cluster_no, data):
		print("Updating cluster %x (block %x)" % (cluster_no, cluster_no // 8))
		data = pad(data, b"\x00", 0x4000)
		for i in range(0,8):
			self.set_page(cluster_no * 8 + i, data[0x800 * i : 0x800 * (i+1)])
		self.update_cluster_ecc(cluster_no)

	def encrypt_cluster(self, cluster_no, data):
#		print "Updating encrypted cluster %x (block %x)" % (cluster_no, cluster_no / 8)
#		print "%x, " % (cluster_no),
		data = encrypt_block(self.aes_key, pad(data, b"\x00", 0x4000))
		for i in range(0,8):
			self.set_page(cluster_no * 8 + i, data[0x800 * i : 0x800 * (i+1)])
		self.update_cluster_ecc(cluster_no)
#		print "Done."

	def get_cluster_hmac(self, cluster_no):
		return self.get_spare(cluster_no * 8 + 6)[1:21]

	def set_cluster_hmac(self, cluster_no: int, hmac: bytes):
		pageno = cluster_no * 8 + 6
		ecc = self.calc_page_ecc(pageno)
		spare = b"\xff" + hmac + hmac[0:12] + b"\x00"*15 + ecc
		self.set_spare(pageno, spare)
		pageno = pageno + 1
		ecc = self.calc_page_ecc(pageno)
		spare = b"\xff" + hmac[12:] + b"\x00"*39 + ecc
		self.set_spare(pageno, spare)

	def dump_clusters_to_file(self, filename, chain):
		print("Dumping %d clusters to %s" % (len(chain), filename))
		outfile = open(filename, "wb")
		for c in chain:
			outfile.write(self.decrypt_cluster(c))
			self.set_cluster_hmac(c, b"\xab"*20)
		outfile.close()

	def update_clusters_from_file(self, filename, chain):
		print("Updating %d clusters from %s" % (len(chain), filename))
		infile = open(filename, "rb")
		for c in chain:
			buffer = infile.read(0x4000)
			self.encrypt_cluster(c, buffer)
		infile.close()

	def set_keys(self, aes, hmac):
		self.aes_key = aes
		self.hmac_key = hmac
		

class NANDFormatBare(NANDFormat):
	spare_supported = False
	badblock_supported = False
	badpage_supported = False

	def __init__(self, file):
		self.f = open(file,"r+b")
		self.f.seek(0,os.SEEK_END)
		self.fsize = self.f.tell()
		self.f.seek(0,os.SEEK_SET)
		self.blocksize = 64
		self.aes_key = ""
		self.hmac_key = ""

		if self.fsize % 2048 != 0:
			raise ValueError("File size not divisible by 2048")
		self.pages = self.fsize/2048
		if self.pages % 64 != 0:
			raise ValueError("File size is not an even number of blocks")
		self.blocks = self.pages / 64

	def get_page(self, num):
		self.f.seek(num*2048)
		data = self.f.read(2048)
		return data

	def set_page(self, num, data):
		self.f.seek(num*2048)
		self.f.write(data)

	def get_spare(self, num):
		raise NotImplementedError("Spare data not supported")

	def set_spare(self, num, data):
		raise NotImplementedError("Spare data not supported")

	def is_bad_page(self, num):
		return False

	def is_bad_block(self, num):
		return False

class NANDFormatSpare(NANDFormat):
	spare_supported = True
	badblock_supported = True
	badpage_supported = False #set to true when we figure out WTF IOS is doing here

	def __init__(self, file):
		self.f = open(file,"r+b")
		self.f.seek(0,os.SEEK_END)
		self.fsize = self.f.tell()
		self.f.seek(0,os.SEEK_SET)
		self.blocksize = 64

		if self.fsize % 2112 != 0:
			raise ValueError("File size not divisible by 2112")
		self.pages = self.fsize/2112
#		if self.pages % 64 != 0:
#			raise ValueError("File size is not an even number of blocks")
		self.blocks = self.pages / 64

	def _get_rawpage(self, num):
		self.f.seek(num*2112)
		page = self.f.read(2112)
		data = page[:2048]
		spare = page[2048:]

		return data, spare

	def get_page(self, num):
		self.f.seek(num*2112)
		page = self.f.read(2112)
		data = page[:2048]
		spare = page[2048:]

		return data

	def set_page(self, num, data):
		self.f.seek(num*2112)
		self.f.write(data[:2048])

	def get_spare(self, num):
		data, spare = self._get_rawpage(num)
		return spare

	def set_spare(self, num, data):
		self.f.seek(num*2112+2048)
		self.f.write(data[:64])

	# Bad blocks (as seen in real dumps): pages 0 and 1 fully zeroed, data and
	# spare. Only spare byte 0 is the marker - byte 1 is 0x00 on every written page.
	def mark_bad_block(self, num):
		num = int(num)
		for p in (num * 64, num * 64 + 1):
			self.set_page(p, b"\x00" * 2048)
			self.set_spare(p, b"\x00" * 64)

	def is_bad_page(self, num):
		return self.is_bad_block(num // 64)

	def is_bad_block(self, num):
		num = int(num)
		return any(self.get_spare(p)[0] != 0xff for p in (num * 64, num * 64 + 1))

class NANDFormatSDDump(NANDFormat):
	spare_supported = True
	badblock_supported = True
	badpage_supported = True

	def __init__(self, file):
		self.f = open(file,"rb")
		self.f.seek(0,os.SEEK_END)
		self.fsize = self.f.tell()
		self.f.seek(0,os.SEEK_SET)
		self.blocksize = 64

		if self.fsize % 2560 != 0:
			raise ValueError("File size not divisible by 2560")
		self.pages = self.fsize//2560
		if self.pages % 64:
			raise ValueError("File size is not an even number of blocks")
		self.blocks = self.pages // 64

	def _get_rawpage(self, num):
		self.f.seek(num*2560)
		page = self.f.read(2560)
		data, spare, magic, ret, fd, pagenum, iosver, iosrev, bufno = struct.unpack(">2048s64s4siiIiiI420x",page)
		if magic != "NAND":
			raise ValueError("Bad magic for page 0x%x"%num)
		if pagenum != num:
			raise ValueError("Page number mismatch for page 0x%x (is 0x%x)"%(num,pagenum))

		return data, spare, ret == -12

	def get_page(self, num):
		data, spare, bad = self._get_rawpage(num)
		return data

	def get_spare(self, num):
		data, spare, bad = self._get_rawpage(num)
		return spare

	def is_bad_page(self, num):
		data, spare, bad = self._get_rawpage(num)
		return bad
	def is_bad_block(self, num):
		num = int(num)
		data1, spare1, bad1 = self._get_rawpage(num * 64)
		data2, spare2, bad2 = self._get_rawpage(num * 64 + 1)
		if bad1 or bad2:
			return True
		if (all_zeros(data1) and all_zeros(spare1)) or (all_zeros(data2) and all_zeros(spare2)):
			return False
		b1 = spare1[0] if isinstance(spare1[0], int) else ord(spare1[0])
		b2 = spare2[0] if isinstance(spare2[0], int) else ord(spare2[0])
		if b1 != 0xff or b2 != 0xff:
			return True
		return False
		
def nand_open(filename):
	f = open(filename,"rb")
	page = f.read(2112)
	f.close()
	if page[0x800] == 0xff:
		return NANDFormatSpare(filename)
	return NANDFormatBare(filename)

class SFFS_entry_mode:
	def __init__(self, mode):
		dir = "?-d?"
		perm = "-rw"
		self.type = dir[mode & 3]
		self.perms = ""
		for i in range(0,3):
			self.perms += perm[(mode >> 6) & 1]
			self.perms += perm[(mode >> 6) & 2]
			mode <<= 2

	def __str__(self):
		return self.type + self.perms

class SFFS_entry:
	def __init__(self, fst: bytearray, fat, i, path):
		self.fst = fst
		self.fat = fat
		self.path = path
		buffer = fst[i*0x20:(i+1)*0x20]
		self.name = buffer[0:12].rstrip(b'\x00').decode("utf-8")
		if self.name == "/":
			self.name = ""
		self.mode, self.attr, self.sub, self.sib, \
			self.size, self.uid, self.gid, self.x3 = unpack(">BBHHIIHI", buffer[12:])
		self.raw_name = bytes(buffer[0:12])
		self.index = i
		self.chain = None

	def is_file(self):
		return (self.mode & 1) == 1
	
	def get_cluster_chain(self):
		if self.chain is None:
			self.chain = self.fat.get_cluster_chain(self.sub)
		return self.chain

	def check_hmac(self, nand):
		self.clusters = self.get_cluster_chain()
		if self.is_file():
			if self.name == "scfm.img":
				return True
			for x in range(0, len(self.clusters)):
				calculated = self.calc_hmac(nand, x)
				stored = nand.get_cluster_hmac(self.clusters[x])
				if calculated != stored:
					print("Calc HMAC: " + hexdump(calculated))
					print("Stored HMAC: " + hexdump(stored))

	def calc_hmac(self, nand, index, decrypted_cluster=None):
		if self.name == "scfm.img":
			return b"\x00" * 20
		if decrypted_cluster is None:
			decrypted_cluster = nand.decrypt_cluster(self.get_cluster_chain()[index])
		return file_cluster_hmac(nand.hmac_key, self.uid, self.raw_name, self.index, self.x3, index, decrypted_cluster)

	def __str__(self):
		retval = SFFS_entry_mode(self.mode).__str__()
		retval += " %02x %04x %05x %08x [%04x] %s" \
			% (self.attr, self.uid, self.gid, self.size, self.sub, self.path + self.name)
		return retval

	def child(self):
		if self.sub == 0xffff:
			return None
		if (self.mode & 1)==1:
			return None
		return SFFS_entry(self.fst, self.fat, self.sub, self.path + self.name + "/")

	def sibling(self):
		if self.sib == 0xffff:
			return None
		return SFFS_entry(self.fst, self.fat, self.sib, self.path)

	def children(self):
		if self.child() == None:
			return []
		retval = [self.child()]
		while retval[-1].sib != 0xffff:
			retval.append(retval[-1].sibling())
		return retval

	def recur(self):
		retval = ""
		for c in self.children():
			retval += c.recur().__str__()
		i = 0
		return self.__str__() + "\n" + retval

	def recur_getentry(self, filename):
		if (self.path + self.name) == filename:
			return self
		else:
			for c in self.children():
				retval = c.recur_getentry(filename)
				if retval != None:
					return retval
		return None

	def recur_dump_clusters(self, nand):
		for c in self.children():
			c.recur_dump_clusters(nand)
		if (self.mode & 1) == 1:
			print("Cluster chain for %s:" % (self.path+self.name))
			print(self.get_cluster_chain())
			try:
				os.makedirs("."+self.path+self.name)
			except:
				print("dir exists")
			for cl in self.get_cluster_chain():
				fname = ".%s%s/%04x" % (self.path, self.name, cl)
				outfile = open(fname, "w")
				outfile.write(nand.decrypt_cluster(cl))
				outfile.close()

	def recur_dump(self, nand):
		for c in self.children():
			c.recur_dump(nand)
		if (self.mode & 1) == 1:
			print(self)
			try:
				os.makedirs("."+self.path)
			except:
				print("dir exists")
			nand.dump_clusters_to_file("."+self.path+self.name, self.get_cluster_chain())

class SFFS_fat:
	def __init__(self, buffer):
		self.table = buffer

	def get_cluster_entry(self, num: int):
		return unpack(">H", self.table[num*2:num*2+2])[0]

	def set_cluster_entry(self, num: int, val: int):
		# self.table[num * 2:num * 2 + 2]
		a = pack(">H", val)
		self.table[num * 2:num * 2 + 2] = a
		return a

	def get_cluster_chain(self, num) -> []:
		cluster = 0
		retval = []
		if (num < 0) or (num >= 0xfff0):
			return retval
		while cluster < 0xFFF0:
			cluster = self.get_cluster_entry(num)
			retval.append(num)
			num = cluster
		return retval

	def delete_cluster_chain(self, num: int) -> None:
		while num < 0xFFF0:
			cluster = self.get_cluster_entry(num)
			retval.append(num)
			num = cluster


class SFFS:
	def __init__(self, buffer):
		self.data_buffer = buffer
		self.fat = SFFS_fat(buffer[0xc:0x1000c])
		self.fst = buffer[0x1000c:]

	def version(self):
		return unpack(">I", self.data_buffer[0x4:0x8])[0]

	def set_version(self, version: int):
		self.data_buffer[0x4:0x8] = pack(">I", version)
	
	def calc_hmac(self, clusterno, hmac_key):
		return superblock_hmac(hmac_key, clusterno, self.data_buffer)
		
def read_file(filename):
	myfile = open(filename, "rb")
	retval = myfile.read()
	myfile.close()
	return retval

def read_superblock(nand, cluster):
	superblock_data = bytearray()
	for offset in range(0,0x10):
		superblock_data.extend(nand.get_cluster(cluster + offset))
	return superblock_data

def find_newest_superblock(nand):
	highest_valid_hmac_version = 0
	highest_valid_hmac_cluster = None

	highest_any_version = 0
	highest_any_cluster = None

	for superblock_cluster in range(TOTAL_CLUSTER - NUM_SUPER * CLUSTER_PER_SUPER, TOTAL_CLUSTER, CLUSTER_PER_SUPER):
		raw_superblock = read_superblock(nand, superblock_cluster)
		if raw_superblock[:4] != b"SFS!":
			continue
		superblock = SFFS(raw_superblock)
		version = superblock.version()
		if version < 0xffff7fff:
			if version > highest_any_version:
				highest_any_version = version
				highest_any_cluster = superblock_cluster

			if nand.hmac_key:
				calc_hmac = superblock.calc_hmac(superblock_cluster, nand.hmac_key)
				stored_hmac = nand.get_cluster_hmac(superblock_cluster + 0xf)
				if calc_hmac == stored_hmac:
					if version > highest_valid_hmac_version:
						print(f"Superblock @ {superblock_cluster:x}: version {version:x} (HMAC ok)")
						highest_valid_hmac_version = version
						highest_valid_hmac_cluster = superblock_cluster
				else:
					print(f"Superblock @ {superblock_cluster:x}: version {version:x} (HMAC mismatch)")

	if highest_valid_hmac_cluster is not None:
		print("highest superblock: %x / %x" % (highest_valid_hmac_version, highest_valid_hmac_cluster))
		return highest_valid_hmac_cluster
	elif highest_any_cluster is not None:
		print("Warning: No HMAC-verified superblock found. Using highest-version SFS! superblock (ISFSHAX / custom): %x / %x" % (highest_any_version, highest_any_cluster))
		return highest_any_cluster
	else:
		raise ValueError("No valid SFS! superblock found in SLC image!")
