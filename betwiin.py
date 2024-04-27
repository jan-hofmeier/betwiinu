# Betwiin v1.0, Copyright 2009 Haxx Enterprises (bushing@gmail.com)
# Licensed to you under the terms of the GNU GPL v2.0; see http://www.gnu.org/licenses/old-licenses/gpl-2.0.txt

import os, sys, struct, hashlib, hmac, numpy
from struct import unpack, pack
from Crypto.Cipher import AES
from nand import *

cluster_contents = {}

def recur_copyclusters(entry: SFFS_entry):
	for c in entry.children():
		recur_copyclusters(c)
	if entry.is_file():
		print("Cluster chain for %s:" % (entry.path+entry.name))
		if entry.name == "scfm.img":
			print("Skipping scfm.img")
			return
		clusters = entry.get_cluster_chain()
#		print clusters
		for x, cluster in enumerate(clusters):
			#calculated = entry.calc_hmac(input_nand, x)
			#stored = input_nand.get_cluster_hmac(cluster)
			decrypted_cluster = input_nand.decrypt_cluster(cluster)

			output_nand.encrypt_cluster(cluster, decrypted_cluster)
			output_nand.set_cluster_hmac(cluster, entry.calc_hmac(output_nand, x, decrypted_cluster))

#			if calculated != stored:
#				print "Calc HMAC: " + hexdump(calculated)
#				print "Stored HMAC: " + hexdump(input_nand.get_cluster_hmac(clusters[x]))
#				print "You fail it."
#				exit(1)
#			else:
#				print "HMAC okay in input file for cluster %d" % (clusters[x])

with open('input/otp.bin', 'rb') as f:
	f.seek(0x170)
	input_key = f.read(0x10)
	f.seek(0x1E0)
	input_hmac = f.read(0x14)

with open('output/otp.bin', 'rb') as f:
	f.seek(0x170)
	output_key = f.read(0x10)
	f.seek(0x1E0)
	output_hmac = f.read(0x14)

print("Creating empty output image:")
output_image = open("output/SLC.RAW", "wb")

for cluster in range(0, TOTAL_CLUSTER):
	output_image.write(b"\xff" * 0x4200)
output_image.close()

print("Copying boot1 / boot2:")

input_nand = NANDFormatSpare("input/SLC.RAW")
input_nand.set_keys(input_key, input_hmac)
output_nand = NANDFormatSpare("output/SLC.RAW")
output_nand.set_keys(output_key, output_hmac)

for cluster in range(0, 0x40):
	output_nand.set_cluster(cluster, input_nand.get_cluster(cluster))

superblock_cluster = find_newest_superblock(input_nand)

latest_superblock = SFFS(read_superblock(input_nand, superblock_cluster))

for version, cluster in enumerate(range(TOTAL_CLUSTER - NUM_SUPER * CLUSTER_PER_SUPER, TOTAL_CLUSTER, CLUSTER_PER_SUPER,),1):
	latest_superblock.set_version(version)
	for i, clusterno in enumerate(range(cluster, cluster + 0x10)):
		buff_off = i * CLUSTER_SIZE
		output_nand.set_cluster(clusterno, latest_superblock.data_buffer[buff_off:buff_off+CLUSTER_SIZE])
		output_nand.update_cluster_ecc(clusterno)
	latest_superblock.data_buffer
	print(f"Writing supercluster {version} at 0x{cluster:x}")
	calc_hmac = latest_superblock.calc_hmac(cluster, output_nand.hmac_key)
	output_nand.set_cluster_hmac(cluster + 0xf, calc_hmac)

recur_copyclusters(SFFS_entry(latest_superblock.fst, latest_superblock.fat, 0, ""))
