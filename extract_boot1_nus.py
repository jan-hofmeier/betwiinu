#!/usr/bin/env python3
"""
Extract boot1 directly from Nintendo Update Server (NUS) Title 00050010-10000100.
Decryption uses WUP title ticket & key with Wii U Common Key read from otp.bin.
"""

import os
import sys
import argparse
import urllib.request
import struct
from Crypto.Cipher import AES

TITLE_ID_HEX = "0005001010000100"
TITLE_ID = bytes.fromhex(TITLE_ID_HEX)
BASE_URL = f"http://ccs.cdn.wup.shop.nintendo.net/ccs/download/{TITLE_ID_HEX}"

def read_common_key_from_otp(otp_path):
    with open(otp_path, "rb") as f:
        f.seek(0xE0)
        common_key = f.read(16)
    if len(common_key) != 16:
        raise ValueError(f"Could not read 16-byte common key from {otp_path} at offset 0xE0")
    return common_key

def extract_boot1_from_nus(otp_path="otp.bin", output_path="boot1.bin", patch_prod=True):
    print(f"Reading Wii U Common Key from {otp_path} (offset 0xE0)...")
    common_key = read_common_key_from_otp(otp_path)

    print(f"Downloading ticket (cetk) for Title {TITLE_ID_HEX} from NUS...")
    tik_url = f"{BASE_URL}/cetk"
    req = urllib.request.Request(tik_url, headers={"User-Agent": "WiiU/1.0"})
    with urllib.request.urlopen(req) as resp:
        tik_data = resp.read()

    # Encrypted title key is located at offset 0x1BF in the ticket
    encrypted_title_key = tik_data[0x1BF:0x1BF+16]
    iv_tik = TITLE_ID + b"\x00" * 8

    cipher_tik = AES.new(common_key, AES.MODE_CBC, iv_tik)
    title_key = cipher_tik.decrypt(encrypted_title_key)
    print(f"Decrypted Title Key: {title_key.hex()}")

    print("Downloading boot1 content (00000009) from NUS...")
    app_url = f"{BASE_URL}/00000009"
    req = urllib.request.Request(app_url, headers={"User-Agent": "WiiU/1.0"})
    with urllib.request.urlopen(req) as resp:
        app_data = resp.read()

    print(f"Downloaded encrypted content 00000009 ({len(app_data)} bytes)")

    # Decrypt content 00000009 (index 0x0009)
    iv_app = struct.pack(">H", 9) + b"\x00" * 14
    cipher_app = AES.new(title_key, AES.MODE_CBC, iv_app)
    decrypted_boot1 = bytearray(cipher_app.decrypt(app_data))

    header_magic = decrypted_boot1[:4].hex()
    print(f"Decrypted Header Magic: {header_magic}")

    if patch_prod and decrypted_boot1[:4] == bytes.fromhex("efab82d9"):
        decrypted_boot1[1] = 0xA2
        print(f"Patched Ancast header magic to Prod: {decrypted_boot1[:4].hex()}")

    with open(output_path, "wb") as f:
        f.write(decrypted_boot1)

    print(f"Successfully extracted boot1 to {output_path} ({len(decrypted_boot1)} bytes)")
    return output_path

def main():
    parser = argparse.ArgumentParser(description="Extract boot1 from NUS (Title 00050010-10000100)")
    parser.add_argument("--otp", default="otp.bin", help="Path to otp.bin file containing keys (default: otp.bin)")
    parser.add_argument("--output", "-o", default="boot1.bin", help="Output file path for boot1 (default: boot1.bin)")
    parser.add_argument("--no-patch", action="store_true", help="Do not patch Ancast magic 0xEFAB82D9 to 0xEFA282D9")
    args = parser.parse_args()

    extract_boot1_from_nus(otp_path=args.otp, output_path=args.output, patch_prod=not args.no_patch)

if __name__ == "__main__":
    main()
