#!/usr/bin/env python3
"""
Download boot1 from the Nintendo Update Server (NUS), title 00050010-10000100,
and decrypt it with the common key read from otp.bin.
"""

import os
import sys
import argparse
import urllib.error
from slctools.boot1 import parse_boot1
from slctools.nus import Title, decrypt_content, decrypt_title_key, parse_tmd, read_common_key

TITLE_ID = "0005001010000100"

def download_boot1(otp_path, output_path):
    print(f"Reading Wii U Common Key from {otp_path} (offset 0xE0)...")
    common_key = read_common_key(otp_path)

    title = Title(TITLE_ID)
    tmd = title.tmd()
    title_key = decrypt_title_key(title.cetk(), common_key)

    # The title has a single content: boot1, padded
    content_id, index, content_type, size, sha1 = parse_tmd(tmd)[0]
    content = decrypt_content(title.content(content_id), title_key, index, content_type, size, sha1)
    try:
        version, decrypted_boot1 = parse_boot1(content)
    except ValueError as e:
        raise ValueError(f"downloaded boot1 is invalid: {e}")
    print(f"boot1 v{version}, hash ok")

    parent_dir = os.path.dirname(output_path)
    if parent_dir:
        os.makedirs(parent_dir, exist_ok=True)
    with open(output_path, "wb") as f:
        f.write(decrypted_boot1)

    print(f"Wrote boot1 to {output_path} ({len(decrypted_boot1)} bytes)")
    return output_path

def main():
    parser = argparse.ArgumentParser(description="Download boot1 from NUS (title 00050010-10000100)")
    parser.add_argument("--otp", default="input/otp.bin", help="otp.bin to read the common key from (default: input/otp.bin)")
    parser.add_argument("--output", "-o", default="rebuild/boot1.bin", help="Output file for boot1 (default: rebuild/boot1.bin)")
    args = parser.parse_args()

    try:
        download_boot1(args.otp, args.output)
    except (OSError, ValueError, urllib.error.URLError) as e:
        sys.exit(f"Error: {e}")

if __name__ == "__main__":
    main()
