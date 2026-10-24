#!/usr/bin/env python3
"""Download OSv10 (00050010-1000400a) from NUS and put it into the SLC tree.

Writes the decrypted title to <slc_dir>/sys/title/00050010/1000400a, and its
ticket, cert.sys and title.list to <slc_dir>/sys/rights. Only these are
replaced, the rest of the tree is kept. The title key is decrypted with the
common key from otp.bin.
"""

import argparse
import os
import shutil
import sys
import urllib.error

from slctools.nus import Title, download_title, read_common_key
from slctools.rights import TICKET_PATH, CERT_SYS_PATH, TITLE_LIST_PATH, write_rights

TITLE_ID = "000500101000400a"
TITLE_DIR = "sys/title/00050010/1000400a"

def main():
    parser = argparse.ArgumentParser(description="Download OSv10 from NUS into the SLC tree")
    parser.add_argument("--otp", default="input/otp.bin", help="otp.bin to read the common key from (default: input/otp.bin)")
    parser.add_argument("-o", "--output-dir", default="rebuild/slc", help="SLC root directory (default: rebuild/slc)")
    parser.add_argument("--cache-dir", default=f"downloads/{TITLE_ID}", help=f"Keep the encrypted downloads here and reuse them (default: downloads/{TITLE_ID})")
    parser.add_argument("--source", help="Use an already downloaded title instead of NUS, e.g. MLCRestorerDownloader's 000500101000400a directory (title.tmd, title.tik, *.app)")
    args = parser.parse_args()

    try:
        common_key = read_common_key(args.otp)
    except (OSError, ValueError) as e:
        sys.exit(f"Error: {e}")

    title_dir = os.path.join(args.output_dir, TITLE_DIR)
    for path in (TICKET_PATH, CERT_SYS_PATH, TITLE_LIST_PATH):
        path = os.path.join(args.output_dir, path)
        if os.path.exists(path):
            os.remove(path)
    shutil.rmtree(title_dir, ignore_errors=True)

    title = Title(TITLE_ID, source_dir=args.source, cache_dir=None if args.source else args.cache_dir)
    try:
        tmd, cetk = download_title(title, common_key, title_dir)
        write_rights(tmd, cetk, args.output_dir)
    except (OSError, ValueError, NotImplementedError, urllib.error.URLError) as e:
        sys.exit(f"Error: {e}")
    print(f"OSv10 is in {title_dir}")

if __name__ == "__main__":
    main()
