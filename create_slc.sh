#!/bin/bash
# Creates a new SLC image from scratch, see docs/create_slc.md.
# usage: ./create_slc.sh <serial> [region]
#   serial          serial from the target console's sticker, e.g. FEM123456784
#   region          EUR or USA, only needed if the serial prefix is unknown
#   input/otp.bin   OTP of the target console (required)
#   input/SLC.RAW   raw dump of the SLC chip that will be written (for its
#                   bad blocks and, if it still has one, boot1)
# The result is rebuild/SLC.RAW; boot1, the bad block list and the files that
# went into it are kept in rebuild/.
set -e
cd "$(dirname "$0")"

OTP=input/otp.bin
DUMP=input/SLC.RAW
REBUILD=rebuild
SERIAL=$1
REGION=$2

fail() {
    echo "Error: $*"
    exit 1
}

if [ -z "$SERIAL" ] || [ $# -gt 2 ]; then
    echo "usage: $0 <serial> [region]"
    echo "  serial: from the target console's sticker, e.g. FEM123456784"
    exit 1
fi

echo "== Checking prerequisites"
python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))' 2>/dev/null \
    || fail "python3 3.10 or newer is needed"
python3 -c 'import Crypto.Cipher.AES' 2>/dev/null \
    || fail "pycryptodome is missing (pip3 install -r requirements.txt)"
python3 -c '
import sys, sys_config
try:
    sys_config.parse_serial(sys.argv[1], sys.argv[2] or None)
except ValueError as e:
    sys.exit(f"Error: {e}")' "$SERIAL" "$REGION" || exit 1
[ -f "$OTP" ] || fail "$OTP not found: put the target console's otp.bin there"
if [ -e "$REBUILD" ]; then
    fail "$REBUILD/ already exists. Move it away or delete it (rm -rf $REBUILD) to start from scratch."
fi
mkdir -p "$REBUILD"

echo
echo "== Extracting bad blocks and boot1 from $DUMP"
if [ -f "$DUMP" ]; then
    python3 extract_slc.py --image "$DUMP" bad_blocks
    if ! python3 extract_slc.py --image "$DUMP" boot1; then
        echo "No valid boot1 in the dump, downloading it from NUS instead"
        rm -f "$REBUILD/boot1.bin"
    fi
else
    rmdir "$REBUILD"
    fail "$DUMP not found: dump the SLC chip that will be written first (minute: Dump SLC.RAW), its bad blocks are needed"
fi

if [ ! -f "$REBUILD/boot1.bin" ]; then
    echo
    echo "== Downloading boot1 from NUS"
    python3 download_boot1.py --otp "$OTP" -o "$REBUILD/boot1.bin"
fi

echo
echo "== Downloading OSv10"
python3 download_osv10.py --otp "$OTP" -o "$REBUILD/slc"

echo
echo "== Generating system.xml and sys_prod.xml"
python3 sys_config.py --serial "$SERIAL" ${REGION:+--region "$REGION"} -o "$REBUILD/slc"

echo
echo "== Building the SLC image"
python3 build_slc.py --rebuild-dir "$REBUILD" --otp "$OTP"

echo
echo "Done: $REBUILD/SLC.RAW"
echo "Next: copy it to the root of the SD card as SLC.RAW, restore it with minute"
echo "(Restore SLC.RAW), then install the other system titles with wafel_setup_mlc."
