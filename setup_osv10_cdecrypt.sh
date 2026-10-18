#!/bin/bash
set -e

# Encrypted title as downloaded by MLCRestorerDownloader
# (output/SLC/<region>/000500101000400a, containing title.tmd/title.tik/*.app)
MLC_DOWN_DIR="$(realpath "${1:?usage: $0 <MLCRestorerDownloader output dir of 000500101000400a>}")"

# CDecrypt from PATH (can be overridden by user)
CDECRYPT_CMD="${CDECRYPT_CMD:-cdecrypt}"

if ! command -v $CDECRYPT_CMD &> /dev/null; then
    echo "Error: $CDECRYPT_CMD not found in PATH."
    echo "Please install a native CDecrypt (e.g. VitaSmith's cdecrypt) and make sure it's in your PATH,"
    echo "or run the script as: CDECRYPT_CMD=/path/to/cdecrypt ./setup_osv10_cdecrypt.sh"
    exit 1
fi

BASE_DIR="$(pwd)"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SLC_REBUILD="$BASE_DIR/rebuild/slc"
CODE_DIR="$SLC_REBUILD/sys/title/00050010/1000400a/code"
TICKET_DIR="$SLC_REBUILD/sys/rights/ticket/sys/0002"

# Ensure the MLCRestorerDownloader output exists
if [ ! -d "$MLC_DOWN_DIR" ] || [ ! -f "$MLC_DOWN_DIR/title.tmd" ]; then
    echo "Error: Could not find encrypted OSv10 files in $MLC_DOWN_DIR"
    echo "Please run MLCRestorerDownloader first to download the title."
    exit 1
fi

# Replace only the OSv10 title and its ticket, keep the rest of the tree
rm -rf "$SLC_REBUILD/sys/title/00050010/1000400a"
rm -f "$TICKET_DIR/00000000.tik" "$SLC_REBUILD/sys/rights/sys/cert.sys" "$SLC_REBUILD/sys/rights/sys/title.list"
mkdir -p "$CODE_DIR"

echo "Extracting encrypted OSv10 files using CDecrypt..."
# Change into CODE_DIR because cdecrypt typically extracts to the current working directory
cd "$CODE_DIR"

# Run CDecrypt using the downloaded TMD and Ticket
$CDECRYPT_CMD "$MLC_DOWN_DIR/title.tmd" "$MLC_DOWN_DIR/title.tik"

# Ensure title.tmd and title.fst are also in the code dir (CDecrypt usually handles this, 
# but we can explicitly copy the TMD just in case)
if [ ! -f "$CODE_DIR/title.tmd" ]; then
    cp "$MLC_DOWN_DIR/title.tmd" "$CODE_DIR/"
fi

# Return to base dir
cd "$BASE_DIR"

# The ticket is stored without its certificates; those go into cert.sys,
# and the title into title.list
echo "Setting up ticket and certificates..."
PYTHONPATH="$SCRIPT_DIR" python3 -m slctools.rights "$MLC_DOWN_DIR/title.tmd" "$MLC_DOWN_DIR/title.tik" "$SLC_REBUILD"

echo "Setup complete! OSv10 has been placed in rebuild/slc via CDecrypt."
