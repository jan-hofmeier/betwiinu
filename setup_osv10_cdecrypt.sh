#!/bin/bash
set -e

# Default path for CDecrypt (can be overridden by user)
CDECRYPT_CMD="${CDECRYPT_CMD:-/home/jan/wiiu/cdecrypt/cdecrypt}"

if ! command -v $CDECRYPT_CMD &> /dev/null; then
    echo "Error: $CDECRYPT_CMD not found in PATH."
    echo "Please install a native CDecrypt (e.g. VitaSmith's cdecrypt) and make sure it's in your PATH,"
    echo "or run the script as: CDECRYPT_CMD=/path/to/cdecrypt ./setup_osv10_cdecrypt.sh"
    exit 1
fi

BASE_DIR="$(pwd)"
MLC_DOWN_DIR="/home/jan/Downloads/MLCRestorerDownloader_Linux_x86_64/output/SLC/EUR/000500101000400a"
SLC_REBUILD="$BASE_DIR/slc_rebuild"
CODE_DIR="$SLC_REBUILD/sys/title/00050010/1000400a/code"
TICKET_DIR="$SLC_REBUILD/sys/rights/ticket/sys/0002"

# Ensure the MLCRestorerDownloader output exists
if [ ! -d "$MLC_DOWN_DIR" ] || [ ! -f "$MLC_DOWN_DIR/title.tmd" ]; then
    echo "Error: Could not find encrypted OSv10 files in $MLC_DOWN_DIR"
    echo "Please run MLCRestorerDownloader first to download the title."
    exit 1
fi

# Create target directories
mkdir -p "$CODE_DIR"
mkdir -p "$TICKET_DIR"

echo "Extracting encrypted OSv10 files using CDecrypt..."
# Change into CODE_DIR because cdecrypt typically extracts to the current working directory
cd "$CODE_DIR"

# Run CDecrypt using the downloaded TMD and Ticket
$CDECRYPT_CMD "$MLC_DOWN_DIR/title.tmd" "$MLC_DOWN_DIR/title.tik"

# Depending on the CDecrypt version, it might output a 'title.tmd' and 'title.fst' alongside the code files.
# But it does not typically put the ticket in the correct rights/ticket folder natively.
echo "Setting up ticket..."
cp "$MLC_DOWN_DIR/title.tik" "$TICKET_DIR/00000000.tik"

# Ensure title.tmd and title.fst are also in the code dir (CDecrypt usually handles this, 
# but we can explicitly copy the TMD just in case)
if [ ! -f "$CODE_DIR/title.tmd" ]; then
    cp "$MLC_DOWN_DIR/title.tmd" "$CODE_DIR/"
fi

# Return to base dir
cd "$BASE_DIR"

echo "Setup complete! The slc_rebuild directory has been constructed via CDecrypt."
