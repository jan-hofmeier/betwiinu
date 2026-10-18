#!/bin/bash
set -e

# usage: ./setup_osv10_jnus.sh [otp.bin]   (default: input/otp.bin)
OTP="${1:-input/otp.bin}"
if [ ! -f "$OTP" ]; then
    echo "Error: $OTP not found (pass the path to an otp.bin)"
    exit 1
fi
OTP="$(realpath "$OTP")"
if [ "$(stat -c%s "$OTP")" -ne 1024 ]; then
    echo "Error: $OTP is not a 1024-byte otp.bin"
    exit 1
fi

echo "Starting OSv10 setup for SLC rebuild..."

# Paths
BASE_DIR="$(pwd)"
SLC_REBUILD="$BASE_DIR/rebuild/slc"
DOWNLOADS="$BASE_DIR/downloads"
JNUS_DIR="$DOWNLOADS/jnus"
JNUS_RELEASE_URL="https://github.com/Maschell/JNUSTool/releases/download/0.3b/release.zip"
JNUS_RELEASE_SHA256="95ef9f2c9b421cc05b9d6e4c5c0c39161005920617a6b19137e4e211130e572b"

if [ -z "$JNUS_JAR" ] && [ ! -f "$DOWNLOADS/JNUSTool.jar" ]; then
    echo "JNUSTool.jar not found, downloading JNUSTool 0.3b from GitHub..."
    JNUS_ZIP="$(mktemp)"
    curl -sfL -o "$JNUS_ZIP" "$JNUS_RELEASE_URL"
    if ! echo "$JNUS_RELEASE_SHA256  $JNUS_ZIP" | sha256sum -c --quiet; then
        rm -f "$JNUS_ZIP"
        echo "Error: downloaded JNUSTool release doesn't match the expected SHA-256"
        exit 1
    fi
    mkdir -p "$DOWNLOADS"
    python3 -I -c "import sys, zipfile; zipfile.ZipFile(sys.argv[1]).extract('JNUSTool.jar', sys.argv[2])" "$JNUS_ZIP" "$DOWNLOADS"
    rm -f "$JNUS_ZIP"
fi
JNUS_JAR="$(realpath "${JNUS_JAR:-$DOWNLOADS/JNUSTool.jar}")"
if [ ! -f "$JNUS_JAR" ]; then
    echo "Error: $JNUS_JAR not found"
    exit 1
fi

# Target directories
CODE_DIR="$SLC_REBUILD/sys/title/00050010/1000400a/code"
TICKET_DIR="$SLC_REBUILD/sys/rights/ticket/sys/0002"

# Replace only the OSv10 title and its ticket, keep the rest of the tree
rm -rf "$SLC_REBUILD/sys/title/00050010/1000400a"
rm -f "$TICKET_DIR/00000000.tik"
rm -rf "$JNUS_DIR"
mkdir -p "$CODE_DIR"
mkdir -p "$TICKET_DIR"
mkdir -p "$JNUS_DIR"

cd "$JNUS_DIR"
# JNUSTool reads the common key from line 2 of its config; take it from the
# OTP (0xE0) instead of keeping a copy of the key around, and remove it again
# when done.
COMMON_KEY="$(od -An -tx1 -j $((0xE0)) -N 16 "$OTP" | tr -d ' \n')"
trap 'rm -f "$JNUS_DIR/config"' EXIT
cat > config <<EOF_CONFIG
http://ccs.cdn.wup.shop.nintendo.net/ccs/download
$COMMON_KEY
updatetitles.csv
https://tagaya.wup.shop.nintendo.net/tagaya/versionlist/EUR/EU/latest_version
https://tagaya-wup.cdn.nintendo.net/tagaya/versionlist/EUR/EU/list/%d.versionlist
EOF_CONFIG

echo "Downloading decrypted OSv10 files via JNUSTool..."
echo
echo "  JNUSTool opens a window now: tick \"root\" in the file tree and press"
echo "  \"Download\". Close the window once the download has finished."
echo
java -jar "$JNUS_JAR" 000500101000400A > jnus_dec.log

echo "Moving decrypted code files..."
cp -r 000500101000400A/code/* "$CODE_DIR/"

echo "Fetching TMD and Ticket directly from NUS..."
curl -s -o "$CODE_DIR/title.tmd" http://ccs.cdn.wup.shop.nintendo.net/ccs/download/000500101000400A/tmd
curl -s -o "$TICKET_DIR/00000000.tik" http://ccs.cdn.wup.shop.nintendo.net/ccs/download/000500101000400A/cetk

echo "Extracting FST..."
# Find the decrypted title key and FST ID from the JNUSTool log
TITLE_KEY=$(grep "Decrypted Key" jnus_dec.log | awk '{print $4}')
FST_ID=$(grep "Getting FST from server." jnus_dec.log -B 1 | grep "No cached FST" | sed -n 's/.*(\(.*\)).*/\1/p' | head -n 1)

if [ -z "$FST_ID" ]; then
    # Fallback to 00001322 if grep failed (e.g. if it was cached or different output)
    FST_ID="00001322"
fi

echo "Fetching encrypted FST (${FST_ID}.app) directly from NUS..."
curl -s -o "${FST_ID}.app" "http://ccs.cdn.wup.shop.nintendo.net/ccs/download/000500101000400A/${FST_ID}"

# The IV for the FST is its ID padded to 16 bytes (32 hex characters)
IV="${FST_ID}000000000000000000000000"

openssl enc -d -nopad -aes-128-cbc -K "$TITLE_KEY" -iv "$IV" -in "${FST_ID}.app" -out "$CODE_DIR/title.fst"

echo "Setup complete! OSv10 has been placed in rebuild/slc."
