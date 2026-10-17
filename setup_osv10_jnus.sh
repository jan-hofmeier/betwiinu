#!/bin/bash
set -e

echo "Starting OSv10 setup for SLC rebuild..."

# Paths
BASE_DIR="$(pwd)"
SLC_REBUILD="$BASE_DIR/slc_rebuild"
JNUS_DIR="$BASE_DIR/jnus_test_build"
JNUS_JAR="/home/jan/wiiu/jnus/JNUSTool.jar"
JNUS_CONFIG="/home/jan/wiiu/jnus/config"

# Target directories
CODE_DIR="$SLC_REBUILD/sys/title/00050010/1000400a/code"
TICKET_DIR="$SLC_REBUILD/sys/rights/ticket/sys/0002"

# Clean previous build
rm -rf "$SLC_REBUILD"
rm -rf "$JNUS_DIR"
mkdir -p "$CODE_DIR"
mkdir -p "$TICKET_DIR"
mkdir -p "$JNUS_DIR"

cd "$JNUS_DIR"
cp "$JNUS_CONFIG" .

echo "Downloading decrypted OSv10 files via JNUSTool..."
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

echo "Setup complete! The slc_rebuild directory has been created."
