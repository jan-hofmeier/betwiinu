#!/usr/bin/env python3
"""Generate /sys/config/system.xml and /sys/config/sys_prod.xml.

sys_prod.xml holds the console's production data (serial, region, model).
It comes from one of:
- the console's SEEPROM (seeprom.bin, dumped with minute), which holds all of
  sys_prod in plain text, so any region works;
- the serial printed on the sticker of the target console, e.g.
  "FEM123456784": a code_id prefix (letters) followed by a 9-digit serial_id
  whose last digit is a check digit. The other fields come from the per-region
  values below (EUR and USA only).

Both templates reproduce byte-for-byte the files found in real dumps
(firmware 5.5.x, sys_prod version 5 / system version 21).

A rebuilt SLC needs both: the console doesn't boot without them.
"""

import argparse
import os
import re
import sys
from slctools.seeprom import read_seeprom

# Per-region values for --serial, taken from real EUR/USA dumps. Other regions
# (JPN, ...) aren't included because no verified dump was available; with
# --seeprom they come from the SEEPROM instead.
REGIONS = {
    "EUR": {
        "product_area": 4,
        "game_region": 4,
        "ntsc_pal": "PAL",
        "5ghz_country_code": "EU",
        "5ghz_country_code_revision": 24,
        "model_number": "WUP-101(03)",
    },
    "USA": {
        "product_area": 2,
        "game_region": 2,
        "ntsc_pal": "NTSC",
        "5ghz_country_code": "Q2",
        "5ghz_country_code_revision": 7,
        "model_number": "WUP-101(02)",
    },
}

# sys_prod product_area -> region
AREA_REGIONS = {1: "JPN", 2: "USA", 4: "EUR"}

# system.xml default_title_id: the region's Wii U Menu
MENU_TITLE_IDS = {
    "JPN": "0005001010040000",
    "USA": "0005001010040100",
    "EUR": "0005001010040200",
}

# Serial prefix (code_id) -> region, as seen on real consoles.
CODE_ID_REGIONS = {
    "FEM": "EUR",
    "FW": "USA",
}

SERIAL_RE = re.compile(r"^([A-Z]{1,7})(\d{9})$")

SYS_PROD_TEMPLATE = """\
<?xml version="1.0" encoding="utf-8"?>
<sys_prod type="complex" access="710">
  <version type="unsignedInt" length="4" access="710">5</version>
  <eeprom_version type="unsignedShort" length="2" access="710">{eeprom_version}</eeprom_version>
  <product_area type="unsignedInt" length="4" access="710">{product_area}</product_area>
  <game_region type="unsignedInt" length="4" access="700">{game_region}</game_region>
  <ntsc_pal type="string" length="5" access="700">{ntsc_pal}</ntsc_pal>
  <5ghz_country_code type="string" length="4" access="710">{5ghz_country_code}</5ghz_country_code>
  <5ghz_country_code_revision type="unsignedByte" length="1" access="710">{5ghz_country_code_revision}</5ghz_country_code_revision>
  <code_id type="string" length="8" access="710">{code_id}</code_id>
  <serial_id type="string" length="12" access="710">{serial_id}</serial_id>
  <model_number type="string" length="16" access="710">{model_number}</model_number>
</sys_prod>
"""

SYSTEM_TEMPLATE = """\
<?xml version="1.0"?>
<system type="complex" access="777">
  <version type="unsignedInt" length="4">21</version>
  <cmdFlags type="unsignedInt" length="4">0</cmdFlags>
  <default_os_id type="hexBinary" length="8">000500101000400a</default_os_id>
  <default_title_id type="hexBinary" length="8">{default_title_id}</default_title_id>
  <log type="complex" length="0">
    <enable type="unsignedInt" length="4">0</enable>
    <max_size type="unsignedInt" length="4">8388607</max_size>
  </log>
  <standby type="complex" length="0">
    <enable type="unsignedInt" length="4">0</enable>
  </standby>
  <ramdisk type="complex" length="0">
    <cache_user_code type="unsignedInt" length="4">0</cache_user_code>
    <max_file_size type="unsignedInt" length="4">10485760</max_file_size>
    <cache_delay_ms type="unsignedInt" length="4">10000</cache_delay_ms>
  </ramdisk>
  <simulated_ppc_mem2_size type="hexBinary" length="4">00000000</simulated_ppc_mem2_size>
  <dev_mode type="unsignedInt" length="4">0</dev_mode>
  <prev_title_id type="hexBinary" length="8">0000000000000000</prev_title_id>
  <prev_os_id type="hexBinary" length="8">0000000000000000</prev_os_id>
  <default_app_type type="hexBinary" length="4">90000001</default_app_type>
  <default_device_type type="string" length="16" />
  <default_device_index type="unsignedInt" length="4">0</default_device_index>
  <fast_relaunch_value type="unsignedInt" length="4">0</fast_relaunch_value>
  <default_eco_title_id type="hexBinary" length="8">0005001010066000</default_eco_title_id>
</system>
"""

def serial_check_digit(digits):
    """Check digit over the first 8 digits of serial_id (same scheme as the Wii)."""
    odd = sum(int(d) for d in digits[0:8:2])
    even = sum(int(d) for d in digits[1:8:2])
    return (10 - (odd + 3 * even) % 10) % 10

def parse_serial(serial, region=None):
    """Validate a sticker serial; returns (code_id, serial_id, region)."""
    serial = serial.strip().upper().replace(" ", "")
    m = SERIAL_RE.match(serial)
    if not m:
        raise ValueError(f"Invalid serial '{serial}': expected letters followed by 9 digits, e.g. FEM123456784")
    code_id, serial_id = m.groups()

    expected = serial_check_digit(serial_id)
    if int(serial_id[8]) != expected:
        raise ValueError(f"Invalid serial '{serial}': check digit is {serial_id[8]}, expected {expected} (typo?)")

    known_region = CODE_ID_REGIONS.get(code_id)
    if region is None:
        if known_region is None:
            raise ValueError(f"Unknown serial prefix '{code_id}' (known: {', '.join(CODE_ID_REGIONS)}); pass the region explicitly")
        region = known_region
    elif known_region is not None and known_region != region:
        raise ValueError(f"Serial prefix '{code_id}' belongs to region {known_region}, not {region}")
    if region not in REGIONS:
        raise ValueError(f"Unsupported region '{region}' (supported: {', '.join(REGIONS)})")

    return code_id, serial_id, region

def sys_prod_from_serial(serial, region=None):
    code_id, serial_id, region = parse_serial(serial, region)
    return dict(REGIONS[region], code_id=code_id, serial_id=serial_id, eeprom_version=1)

def sys_prod_from_seeprom(path, serial=None, region=None, otp_path=None):
    """Reads sys_prod from a SEEPROM dump; returns (sys_prod, boot1_versions).

    A serial or region passed as well has to match the SEEPROM's. The OTP is
    only needed to read the boot1 versions from an encrypted dump.
    """
    info = read_seeprom(path, otp_path)
    sys_prod = info["sys_prod"]
    seeprom_serial = sys_prod["code_id"] + sys_prod["serial_id"]
    seeprom_region = AREA_REGIONS.get(sys_prod["product_area"])
    if seeprom_region is None:
        raise ValueError(f"{path}: unknown product_area {sys_prod['product_area']} (not a SEEPROM dump?)")

    if serial is not None:
        serial = serial.strip().upper().replace(" ", "")
        if serial != seeprom_serial:
            raise ValueError(f"Serial {serial} doesn't match the SEEPROM's {seeprom_serial} (SEEPROM from another console?)")
    if region is not None and region != seeprom_region:
        raise ValueError(f"Region {region} doesn't match the SEEPROM's {seeprom_region}")

    # The SEEPROM is authoritative, so these only warn
    m = SERIAL_RE.match(seeprom_serial)
    if not m:
        print(f"Warning: SEEPROM serial '{seeprom_serial}' doesn't look like letters followed by 9 digits")
    elif int(m.group(2)[8]) != serial_check_digit(m.group(2)):
        print(f"Warning: SEEPROM serial {seeprom_serial} has a wrong check digit (corrupt dump?)")
    known_region = CODE_ID_REGIONS.get(sys_prod["code_id"])
    if known_region is not None and known_region != seeprom_region:
        print(f"Warning: SEEPROM serial prefix {sys_prod['code_id']} belongs to {known_region}, but its product_area is {seeprom_region}")

    return sys_prod, info["boot1_versions"]

def region_of(sys_prod):
    return AREA_REGIONS[sys_prod["product_area"]]

def generate_sys_prod(sys_prod):
    return SYS_PROD_TEMPLATE.format(**sys_prod).encode("utf-8")

def generate_system(region):
    return SYSTEM_TEMPLATE.format(default_title_id=MENU_TITLE_IDS[region]).encode("utf-8")

def generate_config_files(sys_prod):
    """Returns {slc_path: bytes} for both config files."""
    return {
        "/sys/config/system.xml": generate_system(region_of(sys_prod)),
        "/sys/config/sys_prod.xml": generate_sys_prod(sys_prod),
    }

def main():
    parser = argparse.ArgumentParser(description="Generate system.xml and sys_prod.xml for a Wii U SLC")
    parser.add_argument("--seeprom", help="SEEPROM dump of the target console (seeprom.bin from minute); everything is taken from it")
    parser.add_argument("--serial", help="Serial from the target console's sticker, e.g. FEM123456784 (checked against --seeprom if given)")
    parser.add_argument("--region", choices=sorted(REGIONS), help="Region (default: derived from the serial prefix or the SEEPROM)")
    parser.add_argument("--otp", default=None, help="OTP of the target console, to read the boot1 versions from an encrypted SEEPROM (default: input/otp.bin if it exists)")
    parser.add_argument("-o", "--output-dir", default="rebuild/slc", help="SLC root directory to write sys/config/*.xml into (default: rebuild/slc)")
    args = parser.parse_args()

    if not args.seeprom and not args.serial:
        parser.error("pass --seeprom and/or --serial")
    otp = args.otp
    if otp is None and os.path.exists("input/otp.bin"):
        otp = "input/otp.bin"

    try:
        if args.seeprom:
            sys_prod, boot1_versions = sys_prod_from_seeprom(args.seeprom, args.serial, args.region, otp)
            print(f"SEEPROM: serial {sys_prod['code_id']}{sys_prod['serial_id']}, {region_of(sys_prod)}, {sys_prod['model_number']}")
            if boot1_versions:
                print(f"SEEPROM: boot1 v{boot1_versions[0]} (primary), v{boot1_versions[1]} (copy)")
        else:
            sys_prod = sys_prod_from_serial(args.serial, args.region)
        files = generate_config_files(sys_prod)
    except ValueError as e:
        sys.exit(f"Error: {e}")

    for slc_path, data in files.items():
        out_path = os.path.join(args.output_dir, slc_path.lstrip("/"))
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(data)
        print(f"Wrote {out_path} ({len(data)} bytes)")

if __name__ == "__main__":
    main()
