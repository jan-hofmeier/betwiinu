"""Tickets and certificates for the SLC.

NUS appends the certificate chain to what it serves: a TMD comes with
CP0000000b + CA00000003, a ticket (cetk) with XS0000000c + CA00000003. On the
console the TMD is stored as downloaded, but tickets are stored bare (0x350
bytes each, several per .tik file), and the certificates live in
/sys/rights/sys/cert.sys: XS0000000c, CA00000003, CP0000000b.
/sys/rights/sys/title.list lists the title IDs (u64 each) that have a ticket.

usage: python3 -m slctools.rights <title.tmd> <cetk> <slc_dir>
  writes <slc_dir>/sys/rights/ticket/sys/0002/00000000.tik,
  <slc_dir>/sys/rights/sys/cert.sys and <slc_dir>/sys/rights/sys/title.list
"""

import os
import struct
import sys

TICKET_SIZE = 0x350
TICKET_PATH = "sys/rights/ticket/sys/0002/00000000.tik"
CERT_SYS_PATH = "sys/rights/sys/cert.sys"
TITLE_LIST_PATH = "sys/rights/sys/title.list"
CERT_SYS_ORDER = ("Root-CA00000003-XS0000000c", "Root-CA00000003", "Root-CA00000003-CP0000000b")

# signature type -> signature + padding, key type -> key + padding
SIGNATURE_SIZES = {0x10000: 0x200 + 0x3C, 0x10001: 0x100 + 0x3C, 0x10002: 0x3C + 0x40,
                   0x10003: 0x200 + 0x3C, 0x10004: 0x100 + 0x3C, 0x10005: 0x3C + 0x40}
KEY_SIZES = {0: 0x200 + 0x4 + 0x34, 1: 0x100 + 0x4 + 0x34, 2: 0x3C + 0x3C}

def parse_certs(data, offset):
    """Parses the certificate chain starting at offset: {"issuer-name": cert}."""
    certs = {}
    while offset < len(data):
        sig_type, = struct.unpack_from(">I", data, offset)
        if sig_type not in SIGNATURE_SIZES:
            raise ValueError(f"unknown signature type 0x{sig_type:x} at 0x{offset:x}")
        body = offset + 4 + SIGNATURE_SIZES[sig_type]
        issuer = data[body:body + 0x40].rstrip(b"\0").decode()
        key_type, = struct.unpack_from(">I", data, body + 0x40)
        name = data[body + 0x44:body + 0x84].rstrip(b"\0").decode()
        end = body + 0x88 + KEY_SIZES[key_type]
        if end > len(data):
            raise ValueError(f"certificate {issuer}-{name} is truncated")
        certs[f"{issuer}-{name}"] = bytes(data[offset:end])
        offset = end
    return certs

def tmd_size(tmd):
    """Size of a Wii U TMD without the certificates appended to it."""
    num_contents, = struct.unpack_from(">H", tmd, 0x1DE)
    return 0xB04 + num_contents * 0x30

def make_cert_sys(tmd, cetk):
    certs = parse_certs(cetk, TICKET_SIZE)
    for name, cert in parse_certs(tmd, tmd_size(tmd)).items():
        if certs.setdefault(name, cert) != cert:
            raise ValueError(f"{name} differs between TMD and ticket")
    missing = [name for name in CERT_SYS_ORDER if name not in certs]
    if missing:
        raise ValueError(f"certificate(s) missing: {', '.join(missing)}")
    return b"".join(certs[name] for name in CERT_SYS_ORDER)

def write_rights(tmd, cetk, slc_dir):
    ticket = cetk[:TICKET_SIZE]
    files = ((TICKET_PATH, ticket),
             (CERT_SYS_PATH, make_cert_sys(tmd, cetk)),
             (TITLE_LIST_PATH, ticket[0x1DC:0x1E4]))
    for path, data in files:
        out_path = os.path.join(slc_dir, path)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(data)
        print(f"Wrote {out_path} ({len(data)} bytes)")

if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__.strip().split("\n\n")[-1])
    with open(sys.argv[1], "rb") as f:
        tmd = f.read()
    with open(sys.argv[2], "rb") as f:
        cetk = f.read()
    try:
        write_rights(tmd, cetk, sys.argv[3])
    except ValueError as e:
        sys.exit(f"Error: {e}")
