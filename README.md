# betwiinu

Fork of [betwiin](http://wiibrew.org/wiki/Betwiin) for the Wii U SLC (system
NAND): extract an SLC dump, build a new SLC image from a folder, fetch the
generic parts (boot1, OSv10) from Nintendo's update server, and recrypt a
dump for another console.

## Guides

- [Create a new SLC from scratch](docs/create_slc.md) - boot1 + OSv10 for a
  console whose SLC is lost or replaced; the other system titles are installed
  afterwards with wafel_setup_mlc.
- [Modify an existing SLC](docs/modify_slc.md) - extract a dump, change files,
  repack it for the same console.

This README describes what each tool does.

## Requirements

- Python 3.10 or newer with [pycryptodome](https://www.pycryptodome.org)
  (`pip3 install -r requirements.txt`)
- An internet connection for the tools that download from Nintendo's update
  server (NUS)

## Layout

The scripts in the root are the ones you run, always from the repository
root. They share these working folders (all ignored by git):

```
input/SLC.RAW            your SLC dump (minute: Dump SLC.RAW)
input/otp.bin            the console's OTP
rebuild/slc/             the files that go into the SLC
rebuild/boot1.bin        boot1 image
rebuild/bad_blocks.txt   bad block list of the chip that will be written
rebuild/permissions.txt  FST metadata from an extracted dump
rebuild/SLC.RAW          the built image
downloads/               encrypted NUS downloads, reused on the next run
output/                  betwiin.py's output
```

Every tool defaults to these paths; all of them can be overridden on the
command line.

The rest of the code lives in subfolders:

- `slctools/` - the shared library: `nand.py` (NAND pages and spare area,
  ECC, AES/HMAC, SFFS superblock/FST/FAT parsing), `boot1.py` (boot1 slots
  and ancast validation), `nus.py` (NUS download, title decryption, FST) and
  `rights.py` (tickets and `cert.sys`).
- `research/` - `extract_perms.py`, which lists the FST metadata of a dump,
  and its output `slc_permissions_list.txt`, which the permission rules of
  `build_slc.py` are based on.
- `docs/` - the guides.

## Tools

### create_slc.sh

Runs the whole [from-scratch guide](docs/create_slc.md) in one go. It takes
the serial from the target console's sticker (and the region, if the serial
prefix is unknown):

```bash
./create_slc.sh FEM123456784
```

1. checks the prerequisites and the serial;
2. extracts the bad blocks and boot1 from `input/SLC.RAW`, downloading boot1
   from NUS if the dump has no valid one;
3. downloads OSv10 with `download_osv10.py`;
4. generates `system.xml` and `sys_prod.xml` with `sys_config.py`;
5. builds `rebuild/SLC.RAW`.

It refuses to run if `rebuild/` already exists, so leftovers from an earlier
run never end up in the image.

### extract_slc.py

Extracts files and folders, boot1 and the bad block list from an SLC dump
(default `input/SLC.RAW`) into the rebuild folder (default `rebuild/`, set
with `-o`).

```bash
python3 extract_slc.py --all                 # everything
python3 extract_slc.py boot1 bad_blocks      # no otp.bin needed
python3 extract_slc.py /sys/config /scfm.img # specific paths
python3 extract_slc.py --image SLC.RAW --otp otp.bin --boot1 boot1.bin --bad-blocks bad_blocks.txt
```

- **Files** go to `rebuild/slc/`. They are encrypted, so this needs the OTP of
  the console the dump came from (`--otp`, default `input/otp.bin` if it
  exists). `scfm.img` is stored unencrypted and is extracted as-is.
- **FST metadata:** a complete extraction also writes
  `rebuild/permissions.txt` with the mode, attributes, uid and gid of every
  entry, so `build_slc.py` can repack the tree with exactly the metadata it
  had.
- **boot1** (`rebuild/boot1.bin`): both slots (blocks 0 and 1) are checked,
  with a warning if one is invalid or they differ. Only the boot1 image itself
  is written (header + body, e.g. 0xE200 bytes), not the whole slot.
- **Bad blocks** (`rebuild/bad_blocks.txt`) are collected from two places:
  - the NAND spare area: the factory markers;
  - clusters marked bad (`0xFFFD`) in the FAT of the newest superblock, e.g.
    found bad by IOSU later.

  Each line notes where the block was found (`# spare` / `# FAT`).

  isfshax's superblock slots are left out. isfshax marks them bad in the FAT
  only to keep IOSU away, so they aren't really bad, unless isfshax itself
  flagged one as bad.

  boot1 and the bad blocks aren't encrypted and need no `otp.bin`.

This also works on a chip that has never been in a Wii U (no SFFS on it);
then only the spare markers are read. Those are the factory markers, so this
only works on a fresh chip or one from a Wii U: erasing a chip, or using it
in another device, can destroy them.

### build_slc.py

Builds a new SLC image from the rebuild folder (`-d`, default `rebuild/`):
`rebuild/slc/` plus `boot1.bin`, `bad_blocks.txt` and `permissions.txt` if
they exist, written to `rebuild/SLC.RAW`.

```bash
python3 build_slc.py
python3 build_slc.py --input-dir dir --output-image SLC.RAW --otp otp.bin \
  --boot1 boot1.bin --bad-blocks bad_blocks.txt
```

- **Building:** it allocates FAT clusters, builds the FST, encrypts and HMACs
  every cluster, and writes all 64 superblock slots.
  - The FAT uses the same markers as IOSU: `0xFFFE` free, `0xFFFB` end of
    chain, `0xFFFC` reserved, `0xFFFD` bad.
  - Reserved are both boot1 slots, the superblock area, and a pool of 96
    blocks right below it (from 0x7900, skipping bad blocks). IOSU swaps
    blocks it rewrites with blocks from that pool, so on a used SLC some
    reserved blocks are scattered elsewhere; all real dumps have 96.
  - `scfm.img` is written unencrypted and without HMAC, like on a real
    console.
- **`--otp`:** the target console's OTP (default `input/otp.bin`).
- **Permissions:** the mode, attributes, uid and gid of each entry come from
  `permissions.txt` (`--permissions`). Entries that aren't listed there use
  built-in rules worked out from real dumps (see
  `research/slc_permissions_list.txt`).
- **`--boot1`:** validated (ancast magic + SHA-1 of the body) and written to
  both boot1 slots, block 0 (primary) and block 1 (backup). A slot on a bad
  block is skipped. `--boot-image` takes boot1 from another full SLC dump
  instead. The SEEPROM's boot1 version entries aren't touched; minute syncs
  them when flashing.
- **`--scfm`:** includes an `scfm.img` from somewhere else. One in
  `rebuild/slc/` is included anyway.
- **`--bad-blocks`:** marks the listed blocks bad in two places:
  - the NAND spare area: pages 0 and 1 are zeroed, like a factory marker;
  - the FAT: `0xFFFD`.

  Superblock and boot1 slots on bad blocks are skipped.

  Both places matter. minute's restore erases and programs every block, bad
  ones included: the erase can wipe the chip's factory marker, and only the
  marker in the image puts it back, which may not fully work on a bad block.
  IOSU itself goes by the FAT, so that entry is the reliable one.

  Bad blocks are a defect map of the *physical chip*, so the list has to come
  from a dump of the chip that is going to be written. Never reuse someone
  else's list.

### download_boot1.py

Downloads boot1 (title 00050010-10000100, content 00000009) from NUS and
decrypts it with the common key from `input/otp.bin`. The content is checked
against the TMD, the image is validated like an extracted one, and the
content padding is stripped, so it gives the same file as
`extract_slc.py boot1` (default `rebuild/boot1.bin`).

### download_osv10.py

Downloads OSv10 (00050010-1000400a) from NUS and puts it into `rebuild/slc`:
- its files at `sys/title/00050010/1000400a/code/`, with `title.tmd` and
  `title.fst`;
- its ticket at `sys/rights/ticket/sys/0002/00000000.tik`;
- the certificate store `sys/rights/sys/cert.sys`;
- `sys/rights/sys/title.list`, the list of titles with a ticket.

Only these are replaced; the rest of `rebuild/slc` is left alone.

```bash
python3 download_osv10.py                  # from NUS
python3 download_osv10.py --source <dir>   # from MLCRestorerDownloader's 000500101000400a
```

**Download and decryption** (`slctools/nus.py`):
- The title key is decrypted from the ticket with the common key from the
  OTP; there's no key in the code.
- Each content is decrypted and checked against its SHA-1 in the TMD, then
  the files are cut out of the contents as the FST describes. Hashed
  contents aren't supported, OSv10 has none.
- The encrypted downloads are kept in `downloads/000500101000400a` and reused
  on the next run (`--cache-dir`).
- `--source` takes an already downloaded title instead (`tmd`/`title.tmd`,
  `cetk`/`title.tik`, contents as `<id>` or `<id>.app`).
- The result is byte-identical to the OSv10 on a real console, `title.tmd`
  and `title.fst` included.

**Ticket and certificates** (`slctools/rights.py`):
- System titles have common tickets, so the same ticket works on every
  console.
- NUS appends the certificate chain to what it serves: the TMD comes with
  CP0000000b and CA00000003, the ticket with XS0000000c and CA00000003. The
  console stores the TMD as downloaded, but tickets bare (0x350 bytes each),
  so the certificates are split off the ticket.
- `cert.sys` is put together from those certificates in the console's order
  (XS0000000c, CA00000003, CP0000000b). This makes it byte-identical to a
  real console's, without shipping any certificates.
- `title.list` lists the title ID (u64) of every title with a ticket; on a
  real console it matches the ticket store exactly. Here it's just OSv10.
- The ticket's path was confirmed on a real dump: the title ID is stored at
  offset `0x1DC` of each `.tik`.

Only OSv10 is put into the SLC this way. The other SLC system titles are
installed on the console afterwards with wafel_setup_mlc (see the
[guide](docs/create_slc.md)).

### sys_config.py

Generates `/sys/config/system.xml` and `/sys/config/sys_prod.xml` from the
serial on the target console's sticker. A rebuilt SLC needs both: the console
doesn't boot without them.

```bash
python3 sys_config.py --serial FEM123456784   # writes into rebuild/slc
```

- **Serial validation:** a letter prefix (`code_id`) followed by 9 digits, the
  last of which is a check digit
  (`(10 - (d1+d3+d5+d7 + 3*(d2+d4+d6+d8))) % 10`, the same scheme as the Wii).
- **Region:** the prefix selects it (`FEM` = EUR, `FW` = USA); for other
  prefixes pass `--region`.
- **Supported regions:** only EUR and USA, since their values were taken from
  real dumps. The generated EUR files are byte-identical to a real
  console's.

### betwiin.py

The original betwiin use case: re-encrypt a complete SLC dump for a different
console. Every file is decrypted with the source console's keys and
re-encrypted and re-HMAC'd with the target's. boot1 is copied as-is, and new
superblocks are written. `scfm.img` isn't copied.

```
input/SLC.RAW    source SLC dump
input/otp.bin    source console's OTP
output/otp.bin   target console's OTP
```

`python3 betwiin.py` writes `output/SLC.RAW`. Console-specific files such as
`sys_prod.xml` still have to be fixed by hand.

## Credits

This project builds on the work of many people in the Wii and Wii U scene:

- **bushing / Haxx Enterprises** - the original
  [betwiin](http://wiibrew.org/wiki/Betwiin) (2009) for the Wii NAND, which
  `betwiin.py` and the NAND, ECC, AES/HMAC and SFFS code in
  `slctools/nand.py` are based on.
- **[minute_minute](https://github.com/StroopwafelCFW/minute_minute)** -
  based on [minute](https://github.com/dazjo/minute) by SALT / Dazzozo, with
  work by shinyquagsire23 and other contributors. Dumps and restores the SLC
  and OTP. Its source was the reference for the SEEPROM boot1 slot parameters,
  the ancast header, the ISFS FAT values and how SLC restores handle bad
  blocks.
- **[stroopwafel](https://github.com/shinyquagsire23/stroopwafel)** by
  shinyquagsire23, and
  **[wafel_setup_mlc](https://github.com/StroopwafelCFW/wafel_setup_mlc)**
  (with IOSU patches by GaryOderNichts and Ash, and work by V10lator and
  Lazr1026) - install the remaining system titles on a rebuilt console.
- **[isfshax](https://github.com/isfshax/isfshax)** by rw-r-r-0644 (and the
  [isfshax installer](https://github.com/isfshax/isfshax_installer)) - the
  isfshax superblock and slot layout that `extract_slc.py` recognises when
  collecting bad blocks.
- **[JNUSTool](https://github.com/Maschell/JNUSTool)** by Maschell and
  **[cdecrypt](https://github.com/VitaSmith/cdecrypt)** by crediar
  (maintained by VitaSmith) - earlier versions used them to download and
  decrypt OSv10; they were the reference for `slctools/nus.py`.
- **[MLCRestorerDownloader](https://github.com/Xpl0itU/MLCRestorerDownloader)**
  by Xpl0itU - downloads the system titles for wafel_setup_mlc
  (`download_osv10.py --source` can also take its OSv10 download).
- **[WiiBrew](https://wiibrew.org) and [WiiUBrew](https://wiiubrew.org)** -
  the community documentation of the NAND, title and ticket formats.
- **[pycryptodome](https://www.pycryptodome.org)** - AES for the Python tools.

The FST permission rules (`research/slc_permissions_list.txt`), the
`system.xml` / `sys_prod.xml` templates, the serial check digit and the
bad-block marker layout were worked out by comparing real SLC dumps.
