# betwiinu

Fork of `betwiin` for the Wii U SLC (system NAND). Original Wii `betwiin` is here:
http://wiibrew.org/wiki/Betwiin

`nand.py` is the shared library: NAND spare/ECC handling, AES encrypt/decrypt,
HMAC, and SFFS (superblock/FST/FAT) parsing. Everything else below is built on
top of it.

There are two different things you might want to do with an SLC, covered
below:

1. **Recrypt an existing SLC dump for a different console** - the original
   `betwiin` use case. You already have a complete, working SLC and just need its content
   re-keyed to boot on another console. (This still needs manual fixing of the serial and so on)
2. **Rebuild an SLC from scratch** - assemble a new SLC image from
   individual pieces (some fetched fresh from Nintendo, some pulled from a
   donor dump) rather than re-keying one complete existing dump.

## 1. Recrypting an existing SLC to a different console

This is the original purpose of the tool: take a complete SLC dump from one
console and re-encrypt/re-HMAC its *entire* contents (files,
superblocks) under a different console's keys, so the same data can be
written back and booted on that other console. Content and metadata are
preserved byte-for-byte; only the per-console AES/HMAC keys change.

`betwiin.py` uses fixed paths rather than CLI args:

```
input/SLC.RAW    source SLC dump
input/otp.bin    source console's OTP (keys the dump was encrypted with)
output/otp.bin   target console's OTP (keys to re-encrypt for)
```

```bash
mkdir -p input output
cp /path/to/source_SLC.RAW input/SLC.RAW
cp /path/to/source_otp.bin input/otp.bin
cp /path/to/target_otp.bin output/otp.bin
python3 betwiin.py
```

This writes `output/SLC.RAW`: boot1/boot2 copied as-is, every SFFS file
decrypted with the source keys and re-encrypted/re-HMAC'd with the target
keys, and a fresh superblock written with a bumped version. `scfm.img` is
skipped (it's never encrypted/HMAC'd on the NAND to begin with).

## 2. Rebuilding an SLC from scratch

This path assembles a directory tree from several sources — some
console-specific (must come from a donor dump of the target console, or the
target console itself), some generic (fetched fresh from Nintendo) — and
then builds a brand-new image from it. The three steps below are typically
used in this order: extract whatever you need from a donor dump, fetch the
generic pieces, then build.

### 2.1 Extracting from an existing SLC dump

`extract_slc.py` pulls files/folders, `boot1.bin`, or the bad-block list out
of a real SLC dump.

```bash
# Extract everything (all SFFS files, boot1, bad blocks)
python3 extract_slc.py --image SLC.RAW --otp otp.bin --all -o ./extracted

# Extract just specific paths
python3 extract_slc.py --image SLC.RAW --otp otp.bin -e /sys/config -o ./extracted
python3 extract_slc.py --image SLC.RAW --otp otp.bin /sys/config /scfm.img boot1

# Legacy / raw component extraction
python3 extract_slc.py --image SLC.RAW --otp otp.bin --boot1 boot1.bin --scfm scfm.img --bad-blocks bad_blocks.txt
```

`--otp` is only required when extracting actual SFFS file/folder content
(it's encrypted). Extracting just `--boot1` or `--bad-blocks` reads
unencrypted NAND data directly and needs no key material at all, which
matters if you have an SLC dump but not the matching `otp.bin`:

```bash
python3 extract_slc.py --image SLC.RAW --bad-blocks bad_blocks.txt
python3 extract_slc.py --image SLC.RAW --boot1 boot1.bin
```

`--bad-blocks` collects blocks marked bad in the NAND spare area (factory)
and blocks with clusters marked bad (`0xFFFD`) in the FAT of the newest
superblock (e.g. found bad by IOSU later). If isfshax is installed, its
superblock slots are left out: isfshax marks them bad in the FAT only to keep
IOSU away, so they aren't really bad - unless isfshax itself flagged one as
bad. Each line notes where the block was found (`# spare` / `# FAT`).

This also works on a chip that has never been in a Wii U (no SFFS on it):
then only the spare markers are read. Those are the factory markers, so this
only works on a fresh chip (or one from a Wii U) - erasing a chip, or using
it in another device, can destroy them.

`--boot1` checks both boot1 slots (blocks 0 and 1), warns if one is invalid
or they differ, and writes just the boot1 image (header + body, e.g. 0xE200
bytes), not the whole slot. `extract_boot1_nus.py` validates the download the
same way and strips the content padding, so both produce the same file.

### 2.2 Fetching generic components from Nintendo's servers

Some of what belongs in the SLC isn't console-specific and doesn't require a
donor dump — it can be pulled straight from the NUS (Nintendo Update Server)
CDN, decrypted with just the common key out of your `otp.bin`:

```bash
# boot1 (title 00050010-10000100), downloaded + decrypted directly over HTTP,
# no JNUS/cdecrypt dependency
python3 extract_boot1_nus.py --otp otp.bin -o boot1.bin

# OSv10 system title (00050010-1000400a): code files + ticket
./setup_osv10_jnus.sh otp.bin   # via JNUSTool (needs java; JNUSTool.jar in the working
                                # directory or JNUS_JAR=/path/to/JNUSTool.jar); its config
                                # is generated with the common key from otp.bin
# or, if you already have an encrypted dump via MLCRestorerDownloader:
./setup_osv10_cdecrypt.sh <dir>  # via cdecrypt (from PATH or CDECRYPT_CMD=...) on the
                                 # MLCRestorerDownloader output dir of 000500101000400a
                                 # (note: cdecrypt has the common key built in instead of
                                 # reading otp.bin)
```

Both setup scripts lay the title's code out at
`slc_rebuild/sys/title/00050010/1000400a/code/` and its ticket at
`slc_rebuild/sys/rights/ticket/sys/0002/00000000.tik`, ready to hand to
`build_slc.py --input-dir slc_rebuild` (next section).

The ticket itself is fetched the same direct-HTTP way as boot1 (both scripts
just `curl`/`GET` `.../ccs/download/<titleid>/cetk` — no JNUS needed for the
ticket, since system-title tickets are "common tickets" signed once by
Nintendo and decryptable by any console's common key). The destination path
(`sys/rights/ticket/sys/0002/00000000.tik`) was confirmed by extracting
`/sys/rights/ticket` from a real dump and reading the title-ID field embedded
at offset `0x1DC` of each `.tik` file — it isn't a known hash formula, so
it's only verified correct for consoles whose ticket cache already contains
that title at that slot, not guaranteed for a from-scratch/empty ticket
cache.

`/sys/config/system.xml` and `/sys/config/sys_prod.xml` are generated by
`sys_config.py` from the serial on the target console's sticker (e.g.
`FEM123456784`), written straight into the rebuild tree:

```bash
python3 sys_config.py --serial FEM123456784 -o slc_rebuild
```

The serial is validated: a letter prefix (`code_id`) followed by 9 digits,
the last of which is a check digit (`(10 - (d1+d3+d5+d7 + 3*(d2+d4+d6+d8))) % 10`,
the same scheme as the Wii). The prefix selects the region (`FEM` = EUR,
`FW` = USA); for other prefixes pass `--region`. Only EUR and USA are
supported for now, since their per-region values (product area, PAL/NTSC,
5 GHz country code, model number, Wii U Menu title ID) were taken from real
dumps; the generated EUR files are byte-identical to the test dump's.

Everything else under `/sys/config`, `/sys/prefs`, other ticket entries,
etc. currently has to come from an existing dump — there's no generator for
it yet. Whether the system actually recreates some of that on first boot is
still untested.

### 2.3 Building a fresh SLC image from a directory

`build_slc.py` creates a brand-new `SLC.RAW` from a plain directory tree
(e.g. `slc_rebuild/` assembled above): it allocates FAT clusters, builds the
FST with the correct per-path mode/attr/uid/gid (see
`slc_permissions_list.txt` for the reverse-engineered rules), encrypts and
HMACs every cluster, and writes all 64 redundant superblocks. The FAT uses
the same markers as IOSU: `0xFFFE` free, `0xFFFB` end of chain, `0xFFFC`
reserved (both boot1 slots and the superblock area), `0xFFFD` bad.

```bash
python3 build_slc.py \
  --input-dir  slc_rebuild \
  --output-image SLC.RAW \
  --otp otp.bin \
  --boot1 boot1.bin \
  --bad-blocks bad_blocks.txt
```

- `--otp` — the target console's OTP (console-unique, must come from real
  hardware; can't be synthesized).
- `--boot1` — the boot1 image (from §2.1 or §2.2). It's validated (ancast
  magic + SHA-1 of the body) and written to both boot1 slots: block 0
  (primary) and block 1 (backup); both are reserved in the FAT. A slot on a
  bad block is skipped (the other one is still written).
  `--boot-image` takes boot1 from another full SLC dump instead (the first
  valid slot). The SEEPROM's boot1 version entries aren't touched here;
  minute syncs them with the NAND when flashing.
- `--scfm` — optional; include an `scfm.img`. Not needed if you're setting up
  a fresh MLC (scfm.img relates to the SD/MLC storage mapping, not SLC system
  config, and gets regenerated for whatever MLC is actually attached). Leave
  it off and no `scfm.img` entry is created at all.
- `--bad-blocks` — optional; marks the given blocks bad in both places: the
  NAND spare area (pages 0 and 1 zeroed, like a factory marker) and the FAT
  (`0xFFFD`). Superblock and boot1 slots on bad blocks are skipped.

  Both matter because minute's restore erases and programs every block,
  bad ones included: the erase can wipe the chip's factory marker, and only
  the marker in the image puts it back - which may not fully work on a bad
  block. IOSU itself goes by the FAT, so that entry is the reliable one.

  Bad blocks are a defect map of the *physical NAND chip*, not of the
  console or its data — so the list has to come from whichever chip is
  actually going to be written, not from the console whose keys/content
  you're using:
  - Writing back to the same chip you dumped? Use the bad-block list
    extracted from that dump (§2.1) — no `otp.bin` needed for this.
  - Replacing the SLC chip with one pulled from a different console? Extract
    the bad-block list from a raw dump of *that* chip instead (again, no
    `otp.bin`/keys needed, just a raw read of the new chip).
  - Writing to a chip that didn't come out of a Wii U at all (e.g. a fresh
    generic NAND)? Dump it raw before writing anything and extract the list
    from that dump - the factory markers are in the spare area. Never reuse
    someone else's list.
