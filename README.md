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

### 2.2 Fetching generic components from Nintendo's servers

Some of what belongs in the SLC isn't console-specific and doesn't require a
donor dump — it can be pulled straight from the NUS (Nintendo Update Server)
CDN, decrypted with just the common key out of your `otp.bin`:

```bash
# boot1 (title 00050010-10000100), downloaded + decrypted directly over HTTP,
# no JNUS/cdecrypt dependency
python3 extract_boot1_nus.py --otp otp.bin -o boot1.bin

# OSv10 system title (00050010-1000400a): code files + ticket
./setup_osv10_jnus.sh       # via JNUSTool, needs java + JNUSTool.jar + config
# or, if you already have an encrypted dump via MLCRestorerDownloader:
./setup_osv10_cdecrypt.sh   # via a local cdecrypt binary
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

Everything else under `/sys/config`, `/sys/prefs`, other ticket entries,
etc. currently has to come from an existing dump — there's no generator for
it yet. Whether the system actually recreates some of that on first boot is
still untested.

### 2.3 Building a fresh SLC image from a directory

`build_slc.py` creates a brand-new `SLC.RAW` from a plain directory tree
(e.g. `slc_rebuild/` assembled above): it allocates FAT clusters, builds the
FST with the correct per-path mode/attr/uid/gid (see
`slc_permissions_list.txt` for the reverse-engineered rules), encrypts and
HMACs every cluster, and writes all 64 redundant superblocks.

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
- `--boot1` — raw boot1/boot2 clusters to copy in as-is (clusters `0x00-0x3f`);
  fetched above. `--boot-image` copies boot1/boot2 from another full SLC
  dump instead, if you have one.
- `--scfm` — optional; include an `scfm.img`. Not needed if you're setting up
  a fresh MLC (scfm.img relates to the SD/MLC storage mapping, not SLC system
  config, and gets regenerated for whatever MLC is actually attached). Leave
  it off and no `scfm.img` entry is created at all.
- `--bad-blocks` — optional; marks the given physical blocks bad in the NAND
  spare area and excludes them from the FAT.

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
    generic NAND)? There's no factory bad-block map to extract — leave
    `--bad-blocks` off entirely rather than reusing someone else's list.
