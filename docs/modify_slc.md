# Modifying an existing SLC

This extracts a complete SLC dump into the rebuild folder, lets you change the
files, and repacks it for **the same console**. To move an SLC to another
console, use `betwiin.py` instead (see the [README](../README.md)).

All commands are run from the repository root.

## 1. Prerequisites

- Python 3.10 or newer, and pycryptodome:
  ```bash
  pip3 install -r requirements.txt
  ```
- [minute_minute](https://github.com/StroopwafelCFW/minute_minute) on the
  console, to dump and restore the SLC

## 2. Dump

Put these into `input/`:
- **`input/SLC.RAW`** - the SLC dump (minute: *Dump SLC.RAW*);
- **`input/otp.bin`** - the console's OTP.

## 3. Extract

```bash
python3 extract_slc.py --all
```

This fills the rebuild folder:

```
rebuild/slc/             all files and folders of the SLC
rebuild/boot1.bin        boot1 (both slots checked)
rebuild/bad_blocks.txt   bad blocks of the chip
rebuild/permissions.txt  mode, attributes, uid and gid of every entry
```

If the console has isfshax, the output says so. Then read the isfshax note
in section 6 **before flashing**.

## 4. Modify

Change, add or delete files in `rebuild/slc/`.

- **Metadata:** existing entries keep their original mode, attributes, uid
  and gid from `rebuild/permissions.txt`. New files and folders get them from
  `build_slc.py`'s built-in rules. To change an entry's metadata, edit its
  line in `permissions.txt` (`mode attr uid gid path`, in hex).
- **`scfm.img`:** this is the SLC cache of the MLC and belongs to the MLC it
  was made with. It's stored unencrypted, so it's extracted as-is and written
  back as-is (without HMAC), just like the console stores it. Leave it alone
  as long as the MLC stays the same. If you replace or wipe the MLC, delete
  `rebuild/slc/scfm.img`; it's recreated for the new MLC.

## 5. Repack

```bash
python3 build_slc.py
```

This builds `rebuild/SLC.RAW` from `rebuild/slc/`, `rebuild/boot1.bin`,
`rebuild/bad_blocks.txt` and `rebuild/permissions.txt`, encrypted for
`input/otp.bin`.

To check the result, extract it again and compare:

```bash
python3 extract_slc.py --image rebuild/SLC.RAW -o rebuild/verify --all
diff -r rebuild/slc rebuild/verify/slc
```

## 6. Flash it

1. Copy `rebuild/SLC.RAW` to the root of the SD card as `SLC.RAW`.
2. Restore it with the latest minute (*Restore SLC.RAW*), see the isfshax
   note below.

Notes:

- **Bad blocks:** `bad_blocks.txt` belongs to the chip the dump was taken
  from. If you write the image to a different SLC chip, extract the bad
  blocks from a raw dump of that chip instead
  (`python3 extract_slc.py --image <dump> bad_blocks`).
- **isfshax:** if the console relies on isfshax to boot (e.g. to load
  minute), **restore with the latest
  [minute](https://github.com/StroopwafelCFW/minute_minute/releases)**.
  `build_slc.py` writes fresh superblocks into all 64 slots, including
  isfshax's; only a recent minute keeps the installed isfshax superblocks
  when restoring. An older one overwrites them, and without isfshax (and so
  without minute) the console bricks.
