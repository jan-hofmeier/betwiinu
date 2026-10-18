# Creating a new SLC from scratch

This builds a new SLC image for a console whose SLC content is lost, or whose
SLC chip was replaced. The image contains only what the console needs to
boot:
- boot1;
- OSv10 (00050010-1000400a), its ticket, the certificate store
  (`cert.sys`) and the ticket index (`title.list`);
- the config files `system.xml` and `sys_prod.xml`, generated from the
  console's serial.

It has no other system titles and no tickets for them. All system titles,
including the ones on the MLC, are reinstalled afterwards (last step).

All commands are run from the repository root. Details on each tool are in
the [README](../README.md).

## 1. Prerequisites

- Python 3.10 or newer, and pycryptodome:
  ```bash
  pip3 install -r requirements.txt
  ```
- An internet connection, for Nintendo's update server (NUS)
- [minute_minute](https://github.com/StroopwafelCFW/minute_minute) on the
  console, to dump and restore the SLC

## 2. Get the OTP, an SLC dump and the serial

Put these into `input/`:

- **`input/otp.bin`** - the OTP of the target console, dumped with minute. Its
  keys encrypt the new SLC, and its common key decrypts the downloads.
- **`input/SLC.RAW`** - a raw dump of the SLC chip that will be written
  (minute: *Dump SLC.RAW*). It's needed for the chip's bad blocks, and boot1
  is taken from it if it still has a valid one.

  If the SLC chip was replaced, dump the new chip *before* writing anything
  to it. Its factory bad-block markers are only in that raw dump.

Also note the **serial** from the sticker on the bottom of the console, e.g.
`FEM123456784`. It goes into `sys_prod.xml`, and its prefix selects the
region (`FEM` = EUR, `FW` = USA; only these two regions are supported).

## 3. Build it

Either run the wrapper with the serial, which does steps 3.1 to 3.5 for you:

```bash
./create_slc.sh FEM123456784
```

If the serial prefix is unknown, add the region: `./create_slc.sh <serial> EUR`.

or do them one by one:

### 3.1 Bad blocks

```bash
python3 extract_slc.py bad_blocks
```

This writes `rebuild/bad_blocks.txt`. Check the output: on a console with
isfshax its superblock slots are left out on purpose, since they aren't
really bad.

### 3.2 boot1

```bash
python3 extract_slc.py boot1
```

This takes boot1 from the dump (`rebuild/boot1.bin`). If both slots are
invalid (e.g. the chip is blank or the content is lost), download it from NUS
instead:

```bash
python3 download_boot1.py
```

### 3.3 OSv10

```bash
python3 download_osv10.py
```

This downloads OSv10 from NUS (about 23 MB) and puts the files, the ticket,
`cert.sys` and `title.list` into `rebuild/slc/`. If you already have the
title from MLCRestorerDownloader, add `--source <its 000500101000400a dir>`
to use that instead.

### 3.4 Config

```bash
python3 sys_config.py --serial FEM123456784
```

This writes `rebuild/slc/sys/config/system.xml` and `sys_prod.xml`. Pass
`--region EUR` or `--region USA` if the serial prefix is unknown.

### 3.5 Build the image

```bash
python3 build_slc.py
```

This builds `rebuild/SLC.RAW` from `rebuild/slc/`, `rebuild/boot1.bin` and
`rebuild/bad_blocks.txt`, encrypted for `input/otp.bin`.

## 4. Flash it

1. Copy `rebuild/SLC.RAW` to the root of the SD card as `SLC.RAW`.
2. Restore it with minute (*Restore SLC.RAW*). minute also syncs the boot1
   version in the SEEPROM.

## 5. Boot it once

Boot the console once with the new SLC, *without* `wafel_setup_mlc.ipx` in
`sd:/wiiu/ios_plugins`. It crashes; that's expected, since the system titles
are still missing. Power it off.

Don't skip this: if wafel_setup_mlc runs on the very first boot of the new
SLC, the setup gets stuck.

## 6. Reinstall all system titles

The new SLC only has OSv10, so **all** other system titles have to be
installed again, the ones on the MLC included, even if the MLC is intact:
- **Tickets:** the tickets of all titles, MLC titles too, are stored on the
  SLC (`/sys/rights/ticket`). The new SLC only has OSv10's, so the system
  can't use the titles on the MLC. Installing them writes their tickets back.
- **scfm.img:** the SLC cache of the MLC (`/scfm.img`) isn't in the new SLC,
  so whatever is on the MLC doesn't match it anymore.

Use wafel_setup_mlc for this; its
[README](https://github.com/StroopwafelCFW/wafel_setup_mlc#how-to-use) has the
details. In short:

1. Download all system titles with
   [MLCRestorerDownloader](https://github.com/Xpl0itU/MLCRestorerDownloader)
   and copy the WUPs to `sd:/wafel_install`.
2. Put `wafel_setup_mlc.ipx` and stroopwafel's `wafel_core.ipx` into
   `sd:/wiiu/ios_plugins`.
3. Erase the MLC
4. Boot, and wait until the log says it's done.
5. Power off and remove `wafel_setup_mlc.ipx`. The next boot starts the
   initial setup.
