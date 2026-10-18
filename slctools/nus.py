"""Downloading and decrypting titles from Nintendo's update server (NUS).

A title on NUS is a TMD (list of contents), a ticket (cetk, holds the title
key encrypted with the common key) and the contents, each AES-128-CBC
encrypted with the title key. Content 0 is the FST, which maps the title's
files to offsets in the other contents.
"""

import hashlib
import os
import struct
import urllib.request

from Crypto.Cipher import AES

NUS_URL = "http://ccs.cdn.wup.shop.nintendo.net/ccs/download"
USER_AGENT = "WiiU/1.0"

CONTENT_HASHED = 0x0002

def read_common_key(otp_path):
    """The Wii U common key, from the OTP at 0xE0."""
    with open(otp_path, "rb") as f:
        otp = f.read()
    if len(otp) != 0x400:
        raise ValueError(f"{otp_path} is not a 1024-byte otp.bin")
    return otp[0xE0:0xF0]

class Title:
    """A title's files, from NUS or from a local directory.

    source_dir: a directory with tmd/cetk (or title.tmd/title.tik, as
    MLCRestorerDownloader names them) and the contents (<id> or <id>.app).
    Without it everything is downloaded; with cache_dir the downloads are
    kept there and reused.
    """
    def __init__(self, title_id, source_dir=None, cache_dir=None):
        self.title_id = title_id
        self.source_dir = source_dir
        self.cache_dir = cache_dir

    def _local(self, directory, names):
        for name in names:
            path = os.path.join(directory, name)
            if os.path.isfile(path):
                with open(path, "rb") as f:
                    return f.read()
        return None

    def get(self, name, alt_names=()):
        names = (name, *alt_names)
        if self.source_dir:
            data = self._local(self.source_dir, names)
            if data is None:
                raise FileNotFoundError(f"{' / '.join(names)} not found in {self.source_dir}")
            return data
        if self.cache_dir:
            data = self._local(self.cache_dir, names)
            if data is not None:
                return data
        url = f"{NUS_URL}/{self.title_id}/{name}"
        print(f"Downloading {url}")
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req) as resp:
            data = resp.read()
        if self.cache_dir:
            os.makedirs(self.cache_dir, exist_ok=True)
            with open(os.path.join(self.cache_dir, name), "wb") as f:
                f.write(data)
        return data

    def tmd(self):
        return self.get("tmd", ("title.tmd",))

    def cetk(self):
        return self.get("cetk", ("title.tik",))

    def content(self, content_id):
        name = f"{content_id:08x}"
        return self.get(name, (name.upper(), name + ".app", name.upper() + ".app"))

def decrypt_title_key(cetk, common_key):
    title_id = cetk[0x1DC:0x1E4]
    return AES.new(common_key, AES.MODE_CBC, title_id + bytes(8)).decrypt(cetk[0x1BF:0x1CF])

def parse_tmd(tmd):
    """Returns the contents as a list of (id, index, type, size, sha1)."""
    num_contents, = struct.unpack_from(">H", tmd, 0x1DE)
    contents = []
    for i in range(num_contents):
        offset = 0xB04 + i * 0x30
        content_id, index, content_type, size = struct.unpack_from(">IHHQ", tmd, offset)
        contents.append((content_id, index, content_type, size, tmd[offset + 0x10:offset + 0x24]))
    return contents

def decrypt_content(data, title_key, index, content_type, size, sha1):
    if content_type & CONTENT_HASHED:
        raise NotImplementedError(f"content {index} is hashed, which isn't supported")
    padded = (size + 0xF) & ~0xF
    if len(data) < padded:
        raise ValueError(f"content {index} is truncated ({len(data)} of {padded} bytes)")
    iv = struct.pack(">H", index) + bytes(14)
    plain = AES.new(title_key, AES.MODE_CBC, iv).decrypt(data[:padded])[:size]
    if hashlib.sha1(plain).digest() != sha1:
        hint = " (wrong common key, is otp.bin from a retail console?)" if index == 0 else ""
        raise ValueError(f"content {index} doesn't match the hash in the TMD{hint}")
    return plain

def parse_fst(fst):
    """Returns the files as a list of (path, content index, offset, size)."""
    if fst[0:4] != b"FST\0":
        raise ValueError("not an FST")
    num_content_headers, = struct.unpack_from(">I", fst, 0x8)
    entries_offset = 0x20 + num_content_headers * 0x20
    num_entries, = struct.unpack_from(">I", fst, entries_offset + 0x8)
    names_offset = entries_offset + num_entries * 0x10

    def name(name_offset):
        end = fst.index(b"\0", names_offset + name_offset)
        return fst[names_offset + name_offset:end].decode()

    files = []
    dirs = [("", num_entries)]  # (path, index of the first entry after it)
    for i in range(1, num_entries):
        type_name, offset, size, flags, content_index = struct.unpack_from(">IIIHH", fst, entries_offset + i * 0x10)
        while i >= dirs[-1][1]:
            dirs.pop()
        path = dirs[-1][0] + name(type_name & 0xFFFFFF)
        if type_name >> 24 & 1:
            dirs.append((path + "/", size))
        else:
            if not flags & 4:
                offset <<= 5
            files.append((path, content_index, offset, size))
    return files

def download_title(title, common_key, output_dir):
    """Decrypts all files of the title into output_dir, plus title.tmd and
    title.fst into its code directory, as the console stores them. Returns
    (tmd, cetk)."""
    tmd = title.tmd()
    cetk = title.cetk()
    if tmd[0x18C:0x194] != cetk[0x1DC:0x1E4]:
        raise ValueError("TMD and ticket belong to different titles")
    title_key = decrypt_title_key(cetk, common_key)

    contents = {}
    for content_id, index, content_type, size, sha1 in parse_tmd(tmd):
        data = title.content(content_id)
        contents[index] = decrypt_content(data, title_key, index, content_type, size, sha1)

    files = parse_fst(contents[0])
    for path, content_index, offset, size in files:
        data = contents[content_index][offset:offset + size]
        if len(data) != size:
            raise ValueError(f"{path} lies outside of content {content_index}")
        out_path = os.path.join(output_dir, path)
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "wb") as f:
            f.write(data)
    print(f"Decrypted {len(files)} files from {len(contents)} contents")

    code_dir = os.path.join(output_dir, "code")
    os.makedirs(code_dir, exist_ok=True)
    for name, data in (("title.tmd", tmd), ("title.fst", contents[0])):
        with open(os.path.join(code_dir, name), "wb") as f:
            f.write(data)
    return tmd, cetk
