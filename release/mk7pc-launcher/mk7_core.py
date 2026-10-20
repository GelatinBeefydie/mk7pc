"""
mk7_core.py - launcher core logic (no GUI imports, so it can be tested headless).

What this does:
  * Validates and parses a DECRYPTED 3DS dump (.3ds/.cci = NCSD, .cxi/.app = NCCH, .cia)
  * Extracts ExeFS (decompressing .code -> code.bin) and RomFS into a local cache
  * Downloads the runtime files listed in your manifest (hash-verified, HTTPS only)

What this never does: download, host, or link to Nintendo code/assets/keys.
Game code and assets come ONLY from the ROM the player supplies.
"""
import hashlib
import json
import os
import struct
import subprocess
import sys
import urllib.request

MEDIA_UNIT = 0x200
EXPECTED_PRODUCT_PREFIX = "CTR-P-AMK"          # Mario Kart 7 (AMKE/AMKP/AMKJ...)
REGIONS = {"E": "USA", "P": "Europe", "J": "Japan", "K": "Korea", "C": "China", "T": "Taiwan"}


class RomError(Exception):
    pass


# --------------------------------------------------------------------------- paths
def app_dir():
    base = os.environ.get("LOCALAPPDATA") or os.path.join(os.path.expanduser("~"), ".local", "share")
    path = os.path.join(base, "MK7PC")
    os.makedirs(path, exist_ok=True)
    return path


def load_config():
    p = os.path.join(app_dir(), "config.json")
    try:
        with open(p, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_config(cfg):
    with open(os.path.join(app_dir(), "config.json"), "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def safe_join(root, rel):
    """Join rel under root; reject absolute paths, drive letters and '..' (zip-slip style attacks)."""
    rel = rel.replace("\\", "/")
    if not rel or rel.startswith("/") or ":" in rel or "\x00" in rel:
        raise RomError("Unsafe path: %r" % rel)
    parts = rel.split("/")
    if any(p in ("", ".", "..") for p in parts):
        raise RomError("Unsafe path: %r" % rel)
    full = os.path.normpath(os.path.join(root, *parts))
    if os.path.commonpath([os.path.abspath(root), os.path.abspath(full)]) != os.path.abspath(root):
        raise RomError("Path escapes target directory: %r" % rel)
    return full


# --------------------------------------------------------------------------- hashing
def sha256_file(path, progress=None, chunk=1 << 20):
    h = hashlib.sha256()
    total = os.path.getsize(path)
    done = 0
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
            done += len(b)
            if progress:
                progress(done, total)
    return h.hexdigest()


# --------------------------------------------------------------------------- 3DS formats
def _read(f, off, n):
    f.seek(off)
    b = f.read(n)
    if len(b) != n:
        raise RomError("File is truncated or not a valid 3DS dump.")
    return b


def locate_ncch(f):
    head = _read(f, 0, 0x200)
    if head[0x100:0x104] == b"NCSD":
        off, size = struct.unpack_from("<II", head, 0x120)       # partition 0 = game executable
        if off == 0 or size == 0:
            raise RomError("NCSD image has no game partition.")
        return off * MEDIA_UNIT
    if head[0x100:0x104] == b"NCCH":
        return 0
    if struct.unpack_from("<I", head, 0)[0] == 0x2020:
        return _locate_cia_content(f, head)
    raise RomError("Not a recognised 3DS image (expected .3ds/.cci, .cxi or .cia).")


def _locate_cia_content(f, head):
    """CIA = header | certs | ticket | TMD | content | meta, each section aligned to 64 bytes.
    The main game NCCH is the first content chunk. If the chunk is still encrypted at the CIA layer
    (normal for CIAs straight from the eShop/installer) the NCCH magic won't be visible."""
    _hdr, _type, _ver, cert, tik, tmd, _meta, _content = struct.unpack_from("<IHHIIIIQ", head, 0)
    a = lambda v: (v + 63) & ~63
    off = a(a(a(a(0x2020) + cert) + tik) + tmd)
    try:
        magic = _read(f, off + 0x100, 4)
    except RomError:
        raise RomError("CIA file is truncated or corrupt.")
    if magic != b"NCCH":
        raise RomError("This CIA's content is encrypted. Decrypt it first (for example with GodMode9 "
                       "on your own console), or use a decrypted .3ds/.cci instead.")
    return off


def parse_ncch(f, base):
    h = _read(f, base, 0x200)
    if h[0x100:0x104] != b"NCCH":
        raise RomError("Game partition header is invalid.")
    flags = h[0x188:0x190]
    info = {
        "base": base,
        "program_id": "%016X" % struct.unpack_from("<Q", h, 0x118)[0],
        "product_code": h[0x150:0x160].split(b"\x00")[0].decode("ascii", "replace"),
        "exheader_size": struct.unpack_from("<I", h, 0x180)[0],
        "no_crypto": bool(flags[7] & 0x04),
        "exefs_off": struct.unpack_from("<I", h, 0x1A0)[0] * MEDIA_UNIT,
        "exefs_size": struct.unpack_from("<I", h, 0x1A4)[0] * MEDIA_UNIT,
        "romfs_off": struct.unpack_from("<I", h, 0x1B0)[0] * MEDIA_UNIT,
        "romfs_size": struct.unpack_from("<I", h, 0x1B4)[0] * MEDIA_UNIT,
    }
    pc = info["product_code"]
    info["region"] = REGIONS.get(pc[-1:], "Unknown")
    info["code_compressed"] = False
    if info["exheader_size"] >= 0x200:
        ex = _read(f, base + 0x200, 0x20)
        info["code_compressed"] = bool(ex[0x0D] & 1)
    return info


def validate(path):
    """Return NCCH info dict or raise RomError with a player-friendly message."""
    with open(path, "rb") as f:
        info = parse_ncch(f, locate_ncch(f))
    if not info["product_code"].startswith(EXPECTED_PRODUCT_PREFIX):
        raise RomError("This doesn't look like Mario Kart 7 (product code: %s)." % info["product_code"])
    if not info["no_crypto"]:
        raise RomError("This dump is still encrypted. Decrypt it first (for example with GodMode9 on your "
                       "own console), then select the decrypted file.")
    if not info["exefs_size"] or not info["romfs_size"]:
        raise RomError("Dump is missing ExeFS or RomFS.")
    return info


# --------------------------------------------------------------------------- .code decompression
def blz_decompress(comp):
    """3DS backwards-LZ ('.code' compression)."""
    n = len(comp)
    if n < 8:
        raise RomError("Compressed .code too small.")
    top_bottom, extra = struct.unpack_from("<II", comp, n - 8)
    hdr_len, bottom = top_bottom >> 24, top_bottom & 0xFFFFFF
    if hdr_len < 8 or hdr_len > bottom or bottom > n:
        raise RomError("Corrupt .code footer.")
    out_size = (n + extra) & 0xFFFFFFFF
    if out_size < n or out_size > 0x10000000:
        raise RomError("Implausible decompressed .code size.")
    out = bytearray(out_size)
    out[:n] = comp
    index = n - (top_bottom >> 24)
    stop = n - (top_bottom & 0xFFFFFF)
    pos = out_size
    while index > stop:
        index -= 1
        control = comp[index]
        for _ in range(8):
            if index <= stop or pos <= 0:
                break
            if control & 0x80:
                if index < 2:
                    raise RomError("Corrupt .code stream.")
                index -= 2
                seg = comp[index] | (comp[index + 1] << 8)
                seg_size = ((seg >> 12) & 0xF) + 3
                seg_off = (seg & 0x0FFF) + 2
                if pos < seg_size:
                    raise RomError("Corrupt .code stream.")
                for _j in range(seg_size):
                    src = pos + seg_off
                    if src >= out_size:
                        raise RomError("Corrupt .code stream.")
                    pos -= 1
                    out[pos] = out[src]
            else:
                if pos < 1:
                    raise RomError("Corrupt .code stream.")
                index -= 1
                pos -= 1
                out[pos] = comp[index]
            control = (control << 1) & 0xFF
    return bytes(out)


# --------------------------------------------------------------------------- ExeFS
def extract_exefs(f, info, out_dir, log=print):
    os.makedirs(out_dir, exist_ok=True)
    base = info["base"] + info["exefs_off"]
    hdr = _read(f, base, 0x200)
    for i in range(10):
        name_raw, off, size = struct.unpack_from("<8sII", hdr, i * 16)
        name = name_raw.split(b"\x00")[0].decode("ascii", "replace")
        if not name or size == 0:
            continue
        if off + size > info["exefs_size"]:
            raise RomError("ExeFS entry %r is out of bounds." % name)
        data = _read(f, base + 0x200 + off, size)
        if name == ".code":
            if info["code_compressed"]:
                log("Decompressing .code ...")
                data = blz_decompress(data)
            name = "code.bin"
        else:
            name = name.lstrip(".") + ".bin"
        with open(safe_join(out_dir, name), "wb") as o:
            o.write(data)
        log("ExeFS: %s (%d bytes)" % (name, len(data)))


# --------------------------------------------------------------------------- RomFS
def _align(v, a):
    return (v + a - 1) // a * a


def extract_romfs(f, info, out_dir, progress=None, log=print):
    base = info["base"] + info["romfs_off"]
    ivfc = _read(f, base, 0x60)
    if ivfc[:4] != b"IVFC":
        raise RomError("RomFS header invalid.")
    master_hash = struct.unpack_from("<I", ivfc, 0x08)[0]
    l3_block = struct.unpack_from("<I", ivfc, 0x4C)[0]
    if not (9 <= l3_block <= 24):
        raise RomError("RomFS header invalid.")
    l3 = base + _align(0x60 + master_hash, 1 << l3_block)

    h = struct.unpack("<10I", _read(f, l3, 0x28))
    dir_off, dir_size, file_off, file_size, data_off = h[3], h[4], h[7], h[8], h[9]
    if dir_size > (64 << 20) or file_size > (64 << 20):
        raise RomError("RomFS metadata implausibly large.")
    dir_tab = _read(f, l3 + dir_off, dir_size)
    file_tab = _read(f, l3 + file_off, file_size)
    NONE = 0xFFFFFFFF
    total = info["romfs_size"]
    state = {"done": 0, "files": 0}
    seen_dirs, seen_files = set(), set()

    def name_at(tab, off, len_pos, name_pos):
        n = struct.unpack_from("<I", tab, off + len_pos)[0]
        raw = tab[off + name_pos: off + name_pos + n]
        if len(raw) != n:
            raise RomError("RomFS name out of bounds.")
        return raw.decode("utf-16-le")

    def walk(doff, target):
        if doff in seen_dirs or doff + 0x18 > len(dir_tab):
            raise RomError("RomFS directory table is corrupt.")
        seen_dirs.add(doff)
        os.makedirs(target, exist_ok=True)
        _parent, _sib, child_dir, child_file = struct.unpack_from("<4I", dir_tab, doff)
        foff = child_file
        while foff != NONE:
            if foff in seen_files or foff + 0x20 > len(file_tab):
                raise RomError("RomFS file table is corrupt.")
            seen_files.add(foff)
            _p, sib, fdata, flen = struct.unpack_from("<IIQQ", file_tab, foff)
            name = name_at(file_tab, foff, 0x1C, 0x20)
            dest = safe_join(target, name)
            f.seek(l3 + data_off + fdata)
            left = flen
            with open(dest, "wb") as o:
                while left:
                    b = f.read(min(left, 1 << 20))
                    if not b:
                        raise RomError("RomFS file %r is truncated." % name)
                    o.write(b)
                    left -= len(b)
                    state["done"] += len(b)
                    if progress:
                        progress(min(state["done"], total), total)
            state["files"] += 1
            foff = sib
        doff2 = child_dir
        while doff2 != NONE:
            if doff2 + 0x18 > len(dir_tab):
                raise RomError("RomFS directory table is corrupt.")
            sib = struct.unpack_from("<I", dir_tab, doff2 + 4)[0]
            name = name_at(dir_tab, doff2, 0x14, 0x18)
            walk(doff2, safe_join(target, name))
            doff2 = sib

    walk(0, out_dir)
    log("RomFS: %d files extracted" % state["files"])


# --------------------------------------------------------------------------- prepare (extract with cache)
def prepare_rom(rom_path, known_roms=None, progress=None, log=print):
    """Validate, hash, extract into the cache. Returns (data_dir, meta). Skips work if already cached."""
    info = validate(rom_path)
    log("Detected: %s, region %s, program ID %s" % (info["product_code"], info["region"], info["program_id"]))
    log("Hashing ROM ...")
    digest = sha256_file(rom_path, progress)
    label = (known_roms or {}).get(digest)
    if known_roms and not label:
        raise RomError("This dump's hash isn't in the supported list (version/region mismatch or a bad dump).\n"
                       "SHA-256: " + digest)
    data_dir = os.path.join(app_dir(), "data", digest[:16])
    meta_path = os.path.join(data_dir, "meta.json")
    if os.path.exists(meta_path) and os.path.exists(os.path.join(data_dir, "exefs", "code.bin")):
        log("Already extracted - using cache.")
        with open(meta_path, "r", encoding="utf-8") as m:
            return data_dir, json.load(m)
    with open(rom_path, "rb") as f:
        extract_exefs(f, info, os.path.join(data_dir, "exefs"), log)
        extract_romfs(f, info, os.path.join(data_dir, "romfs"), progress, log)
    meta = {"sha256": digest, "label": label or "unverified", "region": info["region"],
            "product_code": info["product_code"], "program_id": info["program_id"]}
    with open(meta_path, "w", encoding="utf-8") as m:
        json.dump(meta, m, indent=2)
    return data_dir, meta


# --------------------------------------------------------------------------- manifest / runtime download
def fetch_json(url, timeout=20):
    if not url.lower().startswith("https://"):
        raise RomError("Manifest URL must be HTTPS.")
    req = urllib.request.Request(url, headers={"User-Agent": "MK7PC-Launcher"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def sync_runtime(manifest, progress=None, log=print):
    """Download/refresh runtime files named in the manifest. Only your own files belong here."""
    root = os.path.join(app_dir(), "runtime")
    files = manifest.get("files", [])
    for i, entry in enumerate(files, 1):
        dest = safe_join(root, entry["path"])
        want = entry["sha256"].lower()
        if os.path.exists(dest) and sha256_file(dest) == want:
            log("Up to date: %s" % entry["path"])
            continue
        url = entry["url"]
        if not url.lower().startswith("https://"):
            raise RomError("Refusing non-HTTPS download: %s" % url)
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        part = dest + ".part"
        h = hashlib.sha256()
        log("Downloading %s (%d/%d)" % (entry["path"], i, len(files)))
        req = urllib.request.Request(url, headers={"User-Agent": "MK7PC-Launcher"})
        with urllib.request.urlopen(req, timeout=30) as r, open(part, "wb") as o:
            total = int(r.headers.get("Content-Length") or 0)
            done = 0
            while True:
                b = r.read(1 << 16)
                if not b:
                    break
                o.write(b)
                h.update(b)
                done += len(b)
                if progress and total:
                    progress(done, total)
        if h.hexdigest() != want:
            os.remove(part)
            raise RomError("Hash mismatch for %s - download discarded." % entry["path"])
        os.replace(part, dest)
    return root


def launch(runtime_exe_name, data_dir):
    exe = os.path.join(app_dir(), "runtime", runtime_exe_name)
    if not os.path.exists(exe):
        raise RomError("Runtime not installed yet. Click 'Update runtime' first.")
    return subprocess.Popen([exe, "--data", data_dir], cwd=os.path.dirname(exe))
