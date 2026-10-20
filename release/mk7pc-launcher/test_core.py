import hashlib
import os
import struct
import tempfile
import unittest

import mk7_core as core

NONE = 0xFFFFFFFF


def blz_compress(payload):
    """Tiny greedy encoder for the backwards-LZ format (matches + literals). Test use only."""
    n = len(payload)
    tokens, q = [], n                      # tokens in READ order (from the end of the payload downward)
    while q > 0:
        best_len, best_d = 0, 0
        for d in range(3, 4099):
            if q - 1 + d >= n:
                break
            k = 0
            while k < 18 and q - 1 - k >= 0 and q - 1 - k + d < n and payload[q - 1 - k] == payload[q - 1 - k + d]:
                k += 1
            if k > best_len:
                best_len, best_d = k, d
        if best_len >= 3:
            tokens.append(("m", struct.pack("<H", (best_d - 3) | ((best_len - 3) << 12))))
            q -= best_len
        else:
            tokens.append(("l", payload[q - 1:q]))
            q -= 1
    blocks = []
    for i in range(0, len(tokens), 8):
        grp = tokens[i:i + 8]
        ctrl = 0
        for bit, (kind, _) in enumerate(grp):
            if kind == "m":
                ctrl |= 0x80 >> bit
        blocks.append(b"".join(b for _, b in reversed(grp)) + bytes([ctrl]))
    body = b"".join(reversed(blocks))      # first-read block sits at the highest address
    total = len(body) + 8
    return body + struct.pack("<II", (8 << 24) | total, (n - total) & 0xFFFFFFFF)


def build_romfs(files):
    """files: {'a.txt': b'..', 'd/b.bin': b'..'} (one directory level)."""
    dirs = sorted({p.split("/")[0] for p in files if "/" in p})
    dir_entries, file_entries, data = [], [], b""
    # dir table layout: root first, then each subdir
    dir_off, o = {"": 0}, 0x18
    for d in dirs:
        dir_off[d] = o
        o += 0x18 + ((len(d) * 2 + 3) & ~3)
    root_files = [p for p in files if "/" not in p]
    file_off, fo, order = {}, 0, []
    for d in [""] + dirs:
        for p in (root_files if d == "" else [x for x in files if x.startswith(d + "/")]):
            file_off[p] = fo
            order.append((d, p))
            fo += 0x20 + ((len(p.split("/")[-1]) * 2 + 3) & ~3)
    first_file = {d: NONE for d in [""] + dirs}
    for d, p in reversed(order):
        first_file[d] = file_off[p]
    dtab = b""
    for i, d in enumerate([""] + dirs):
        nm = d.encode("utf-16-le")
        sib = dir_off[dirs[i]] if (d == "" and False) else NONE
        if d != "" and i < len(dirs):
            sib = dir_off[dirs[i]]       # next sibling dir
        child_dir = dir_off[dirs[0]] if (d == "" and dirs) else NONE
        dtab += struct.pack("<6I", 0, NONE, child_dir, first_file[d], NONE, len(nm)) + nm + b"\0" * (-len(nm) % 4)
    ftab = b""
    for idx, (d, p) in enumerate(order):
        content = files[p]
        nm = p.split("/")[-1].encode("utf-16-le")
        nxt = NONE
        for d2, p2 in order[idx + 1:]:
            if d2 == d:
                nxt = file_off[p2]
                break
        while len(data) % 16:
            data += b"\0"
        ftab += struct.pack("<IIQQII", dir_off[d], nxt, len(data), len(content), NONE, len(nm)) + nm + b"\0" * (-len(nm) % 4)
        data += content
    hdr_len = 0x28
    d_off = (hdr_len + 3) & ~3
    f_off = d_off + len(dtab)
    data_off = (f_off + len(ftab) + 0xF) & ~0xF
    lvl3 = struct.pack("<10I", hdr_len, 0, 0, d_off, len(dtab), 0, 0, f_off, len(ftab), data_off)
    lvl3 = lvl3.ljust(d_off, b"\0") + dtab + ftab
    lvl3 = lvl3.ljust(data_off, b"\0") + data
    ivfc = bytearray(0x60)
    ivfc[:4] = b"IVFC"
    struct.pack_into("<I", ivfc, 4, 0x10000)
    struct.pack_into("<I", ivfc, 8, 0x20)
    struct.pack_into("<Q", ivfc, 0x44, len(lvl3))
    struct.pack_into("<I", ivfc, 0x4C, 12)
    return bytes(ivfc).ljust(0x1000, b"\0") + lvl3


def build_image(code, compressed, romfs_files, product="CTR-P-AMKE", crypto=False, container="ncsd", cia_encrypted=False):
    code_blob = blz_compress(code) if compressed else code
    exefs = bytearray(0x200)
    exefs[0:16] = struct.pack("<8sII", b".code", 0, len(code_blob))
    exefs[16:32] = struct.pack("<8sII", b"icon", (len(code_blob) + 0x1FF) & ~0x1FF, 4)
    exe_data = code_blob.ljust((len(code_blob) + 0x1FF) & ~0x1FF, b"\0") + b"ICON"
    exefs = bytes(exefs) + exe_data
    exefs = exefs.ljust((len(exefs) + 0x1FF) & ~0x1FF, b"\0")
    romfs = build_romfs(romfs_files)
    romfs = romfs.ljust((len(romfs) + 0x1FF) & ~0x1FF, b"\0")

    ncch = bytearray(0x600)
    ncch[0x100:0x104] = b"NCCH"
    struct.pack_into("<Q", ncch, 0x118, 0x0004000000030600)
    ncch[0x150:0x150 + len(product)] = product.encode()
    struct.pack_into("<I", ncch, 0x180, 0x400)
    ncch[0x18F] = 0 if crypto else 0x04
    ex_off = 0x600 // 0x200
    exefs_mu = ex_off
    romfs_mu = exefs_mu + len(exefs) // 0x200
    struct.pack_into("<II", ncch, 0x1A0, exefs_mu, len(exefs) // 0x200)
    struct.pack_into("<II", ncch, 0x1B0, romfs_mu, len(romfs) // 0x200)
    ncch[0x20D] = 1 if compressed else 0          # exheader +0xD
    ncch_total = bytes(ncch) + exefs + romfs
    if container == "cxi":
        return ncch_total
    if container == "cia":
        a = lambda v: (v + 63) & ~63
        cert, tik, tmd, meta = 0x700, 0x350, 0x1F4, 0x3AC0
        hdr = bytearray(0x2020)
        struct.pack_into("<IHHIIIIQ", hdr, 0, 0x2020, 0, 0, cert, tik, tmd, meta, len(ncch_total))
        off_c = a(0x2020)
        off_t = a(off_c + cert)
        off_m = a(off_t + tik)
        off_content = a(off_m + tmd)
        blob = bytearray(off_content)
        blob[:0x2020] = hdr
        content = bytes(ncch_total)
        if cia_encrypted:
            content = bytes((b * 5 + 1) & 0xFF for b in content)      # no visible NCCH magic
        return bytes(blob) + content + b"\0" * meta

    ncsd = bytearray(0x4000)
    ncsd[0x100:0x104] = b"NCSD"
    struct.pack_into("<II", ncsd, 0x120, 0x4000 // 0x200, len(ncch_total) // 0x200 + 1)
    return bytes(ncsd) + ncch_total


class CoreTests(unittest.TestCase):
    FILES = {"readme.txt": b"hello world", "course/mario.bin": bytes(range(256)) * 20}
    CODE = bytes((i * 7) & 0xFF for i in range(1500))

    def _write(self, **kw):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "game.3ds")
        with open(p, "wb") as f:
            f.write(build_image(self.CODE, kw.pop("compressed", True), self.FILES, **kw))
        return d, p

    def test_cia_and_cxi_containers(self):
        for container in ("cia", "cxi"):
            d, p = self._write(container=container)
            info = core.validate(p)
            self.assertEqual(info["product_code"], "CTR-P-AMKE")
            out = os.path.join(d, "out")
            with open(p, "rb") as f:
                core.extract_exefs(f, info, os.path.join(out, "exefs"), log=lambda *_: None)
                core.extract_romfs(f, info, os.path.join(out, "romfs"), log=lambda *_: None)
            with open(os.path.join(out, "exefs", "code.bin"), "rb") as fh:
                self.assertEqual(fh.read(), self.CODE)
            with open(os.path.join(out, "romfs", "course", "mario.bin"), "rb") as fh:
                self.assertEqual(fh.read(), self.FILES["course/mario.bin"])

    def test_encrypted_cia_gives_clear_error(self):
        _, p = self._write(container="cia", cia_encrypted=True)
        with self.assertRaisesRegex(core.RomError, "CIA's content is encrypted"):
            core.validate(p)

    def test_blz_roundtrip(self):
        for n in (700, 1200, 2000):
            payload = bytes((i * 31) & 0xFF for i in range(n))
            comp = blz_compress(payload)
            self.assertLess(len(comp), n)                      # real stream, actually compressed
            self.assertEqual(core.blz_decompress(comp), payload)

    def test_blz_rejects_garbage(self):
        with self.assertRaises(core.RomError):
            core.blz_decompress(b"\x01\x02\x03")
        with self.assertRaises(core.RomError):
            core.blz_decompress(b"\x00" * 32)

    def test_validate_ok(self):
        _, p = self._write()
        info = core.validate(p)
        self.assertEqual(info["region"], "USA")
        self.assertTrue(info["code_compressed"])

    def test_rejects_encrypted_wrong_game_and_garbage(self):
        _, p = self._write(crypto=True)
        with self.assertRaisesRegex(core.RomError, "encrypted"):
            core.validate(p)
        _, p = self._write(product="CTR-P-ZZZZ")
        with self.assertRaisesRegex(core.RomError, "Mario Kart 7"):
            core.validate(p)
        d = tempfile.mkdtemp()
        g = os.path.join(d, "x.3ds")
        open(g, "wb").write(b"\x00" * 4096)
        with self.assertRaises(core.RomError):
            core.validate(g)

    def test_extract_everything(self):
        d, p = self._write()
        out = os.path.join(d, "out")
        with open(p, "rb") as f:
            info = core.parse_ncch(f, core.locate_ncch(f))
            core.extract_exefs(f, info, os.path.join(out, "exefs"), log=lambda *_: None)
            core.extract_romfs(f, info, os.path.join(out, "romfs"), log=lambda *_: None)
        self.assertEqual(open(os.path.join(out, "exefs", "code.bin"), "rb").read(), self.CODE)
        self.assertEqual(open(os.path.join(out, "romfs", "readme.txt"), "rb").read(), b"hello world")
        self.assertEqual(open(os.path.join(out, "romfs", "course", "mario.bin"), "rb").read(),
                         self.FILES["course/mario.bin"])

    def test_known_rom_hash_gate(self):
        d, p = self._write()
        os.environ["LOCALAPPDATA"] = d
        with self.assertRaisesRegex(core.RomError, "isn't in the supported list"):
            core.prepare_rom(p, {"deadbeef": "x"}, log=lambda *_: None)
        digest = hashlib.sha256(open(p, "rb").read()).hexdigest()
        data_dir, meta = core.prepare_rom(p, {digest: "MK7 USA v1.1"}, log=lambda *_: None)
        self.assertEqual(meta["label"], "MK7 USA v1.1")
        _, meta2 = core.prepare_rom(p, {digest: "MK7 USA v1.1"}, log=lambda *_: None)   # cache hit
        self.assertEqual(meta2["sha256"], digest)

    def test_safe_join_blocks_traversal(self):
        r = tempfile.mkdtemp()
        for bad in ("../x", "a/../../x", "/etc/passwd", "C:/x", "a//b", ""):
            with self.assertRaises(core.RomError):
                core.safe_join(r, bad)
        self.assertTrue(core.safe_join(r, "a/b.txt").startswith(r))

    def test_manifest_requires_https(self):
        with self.assertRaises(core.RomError):
            core.fetch_json("http://example.com/m.json")


if __name__ == "__main__":
    unittest.main()
