# SPDX-FileCopyrightText: 2026 RiDDiX / Maximilian Hammerschmid
# SPDX-License-Identifier: FSL-1.1-ALv2

"""
Reader for SDIO driver pack index files (.bin). Layout: "SDW", int32
version, then an LZMA86 blob (filter flag, 5 bytes LZMA props, uint64 size,
raw LZMA without end marker) that unpacks to six sections: inf files,
manufacturer lines, model lines, hardware ids, a text block and a hash
table (not needed here). All integers are 4 bytes little-endian; strings
are offsets into the text block.
"""

import struct

VERSIONS = (0x205, 0x204)
MAX_UNPACKED = 256 << 20
MAX_DICT = 64 << 20

INF = struct.Struct("<2I11I11I3i4i2i")
MFG = struct.Struct("<IIIi")
DESC = struct.Struct("<IiIIII")
HWID = struct.Struct("<IiI")

# [Version] keys by position in the inf record
PROVIDER = 2
CAT_PLAIN, CAT_NT, CAT_X86, CAT_AMD64 = 3, 4, 5, 7
CATS = {"amd64": (CAT_AMD64, CAT_NT, CAT_PLAIN), "x86": (CAT_X86, CAT_NT, CAT_PLAIN)}


class IndexError_(Exception):
    pass


def unpack(raw: bytes) -> bytes:
    # imported here: a Python built without liblzma must still load the app
    try:
        import lzma
    except ImportError:
        raise IndexError_("this server's Python has no lzma module") from None
    if len(raw) < 21 or raw[:3] != b"SDW":
        raise IndexError_("not an SDIO index")
    if struct.unpack_from("<i", raw, 3)[0] not in VERSIONS:
        raise IndexError_("unknown SDIO index version")
    flag, props = raw[7], raw[8:13]
    size = struct.unpack_from("<Q", raw, 13)[0]
    dict_size = struct.unpack_from("<I", props, 1)[0]
    if flag not in (0, 1) or size > MAX_UNPACKED or dict_size > MAX_DICT:
        raise IndexError_("SDIO index not understood")
    stream = raw[21:]
    lzma1 = lzma._decode_filter_properties(lzma.FILTER_LZMA1, props)
    try:
        plain = lzma.LZMADecompressor(lzma.FORMAT_RAW, filters=[lzma1]).decompress(
            stream, max_length=size
        )
        if flag:
            # the x86 decoder keeps its last bytes back until the stream ends,
            # which a stream without end marker never says; those bytes are
            # past the last converted call, so they are the same unfiltered
            out = lzma.LZMADecompressor(
                lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_X86}, lzma1]
            ).decompress(stream, max_length=size)
            plain = out + plain[len(out) :]
    except (lzma.LZMAError, MemoryError) as e:
        raise IndexError_(f"SDIO index does not unpack: {e}") from None
    if len(plain) != size:
        raise IndexError_("SDIO index is truncated")
    return plain


def _vector(buf: bytes, pos: int, record: int) -> tuple[memoryview, int, int]:
    if pos + 8 > len(buf):
        raise IndexError_("SDIO index is truncated")
    nbytes, count = struct.unpack_from("<ii", buf, pos)
    pos += 8
    if count == 0:
        count = nbytes // record if record else 0
    if nbytes < 0 or nbytes != count * record or pos + nbytes > len(buf):
        raise IndexError_("SDIO index section does not fit")
    return memoryview(buf)[pos : pos + nbytes], count, pos + nbytes


class Text:
    def __init__(self, block: bytes):
        self.block = block
        self.cache: dict[int, str] = {}

    def __call__(self, off: int) -> str:
        if not off or off >= len(self.block):
            return ""
        s = self.cache.get(off)
        if s is None:
            end = self.block.find(b"\0", off)
            raw = self.block[off : end if end >= 0 else len(self.block)]
            try:
                s = raw.decode("utf-8")
            except UnicodeDecodeError:
                s = raw.decode("cp1252", "replace")
            self.cache[off] = s
        return s

    def offsets(self, off: int, n: int) -> list[int]:
        if n < 0 or off + 4 * n > len(self.block):
            raise IndexError_("SDIO index section list does not fit")
        return list(struct.unpack_from(f"<{n}I", self.block, off))


def _date(day: int, month: int, year: int) -> str:
    if year < 1000 or not (1 <= month <= 12 and 1 <= day <= 31):
        return ""
    return f"{year:04d}-{month:02d}-{day:02d}"


def _version(v: tuple) -> str:
    return "" if v[0] < 0 else ".".join(str(max(p, 0)) for p in v)


def parse(buf: bytes, wanted=None):
    """Driver entries, one per hardware id of a model line. wanted: a set
    of upper-case ids to keep, None keeps all."""
    infs, n_inf, pos = _vector(buf, 0, INF.size)
    mfgs, n_mfg, pos = _vector(buf, pos, MFG.size)
    descs, n_desc, pos = _vector(buf, pos, DESC.size)
    hwids, n_hwid, pos = _vector(buf, pos, HWID.size)
    block, _, pos = _vector(buf, pos, 1)
    text = Text(bytes(block))

    inf_rows = list(INF.iter_unpack(infs))
    mfg_rows = list(MFG.iter_unpack(mfgs))
    desc_rows = list(DESC.iter_unpack(descs))
    lines: dict[int, list[str]] = {}
    for desc_i, inf_pos, hw_off in HWID.iter_unpack(hwids):
        hwid = text(hw_off)
        if wanted is not None and hwid not in wanted:
            continue
        if desc_i >= n_desc:
            raise IndexError_("SDIO index hardware id points nowhere")
        mfg_i, sect_pos, d_off, _, _, _ = desc_rows[desc_i]
        if mfg_i >= n_mfg:
            raise IndexError_("SDIO index model line points nowhere")
        inf_i, _, s_off, s_n = mfg_rows[mfg_i]
        if inf_i >= n_inf:
            raise IndexError_("SDIO index manufacturer points nowhere")
        if mfg_i not in lines:
            names = [text(o) for o in text.offsets(s_off, s_n)]
            # entry 0 is the base section, the rest are its decorations
            lines[mfg_i] = [""] + [n.lower() for n in names[1:]]
        decors = lines[mfg_i]
        if not 0 <= sect_pos < len(decors):
            raise IndexError_("SDIO index section position does not fit")
        row = inf_rows[inf_i]
        fields, cats = row[2:13], row[13:24]
        yield {
            "hwid": hwid,
            "pos": inf_pos,
            "folder": text(row[0]).replace("\\", "/"),
            "inf": text(row[1]),
            "version": _version(row[27:31]),
            "date": _date(*row[24:27]),
            "provider": text(fields[PROVIDER])[:128],
            "desc": text(d_off)[:255],
            "decor": decors[sect_pos],
            "alts": [d for i, d in enumerate(decors) if i != sect_pos],
            "cats": {
                arch: next((text(cats[i]) for i in keys if cats[i]), "")[:200]
                for arch, keys in CATS.items()
            },
        }


def read(path: str, wanted=None):
    with open(path, "rb") as fh:
        raw = fh.read(MAX_UNPACKED)
    return parse(unpack(raw), wanted)
