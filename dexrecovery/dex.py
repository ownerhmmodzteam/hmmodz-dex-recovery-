import hashlib
import struct
import zlib
from pathlib import Path

class DexError(ValueError):
    pass

def u16(b, o): return struct.unpack_from("<H", b, o)[0]
def u32(b, o): return struct.unpack_from("<I", b, o)[0]

def validate_dex(data: bytes):
    if len(data) < 112 or data[:4] != b"dex\n" or data[7:8] != b"\0":
        raise DexError("Header DEX tidak valid atau file terlalu kecil.")
    version = data[4:7].decode("ascii", "replace")
    file_size, header_size, endian = u32(data, 32), u32(data, 36), u32(data, 40)
    if file_size != len(data):
        raise DexError(f"file_size header ({file_size}) berbeda dari ukuran aktual ({len(data)}).")
    if header_size != 112 or endian != 0x12345678:
        raise DexError("header_size atau endian_tag tidak didukung.")
    for label, count_off, off_off, item_size in (
        ("string_ids", 56, 60, 4), ("type_ids", 64, 68, 4),
        ("proto_ids", 72, 76, 12), ("field_ids", 80, 84, 8),
        ("method_ids", 88, 92, 8), ("class_defs", 96, 100, 32),
    ):
        count, off = u32(data, count_off), u32(data, off_off)
        if count and (off < 112 or off + count * item_size > len(data)):
            raise DexError(f"Bagian {label} berada di luar batas file.")
    return {
        "version": version, "file_size": file_size,
        "strings": u32(data, 56), "types": u32(data, 64),
        "protos": u32(data, 72), "fields": u32(data, 80),
        "methods": u32(data, 88), "classes": u32(data, 96),
    }

def _uleb(data, pos):
    result = shift = 0
    for _ in range(5):
        if pos >= len(data): raise DexError("ULEB128 terpotong.")
        byte = data[pos]; pos += 1
        result |= (byte & 0x7f) << shift
        if not byte & 0x80: return result, pos
        shift += 7
    raise DexError("ULEB128 terlalu panjang.")

def method_code_offsets(data: bytes):
    meta = validate_dex(data)
    method_count = meta["methods"]
    class_count = meta["classes"]
    method_ids_off = u32(data, 92)
    class_defs_off = u32(data, 100)
    owners = {}
    for class_i in range(class_count):
        base = class_defs_off + class_i * 32
        class_data_off = u32(data, base + 24)
        if not class_data_off: continue
        p = class_data_off
        static_fields, p = _uleb(data, p)
        instance_fields, p = _uleb(data, p)
        direct_methods, p = _uleb(data, p)
        virtual_methods, p = _uleb(data, p)
        for _ in range(static_fields + instance_fields):
            _, p = _uleb(data, p); _, p = _uleb(data, p)
        for group_count in (direct_methods, virtual_methods):
            idx = 0
            for _ in range(group_count):
                diff, p = _uleb(data, p)
                _, p = _uleb(data, p)
                code_off, p = _uleb(data, p)
                idx += diff
                if idx >= method_count: raise DexError("method_idx di class_data di luar method_ids.")
                if code_off:
                    owners[idx] = code_off
    result = {}
    for idx, code_off in owners.items():
        if code_off + 16 > len(data): raise DexError(f"code_item method {idx} di luar file.")
        insns_size = u32(data, code_off + 12)
        insns_off = code_off + 16
        insns_end = insns_off + insns_size * 2
        if insns_end > len(data): raise DexError(f"Instruksi method {idx} terpotong.")
        result[idx] = (insns_off, insns_size * 2)
    return result

def repair_headers(data: bytearray):
    struct.pack_into("<I", data, 32, len(data))
    data[12:32] = hashlib.sha1(data[32:]).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xffffffff)
    return data

def analyze(path: Path):
    data = path.read_bytes()
    meta = validate_dex(data)
    methods = method_code_offsets(data)
    signatures = {
        "DPT/MultiDexCode": b"MultiDexCode",
        "DexClassLoader": b"DexClassLoader",
        "InMemoryDexClassLoader": b"InMemoryDexClassLoader",
        "壳/packer indicators": b"libjiagu",
    }
    hits = [name for name, needle in signatures.items() if needle in data]
    return {"meta": meta, "code_methods": len(methods), "indicators": hits,
            "sha256": hashlib.sha256(data).hexdigest()}
