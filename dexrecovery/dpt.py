import struct
from dataclasses import dataclass
from pathlib import Path
from .dex import DexError

@dataclass
class Instruction:
    method_index: int
    data: bytes

@dataclass
class DexCode:
    instructions: list

@dataclass
class MultiDexCode:
    version: int
    dex_codes: list

def parse_multidexcode(path: Path, max_file=512 * 1024 * 1024):
    raw = path.read_bytes()
    if len(raw) > max_file: raise DexError("MultiDexCode melewati batas ukuran aman 512 MiB.")
    if len(raw) < 4: raise DexError("Header MultiDexCode terpotong.")
    version, dex_count = struct.unpack_from("<HH", raw, 0)
    if dex_count == 0 or dex_count > 64: raise DexError("dex_count tidak masuk akal.")
    table_end = 4 + dex_count * 4
    if table_end > len(raw): raise DexError("Tabel offset MultiDexCode terpotong.")
    offsets = struct.unpack_from("<" + "I" * dex_count, raw, 4)
    codes = []
    for offset in offsets:
        if offset < table_end or offset + 2 > len(raw): raise DexError("Offset blok DEX tidak valid.")
        method_count = struct.unpack_from("<H", raw, offset)[0]
        if method_count > 65535: raise DexError("method_count tidak valid.")
        p = offset + 2
        instructions = []
        for _ in range(method_count):
            if p + 8 > len(raw): raise DexError("Record method terpotong.")
            method_idx, size = struct.unpack_from("<II", raw, p); p += 8
            if size > len(raw) - p: raise DexError("Ukuran bytecode melewati akhir file.")
            instructions.append(Instruction(method_idx, raw[p:p+size]))
            p += size
        codes.append(DexCode(instructions))
    return MultiDexCode(version, codes)

def restore(dex_path: Path, code_path: Path, out_path: Path, dex_index=0):
    from .dex import validate_dex, method_code_offsets, repair_headers
    import hashlib, json
    source = dex_path.read_bytes()
    validate_dex(source)
    locations = method_code_offsets(source)
    multi = parse_multidexcode(code_path)
    if dex_index < 0 or dex_index >= len(multi.dex_codes):
        raise DexError("Indeks DEX tidak tersedia dalam MultiDexCode.")
    result = bytearray(source)
    restored, skipped, issues = 0, 0, []
    for item in multi.dex_codes[dex_index].instructions:
        location = locations.get(item.method_index)
        if location is None:
            skipped += 1
            issues.append(f"method_id {item.method_index}: tidak memiliki code_item pada DEX dasar")
            continue
        offset, capacity = location
        if len(item.data) > capacity:
            skipped += 1
            issues.append(f"method_id {item.method_index}: payload {len(item.data)} byte melebihi kapasitas {capacity}; dilewati")
            continue
        result[offset:offset+capacity] = item.data + b"\\0" * (capacity-len(item.data))
        restored += 1
    repair_headers(result)
    validate_dex(bytes(result))
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_bytes(result)
    report = {
        "input_dex": str(dex_path), "multidexcode": str(code_path),
        "dex_index": dex_index, "version": multi.version,
        "restored_methods": restored, "skipped_methods": skipped,
        "issues": issues, "output": str(out_path),
        "output_sha256": hashlib.sha256(result).hexdigest(),
        "validation": "header_and_table_bounds_passed"
    }
    out_path.with_suffix(out_path.suffix + ".recovery.json").write_text(
        json.dumps(report, indent=2), encoding="utf-8")
    return report
