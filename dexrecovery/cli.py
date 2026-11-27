import argparse, json, sys, zipfile
from pathlib import Path, PurePosixPath
from .dex import analyze, DexError, validate_dex
from .dpt import restore

def safe_extract_zip(data: bytes, out_dir: Path):
    import io
    out_dir.mkdir(parents=True, exist_ok=True)
    count = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            name = PurePosixPath(info.filename)
            if name.is_absolute() or ".." in name.parts or not name.parts:
                raise DexError(f"Path ZIP tidak aman: {info.filename}")
            if info.file_size > 256 * 1024 * 1024:
                raise DexError(f"File ZIP terlalu besar: {info.filename}")
            target = (out_dir / Path(*name.parts)).resolve()
            if out_dir.resolve() not in target.parents and target != out_dir.resolve():
                raise DexError("Path traversal ZIP terdeteksi.")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(zf.read(info))
                count += 1
    return count

def cmd_analyze(args):
    path = Path(args.dex)
    result = analyze(path)
    print(json.dumps(result, indent=2, ensure_ascii=False))
    if args.extract_zip:
        data = path.read_bytes()
        pos = data.find(b"PK\x03\x04")
        if pos >= 0:
            try:
                n = safe_extract_zip(data[pos:], Path(args.extract_zip))
                print(f"Embedded ZIP: {n} file diekstrak ke {args.extract_zip}")
            except (zipfile.BadZipFile, DexError) as exc:
                print(f"Embedded ZIP ditemukan tetapi tidak dapat diekstrak aman: {exc}")

def main():
    parser = argparse.ArgumentParser(prog="hm-dex", description="HMMODZ DEX Recovery Engine")
    sub = parser.add_subparsers(dest="command", required=True)
    a = sub.add_parser("analyze", help="Analisis struktur DEX dan indikator statis")
    a.add_argument("dex"); a.add_argument("--extract-zip", metavar="DIR")
    a.set_defaults(func=cmd_analyze)
    r = sub.add_parser("restore-dpt", help="Pulihkan format MultiDexCode DPT yang cocok")
    r.add_argument("dex"); r.add_argument("multidexcode")
    r.add_argument("-o", "--output", required=True)
    r.add_argument("--dex-index", type=int, default=0)
    def run_restore(args):
        report = restore(Path(args.dex), Path(args.multidexcode), Path(args.output), args.dex_index)
        print(json.dumps(report, indent=2, ensure_ascii=False))
        if report["skipped_methods"]:
            print("PERINGATAN: sebagian method dilewati. Periksa file recovery.json.")
    r.set_defaults(func=run_restore)
    args = parser.parse_args()
    try: args.func(args)
    except (OSError, DexError, zipfile.BadZipFile) as exc:
        print(f"ERROR: {exc}", file=sys.stderr); sys.exit(2)

if __name__ == "__main__": main()
