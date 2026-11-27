import base64, json, os, shutil, subprocess, tempfile, threading, zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse
from dexrecovery.dex import analyze, DexError
from dexrecovery.dpt import restore

APP = Path(__file__).resolve().parent
WORK = APP / "workspace"
WORK.mkdir(exist_ok=True)
STATE = {"apk": None, "decoded": None, "dex_entries": [], "last_report": None}

def tool_path(name):
    return shutil.which(name)

def run_cmd(args, timeout=600):
    p = subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    if p.returncode:
        raise RuntimeError((p.stderr or p.stdout or "Perintah gagal")[-5000:])
    return p.stdout[-5000:]

def clean_workspace():
    if WORK.exists():
        shutil.rmtree(WORK)
    WORK.mkdir(parents=True)
    STATE.update(apk=None, decoded=None, dex_entries=[], last_report=None)

def safe_name(name):
    return Path(name.replace("\\\\", "/")).name

PAGE = r"""<!doctype html>
<html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>HMMODZ DEX Recovery</title>
<style>
:root{color-scheme:dark;--bg:#090b10;--panel:#121722;--line:#273244;--txt:#edf2fa;--muted:#9aa8ba;--accent:#7c9cff;--ok:#70d6a2;--warn:#ffca78}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 85% 0,#1b2741 0,transparent 36%),var(--bg);color:var(--txt);font:15px system-ui,Segoe UI,sans-serif}
main{max-width:1050px;margin:auto;padding:28px 18px 60px}.brand{display:flex;gap:12px;align-items:center;margin-bottom:24px}.logo{width:44px;height:44px;border:1px solid #435477;border-radius:14px;display:grid;place-items:center;color:#b8caff;font-weight:800;background:#17223a}
h1{font-size:23px;margin:0} .sub{color:var(--muted);font-size:13px;margin-top:3px}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:14px}.card{background:linear-gradient(145deg,#151d2a,#10151e);border:1px solid var(--line);border-radius:17px;padding:18px;margin-bottom:14px}
h2{font-size:16px;margin:0 0 12px}.muted{color:var(--muted);font-size:13px;line-height:1.6}
input[type=file],input[type=text],textarea{width:100%;background:#0b1019;border:1px solid #344156;color:var(--txt);padding:11px;border-radius:10px;margin:7px 0 10px}
textarea{min-height:270px;font:12px ui-monospace,monospace;white-space:pre;overflow:auto}
button{background:#263b67;color:white;border:1px solid #4b659d;border-radius:10px;padding:10px 14px;font-weight:650;cursor:pointer;margin:4px 5px 4px 0}
button.secondary{background:#1a2433;border-color:#344156}button:disabled{opacity:.4;cursor:not-allowed}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#080c12;border:1px solid #263143;padding:13px;border-radius:10px;color:#c9d6e9;font-size:12px;max-height:350px;overflow:auto}
.status{padding:10px 12px;border-radius:10px;background:#0c1720;border:1px solid #244536;color:var(--ok);margin:12px 0;font-size:13px}
.warn{color:var(--warn)}.full{grid-column:1/-1}.row{display:flex;flex-wrap:wrap;align-items:center;gap:8px}
select{background:#0b1019;color:var(--txt);border:1px solid #344156;border-radius:9px;padding:10px}
@media(max-width:700px){.grid{grid-template-columns:1fr}.full{grid-column:auto}main{padding:18px 12px}}
</style></head><body><main>
<div class="brand"><div class="logo">HM</div><div><h1>HMMODZ DEX RECOVERY</h1><div class="sub">APK inspection · DEX recovery · Manifest editor · Rebuild & sign</div></div></div>
<div class="card"><h2>01 · Buka APK</h2><p class="muted">Pilih APK milikmu. File diproses secara lokal di perangkat/komputer ini melalui server localhost.</p>
<input id="apk" type="file" accept=".apk"><button onclick="uploadApk()">Muat & analisis APK</button><div id="apkinfo" class="muted">Belum ada APK dimuat.</div></div>
<div class="grid">
<div class="card"><h2>02 · DEX yang ditemukan</h2><p class="muted">Pilih classes.dex yang ingin diperiksa atau dipulihkan.</p><select id="dexsel" style="width:100%"><option value="">Muat APK terlebih dahulu</option></select><div class="row"><button onclick="analyzeDex()">Analisis DEX</button></div></div>
<div class="card"><h2>03 · Pemulihan DPT</h2><p class="muted">Memerlukan file MultiDexCode yang cocok dengan DEX dasar. Ini bukan decryptor universal.</p>
<input id="dpt" type="file"><div class="row"><button onclick="restoreDex()">Pulihkan DEX</button></div></div>
<div class="card full"><h2>04 · AndroidManifest.xml</h2><p class="muted">Dekode APK memakai Apktool lalu tinjau/edit manifest hasil decode. Ubah package, label, activity, provider authority, dan permission hanya jika memahami dependensinya. Editor tidak otomatis mengubah seluruh referensi bytecode.</p>
<button class="secondary" onclick="decodeManifest()">Decode & tampilkan manifest</button><textarea id="manifest" placeholder="Manifest akan tampil di sini setelah Apktool decode."></textarea><button onclick="saveManifest()">Simpan perubahan manifest</button></div>
<div class="card full"><h2>05 · Rebuild APK</h2><p class="muted">Membangun ulang hasil decode dan menandatangani APK dengan debug key lokal. APK yang ditandatangani debug bukan rilis Play Store. Update aplikasi yang sudah terpasang hanya dapat dilakukan bila signature cocok dengan versi sebelumnya.</p>
<div class="row"><button onclick="rebuild()">Rebuild & sign APK</button><a id="download" hidden style="color:#a9c2ff" download>Unduh APK hasil rebuild</a></div></div>
</div>
<div class="card"><h2>Log proses</h2><pre id="log">Siap. Muat APK untuk memulai.</pre></div>
<p class="muted warn">Peringatan: tool ini hanya mendukung pemulihan format DPT/MultiDexCode yang cocok dengan parser. Proteksi komersial lain, native unpacking, runtime key extraction, dan semua bentuk enkripsi tidak otomatis dibuka. Selalu simpan APK asli.</p>
</main>
<script>
const $=id=>document.getElementById(id);
function log(x){$("log").textContent=typeof x==="string"?x:JSON.stringify(x,null,2)}
async function post(url,obj){let r=await fetch(url,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(obj)});let j=await r.json();if(!r.ok)throw Error(j.error||"Request gagal");return j}
async function file64(f){return new Promise((res,rej)=>{let r=new FileReader();r.onload=()=>res(r.result.split(",")[1]);r.onerror=rej;r.readAsDataURL(f)})}
async function uploadApk(){try{let f=$("apk").files[0];if(!f)throw Error("Pilih file APK terlebih dahulu.");let j=await post("/api/upload",{name:f.name,data:await file64(f)});$("apkinfo").textContent=\`\${j.name} · \${j.size.toLocaleString()} bytes\`;let s=$("dexsel");s.innerHTML="";j.dexes.forEach(x=>{let o=document.createElement("option");o.value=x;o.textContent=x;s.appendChild(o)});log(j)}catch(e){log(e.message)}}
async function analyzeDex(){try{let j=await post("/api/analyze",{dex:$("dexsel").value});log(j)}catch(e){log(e.message)}}
async function restoreDex(){try{let f=$("dpt").files[0];if(!f)throw Error("Pilih file MultiDexCode.");let j=await post("/api/restore",{dex:$("dexsel").value,name:f.name,data:await file64(f)});log(j)}catch(e){log(e.message)}}
async function decodeManifest(){try{let j=await post("/api/manifest/decode",{});$("manifest").value=j.manifest;log(j.message)}catch(e){log(e.message)}}
async function saveManifest(){try{let j=await post("/api/manifest/save",{manifest:$("manifest").value});log(j.message)}catch(e){log(e.message)}}
async function rebuild(){try{let j=await post("/api/rebuild",{});$("download").href=j.url;$("download").hidden=false;$("download").textContent="Unduh "+j.name;log(j)}catch(e){log(e.message)}}
</script></body></html>"""

class Handler(BaseHTTPRequestHandler):
    def send_json(self, obj, code=200):
        raw = json.dumps(obj).encode()
        self.send_response(code); self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length",str(len(raw))); self.end_headers(); self.wfile.write(raw)
    def do_GET(self):
        path=urlparse(self.path).path
        if path=="/":
            raw=PAGE.encode(); self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8")
            self.send_header("Content-Length",str(len(raw))); self.end_headers(); self.wfile.write(raw); return
        if path=="/download":
            p=WORK/"signed.apk"
            if not p.exists(): self.send_error(404); return
            raw=p.read_bytes(); self.send_response(200); self.send_header("Content-Type","application/vnd.android.package-archive")
            self.send_header("Content-Disposition",'attachment; filename="HMMODZ_recovered.apk"')
            self.send_header("Content-Length",str(len(raw))); self.end_headers(); self.wfile.write(raw); return
        self.send_error(404)
    def do_POST(self):
        try:
            n=int(self.headers.get("Content-Length","0"))
            if n>600*1024*1024: return self.send_json({"error":"Upload melebihi batas 600 MiB."},413)
            body=json.loads(self.rfile.read(n) or b"{}")
            path=urlparse(self.path).path
            if path=="/api/upload":
                clean_workspace()
                name=safe_name(body.get("name","input.apk"))
                if not name.lower().endswith(".apk"): raise ValueError("File harus berekstensi .apk.")
                raw=base64.b64decode(body["data"],validate=True)
                apk=WORK/name
                apk.write_bytes(raw)
                if not zipfile.is_zipfile(apk): raise ValueError("APK bukan arsip ZIP yang valid.")
                with zipfile.ZipFile(apk) as z:
                    dexes=[i.filename for i in z.infolist() if i.filename.endswith(".dex") and "/" not in i.filename]
                if not dexes: raise ValueError("Tidak ditemukan classes.dex di APK.")
                STATE["apk"]=apk; STATE["dex_entries"]=sorted(dexes)
                return self.send_json({"name":name,"size":len(raw),"dexes":STATE["dex_entries"]})
            if not STATE["apk"]: raise ValueError("Muat APK terlebih dahulu.")
            if path=="/api/analyze":
                entry=body.get("dex")
                if entry not in STATE["dex_entries"]: raise ValueError("DEX tidak dikenal.")
                with zipfile.ZipFile(STATE["apk"]) as z:
                    p=WORK/entry; p.write_bytes(z.read(entry))
                return self.send_json(analyze(p))
            if path=="/api/restore":
                entry=body.get("dex")
                if entry not in STATE["dex_entries"]: raise ValueError("DEX tidak dikenal.")
                dpt=WORK/safe_name(body.get("name","MultiDexCode"))
                dpt.write_bytes(base64.b64decode(body["data"],validate=True))
                with zipfile.ZipFile(STATE["apk"]) as z:
                    base=WORK/entry; base.write_bytes(z.read(entry))
                out=WORK/"recovered"/Path(entry).name
                report=restore(base,dpt,out)
                STATE["last_report"]=report
                # Place recovered DEX into APK's decoded project only after it exists.
                if STATE["decoded"]:
                    target=STATE["decoded"]/Path(entry).name
                    shutil.copy2(out,target)
                return self.send_json(report)
            if path=="/api/manifest/decode":
                if not tool_path("apktool"): raise RuntimeError("Apktool tidak ditemukan. Pasang Apktool dan pastikan perintah apktool tersedia di PATH.")
                decoded=WORK/"decoded"
                run_cmd(["apktool","d","-f","-s",str(STATE["apk"]),"-o",str(decoded)])
                manifest=decoded/"AndroidManifest.xml"
                if not manifest.exists(): raise RuntimeError("AndroidManifest.xml hasil decode tidak ditemukan.")
                STATE["decoded"]=decoded
                return self.send_json({"manifest":manifest.read_text(encoding="utf-8"),"message":"Manifest berhasil didekode. Periksa sebelum mengedit."})
            if path=="/api/manifest/save":
                if not STATE["decoded"]: raise ValueError("Decode manifest terlebih dahulu.")
                manifest=STATE["decoded"]/"AndroidManifest.xml"
                text=body.get("manifest","")
                if "<manifest" not in text or "<application" not in text: raise ValueError("Manifest tampak tidak lengkap.")
                manifest.write_text(text,encoding="utf-8")
                return self.send_json({"message":"AndroidManifest.xml tersimpan di workspace decode."})
            if path=="/api/rebuild":
                if not STATE["decoded"]: raise ValueError("Decode APK/manifest terlebih dahulu.")
                if not tool_path("apktool"): raise RuntimeError("Apktool tidak ditemukan.")
                if not tool_path("apksigner"): raise RuntimeError("apksigner tidak ditemukan. Instal Android build-tools dan tambahkan ke PATH.")
                unsigned=WORK/"unsigned.apk"
                run_cmd(["apktool","b",str(STATE["decoded"]),"-o",str(unsigned)])
                ks=WORK/"debug.keystore"
                if not ks.exists():
                    if not tool_path("keytool"): raise RuntimeError("keytool tidak ditemukan (butuh JDK).")
                    run_cmd(["keytool","-genkeypair","-v","-keystore",str(ks),"-storepass","android","-alias","androiddebugkey","-keypass","android","-keyalg","RSA","-keysize","2048","-validity","10000","-dname","CN=Android Debug,O=Android,C=US"])
                signed=WORK/"signed.apk"
                run_cmd(["apksigner","sign","--ks",str(ks),"--ks-pass","pass:android","--key-pass","pass:android","--out",str(signed),str(unsigned)])
                verify=run_cmd(["apksigner","verify","--verbose",str(signed)])
                return self.send_json({"name":signed.name,"url":"/download","size":signed.stat().st_size,"signature_verification":verify})
            return self.send_json({"error":"Endpoint tidak dikenal."},404)
        except Exception as e:
            self.send_json({"error":str(e)},400)
    def log_message(self,*args): pass

if __name__=="__main__":
    import webbrowser, time
    host="127.0.0.1"; port=8765
    server=ThreadingHTTPServer((host,port),Handler)
    print(f"HMMODZ DEX RECOVERY aktif: http://{host}:{port}")
    print("Hentikan dengan Ctrl+C. Jangan expose server ini ke jaringan publik.")
    threading.Timer(1.0,lambda:webbrowser.open(f"http://{host}:{port}")).start()
    server.serve_forever()
