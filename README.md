# HMMODZ DEX RECOVERY v2.0 — Local Web UI

Aplikasi lokal lintas platform: Windows, Linux, macOS, dan Termux. Antarmuka dibuka di browser pada `http://127.0.0.1:8765`; tidak memerlukan cloud/server eksternal.

## Yang tersedia
- Memuat APK dan mendeteksi `classes.dex`, `classes2.dex`, dst.
- Menganalisis struktur DEX yang dipilih.
- Menjalankan parser/pemulihan DPT MultiDexCode yang kompatibel.
- Decode `AndroidManifest.xml` dengan Apktool, melihat dan mengedit manifest hasil decode.
- Rebuild APK dengan Apktool dan menandatangani APK dengan `apksigner`.
- Semua file kerja berada di folder `workspace/`.

## Menjalankan

### Windows
1. Install Python 3.10+.
2. Install Java JDK, Apktool, dan Android SDK Build-tools (`apksigner`).
3. Pastikan `apktool`, `keytool`, dan `apksigner` tersedia di PATH.
4. Jalankan `py app.py`, browser akan membuka halaman lokal.

### Linux / macOS
```sh
python3 app.py
```
Pastikan Java, Apktool, dan Android Build-tools terpasang dan tersedia di PATH.

### Termux
```sh
pkg update
pkg install python openjdk-17
```
Apktool dan apksigner tidak tersedia secara seragam di semua repositori Termux. Pasang keduanya secara terpisah dan pastikan executable ada di PATH. Lalu:
```sh
python app.py
```
Buka `http://127.0.0.1:8765` di browser bila tidak terbuka otomatis.

## Alur penggunaan
1. Muat `base.apk`.
2. Pilih DEX lalu klik Analisis.
3. Jika memang punya file `MultiDexCode` DPT yang kompatibel, pilih dan jalankan pemulihan.
4. Decode manifest. Tinjau dan edit manifest seperlunya.
5. Klik Rebuild & sign. Hasil `signed.apk` bisa diunduh.

## Catatan manifest
Apktool mendekode binary AndroidManifest.xml menjadi XML teks. Editor menyimpan XML tersebut ke proyek decode. Mengubah `package`, `applicationId` (di konfigurasi build), `label`, nama komponen, provider authority, permission, atau exported flag dapat memutus referensi aplikasi atau mengubah perilaku. Tool tidak otomatis menebak manifest asli yang hilang dan tidak otomatis mengganti seluruh nama package dalam DEX/resources. Untuk memulihkan identitas aplikasi secara tepat, gunakan manifest asli dari build milikmu atau cocokkan semua referensi terkait.

## Batasan pemulihan
Tool hanya memulihkan DPT `MultiDexCode` yang cocok dengan parser versi ini. Tidak mengidentifikasi/membuka semua protector, tidak mengambil kunci runtime, dan tidak menjamin aplikasi dapat berjalan setelah rebuild. Rebuild hanya menghasilkan APK yang bisa diverifikasi tanda tangannya; keberhasilan instalasi dan runtime perlu diuji pada perangkat. APK debug-signed tidak dapat memperbarui aplikasi yang ditandatangani sertifikat berbeda.

Gunakan hanya pada APK yang kamu miliki atau berwenang untuk dianalisis. Server hanya bind ke `127.0.0.1`; jangan mengubahnya menjadi server publik.
