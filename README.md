# 🔐 Secure CI/CD Pipeline Using Jenkins

Proyek ini merupakan demonstrasi implementasi **Secure CI/CD Pipeline** dengan integrasi *security testing* dan notifikasi otomatis ke Discord.

> 💡 Dirancang oleh: **Fathur Wiriansyah**

---

## 🧱 Komponen Utama

- **Aplikasi Dummy** (`app.py`, `users.db`, dll)  
  Aplikasi Python sederhana yang digunakan sebagai target uji keamanan dalam pipeline.

- **CI/CD Pipeline** (`Jenkinsfile`)  
  Pipeline otomatis yang menggabungkan testing keamanan (SAST & DAST) dan sistem notifikasi.

- **Notifikasi Otomatis ke Discord** (`scripts/generate_report.py`)  
  Berisi script python untuk mengirim laporan hasil pengujian ke Discord menggunakan Webhook.

---

## 🔐 CI/CD Workflow  (Security Integrated)

Berikut adalah tahapan dalam Secure CI/CD Workflow:

![CI/CD Workflow](https://i.imgur.com/kcVDTGy.png)

1. **Checkout dari GitHub**
2. **Run SAST (Static Application Security Testing)**
   - `Semgrep`
   - `Bandit`
3. **Cek hasil SAST**  
   Jika ada High/Critical vuln → kirim notifikasi gagal ke Discord + report → **hentikan pipeline**

4. **Build Docker Image**
5. **Deploy Aplikasi**
6. **Run DAST (Dynamic Application Security Testing)**  
   - `Nuclei`

7. **Cek hasil DAST**  
   Jika ada High/Critical vuln → kirim notifikasi gagal ke Discord + report → **hentikan pipeline**

8. **Jika semua lolos:**  
   Kirim notifikasi sukses + hasil security report ke Discord.

---

## 📂 Struktur Repository

.
├── app.py # Aplikasi dummy untuk pengujian
├── users.db # SQLite dummy database
├── requirements.txt # Dependency Python dummy app
├── Dockerfile # Konfigurasi Docker
├── Jenkinsfile # Pipeline otomatis dengan integrasi keamanan
├── scripts/
│ └── generate_report.py # Script untuk notifikasi/report ke Discord
└── README.md


---

## ⚒️ Tools & Teknologi

| Fungsi        | Tools                         |
|---------------|-------------------------------|
| SAST          | Semgrep, Bandit               |
| DAST          | Nuclei                        |
| CI/CD         | Jenkins                       |
| Notifikasi    | Discord Webhook (`scripts/`)  |
| Container     | Docker                        |

---

## 📢 Sistem Notifikasi

Pipeline secara otomatis akan mengirimkan laporan ke Discord berdasarkan hasil pengujian:

- ✅ **Success Notification**: Jika tidak ditemukan *High/Critical* vulnerability.
- ❌ **Failed Notification**: Jika ditemukan *High/Critical* vulnerability pada SAST atau DAST.

> Semua notifikasi dikirim melalui webhook menggunakan script Python yang ada di folder `scripts/`.

---

## 🎯 Tujuan

- Menunjukkan penerapan prinsip **Secure Pipeline**.
- Memastikan aplikasi diuji dari sisi keamanan sejak tahap build.
- Menyediakan referensi CI/CD pipeline yang aman, efisien, dan open-source.

---

## 📜 Lisensi

Proyek ini memanfaatkan berbagai tools open-source dengan lisensi berikut:

| Tool          | Lisensi             | Link Lisensi Resmi                                                                |
|---------------|---------------------|-----------------------------------------------------------------------------------|
| **Jenkins**   | MIT License         | [Jenkins License](https://github.com/jenkinsci/jenkins/blob/master/LICENSE.txt)   |
| **Nuclei**    | MIT License         | [Nuclei License](https://github.com/projectdiscovery/nuclei/blob/main/LICENSE.md) |
| **Bandit**    | Apache License 2.0  | [Bandit License](https://github.com/PyCQA/bandit/blob/main/LICENSE)               |
| **Semgrep**   | LGPL 2.1            | [Semgrep License](https://github.com/returntocorp/semgrep/blob/develop/LICENSE)   |
| **Docker**    | Apache License 2.0  | [Docker License](https://github.com/moby/moby/blob/master/LICENSE)                |

> ⚠️ *Pastikan mematuhi ketentuan dari masing-masing lisensi open-source saat menggunakan atau mendistribusikan ulang proyek ini.*


---


