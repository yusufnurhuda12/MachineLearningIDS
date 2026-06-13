# 🛡️ NIDS Analytics Dashboard

Sistem **Network Intrusion Detection System (NIDS)** berbasis **Machine Learning** yang dirancang untuk mendeteksi aktivitas lalu lintas jaringan berbahaya seperti **Denial of Service (DoS)**, **Distributed Denial of Service (DDoS)**, **Port Scanning**, **Brute Force**, dan **Web Attack** melalui dasbor interaktif bergaya **Security Operations Center (SOC)**.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red)
![XGBoost](https://img.shields.io/badge/XGBoost-Champion_Model-green)
![RandomForest](https://img.shields.io/badge/RandomForest-Ensemble-orange)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

# 📌 Gambaran Umum

NIDS Analytics Dashboard merupakan platform pemantauan keamanan jaringan yang menggabungkan teknologi:

* Deteksi intrusi berbasis Machine Learning
* Dasbor Security Operations Center (SOC) interaktif
* Analisis dan rekomendasi berbasis Artificial Intelligence (AI)
* Pembuatan laporan otomatis dalam format PDF
* Sistem autentikasi dan manajemen pengguna

Sistem dilatih menggunakan dataset **CICIDS2017** dan diperkaya dengan sebagian data dari **CICIDS2018** untuk meningkatkan kemampuan deteksi terhadap berbagai jenis serangan jaringan modern.

---

# 🎯 Tujuan Penelitian

Penelitian ini dikembangkan untuk:

* Mengkaji efektivitas Machine Learning pada sistem Network Intrusion Detection System (NIDS).
* Membandingkan performa algoritma XGBoost dan Random Forest dalam mendeteksi serangan jaringan.
* Mengevaluasi pengaruh proses Feature Engineering terhadap akurasi model.
* Mengembangkan sistem monitoring keamanan jaringan yang mudah digunakan.
* Mengintegrasikan Generative AI sebagai pendukung interpretasi hasil deteksi keamanan jaringan.
* Menyediakan platform analisis keamanan jaringan yang dapat digunakan sebagai media pembelajaran maupun penelitian.

---

# ✨ Fitur Utama

## 🔍 Deteksi Intrusi Jaringan

Sistem mampu mengklasifikasikan lalu lintas jaringan ke dalam kategori berikut:

- **BENIGN** — Lalu lintas jaringan normal tanpa indikasi aktivitas berbahaya.
- **DoS (Denial of Service)** — Serangan yang bertujuan mengganggu ketersediaan layanan dengan membanjiri target menggunakan trafik berlebih.
- **Port Scan** — Aktivitas pemindaian port yang dilakukan untuk mengidentifikasi layanan dan celah keamanan yang terbuka pada suatu host.

Sistem dirancang untuk membantu administrator jaringan dalam mengidentifikasi aktivitas mencurigakan secara cepat melalui analisis berbasis Machine Learning.
---

## 🚀 Model Machine Learning

### Model Utama (Champion Model)

#### XGBoost Classifier

Spesifikasi:

* 400 Estimators
* Max Depth = 8
* Learning Rate = 0.05
* Per-Class Threshold Tuning

Keunggulan:

* Akurasi sangat tinggi
* Sensitivitas tinggi terhadap kelas minoritas
* Performa terbaik pada dataset penelitian

---

### Model Pembanding

#### Random Forest V1

* Model dasar sebelum optimasi
* Digunakan sebagai baseline penelitian

#### Random Forest V2

* Model hasil tuning parameter
* Digunakan sebagai pembanding terhadap XGBoost

---

## 📊 Dasbor Interaktif

Menyediakan berbagai fitur visualisasi:

* Distribusi jenis serangan
* Tren serangan jaringan
* Simulasi monitoring real-time
* Confusion Matrix
* Evaluasi performa model
* Riwayat analisis jaringan
* Statistik keamanan jaringan

---

## 🤖 Analisis AI Security Insight

Terintegrasi dengan Google Gemini AI untuk menghasilkan:

* Ringkasan eksekutif keamanan jaringan
* Analisis ancaman siber
* Rekomendasi mitigasi
* Penjelasan insiden bergaya Security Operations Center (SOC)

---

## 📄 Pembuatan Laporan Otomatis

Laporan dapat diekspor dalam format:

### CSV

Berisi:

* Hasil klasifikasi
* Detail serangan
* Data hasil analisis

### PDF

Berisi:

* Ringkasan hasil analisis
* Statistik ancaman
* Rasio serangan
* Evaluasi model
* Rekomendasi keamanan berbasis AI

---

# 👥 Role-Based Access Control (RBAC)

Sistem menerapkan mekanisme **Role-Based Access Control (RBAC)** untuk mengatur hak akses pengguna berdasarkan tingkat otorisasinya.

---

## 👤 User

Peran standar yang ditujukan untuk analis keamanan maupun pengguna umum.

### Hak Akses

* Mengunggah berkas CSV lalu lintas jaringan
* Menjalankan analisis intrusi
* Melihat hasil prediksi model
* Mengakses visualisasi dan grafik
* Menggunakan fitur AI Security Insight
* Mengunduh laporan PDF dan CSV
* Melihat riwayat analisis

### Pembatasan

* Tidak dapat mengubah konfigurasi sistem
* Tidak dapat mengelola pengguna lain
* Tidak dapat mengakses panel administrator

---

## 🛠️ Administrator

Peran yang bertanggung jawab terhadap pengelolaan operasional sistem.

### Hak Akses

Seluruh hak akses User ditambah:

* Mengakses Panel Administrator
* Mengelola konfigurasi sistem
* Mengatur integrasi Gemini AI
* Mengaktifkan atau menonaktifkan model Machine Learning
* Memelihara konfigurasi aplikasi

### Pembatasan

* Tidak dapat mengelola akun Super Administrator
* Tidak memiliki akses penuh terhadap seluruh kontrol sistem

---

## 👑 Super Administrator (Godmode)

Peran dengan tingkat otorisasi tertinggi.

### Hak Akses

Seluruh hak akses Administrator ditambah:

* Manajemen seluruh akun pengguna
* Membuat akun administrator baru
* Mengubah role pengguna
* Menghapus akun pengguna
* Mengontrol seluruh konfigurasi aplikasi
* Mengelola kebijakan keamanan sistem
* Mengelola integrasi AI dan Machine Learning
* Melakukan audit aktivitas sistem

### Ditujukan Untuk

* Pemilik Sistem
* Peneliti Utama
* Administrator Infrastruktur
* Security Operations Manager
* Dosen Pembimbing / Penguji (Mode Demonstrasi)

---

## Matriks Hak Akses

| Fitur                         | User | Administrator | Super Administrator |
| ----------------------------- | :--: | :-----------: | :-----------------: |
| Analisis Lalu Lintas Jaringan |   ✅  |       ✅       |          ✅          |
| Visualisasi Dashboard         |   ✅  |       ✅       |          ✅          |
| AI Security Insight           |   ✅  |       ✅       |          ✅          |
| Export PDF & CSV              |   ✅  |       ✅       |          ✅          |
| Riwayat Analisis              |   ✅  |       ✅       |          ✅          |
| Konfigurasi Sistem            |   ❌  |       ✅       |          ✅          |
| Pengaturan Model ML           |   ❌  |       ✅       |          ✅          |
| Konfigurasi Gemini AI         |   ❌  |       ✅       |          ✅          |
| Manajemen Pengguna            |   ❌  |       ❌       |          ✅          |
| Perubahan Role Pengguna       |   ❌  |       ❌       |          ✅          |
| Kontrol Sistem Penuh          |   ❌  |       ❌       |          ✅          |

---

# 🏗️ Arsitektur Sistem

```text
Berkas CSV Lalu Lintas Jaringan
                │
                ▼
Pembersihan dan Normalisasi Data
                │
                ▼
Feature Engineering
                │
                ▼
Standarisasi Data (Scaler)
                │
                ▼
Model Machine Learning
 ├── XGBoost
 ├── Random Forest V1
 └── Random Forest V2
                │
                ▼
Mesin Prediksi
                │
                ▼
Dasbor SOC
                │
                ├── Visualisasi
                ├── AI Security Insight
                ├── Evaluasi Model
                ├── Riwayat Analisis
                └── Laporan PDF
```

---

# 🧠 Alur Machine Learning

```text
Dataset CICIDS2017 & CICIDS2018
            │
            ▼
Data Cleaning
            │
            ▼
Feature Harmonization
            │
            ▼
Feature Engineering
            │
            ▼
Standardisasi Data
            │
            ▼
Pelatihan Model
            │
            ▼
Threshold Optimization
            │
            ▼
Prediksi Intrusi
            │
            ▼
Analisis AI
            │
            ▼
Visualisasi Dashboard
```

---

# 📂 Struktur Proyek

```text
NIDS-Dashboard/
│
├── app.py
├── models/
│   ├── xgboost_model_v2.pkl
│   ├── random_forest_model_v1.pkl
│   ├── random_forest_model_v2.pkl
│   ├── scaler_v1.pkl
│   ├── scaler_v2.pkl
│   ├── label_encoder_v2.pkl
│   └── feature_columns_v2.txt
│
├── users.json
├── config.json
├── analysis_history.json
├── requirements.txt
└── README.md
```

---

# ⚙️ Instalasi

### Clone Repository

```bash
git clone https://github.com/yusufnurhuda12/MachineLearningIDS.git
cd MachineLearningIDS
```

### Membuat Virtual Environment

```bash
python -m venv venv
```

### Aktivasi Environment

Linux/Mac:

```bash
source venv/bin/activate
```

Windows:

```bash
venv\Scripts\activate
```

### Instalasi Dependensi

```bash
pip install -r requirements.txt
```

---

# 🚀 Menjalankan Aplikasi

```bash
streamlit run app.py
```

Aplikasi dapat diakses melalui:

```text
http://localhost:8501
```

---

# 📈 Performa Model

## XGBoost (Champion Model)

| Metrik    | Nilai  |
| --------- | ------ |
| Accuracy  | 99.56% |
| Precision | 99.56% |
| Recall    | 99.00% |
| F1-Score  | 99.58% |

---

## Random Forest V2

| Metrik     | Nilai  |
| ---------- | ------ |
| Accuracy   | 95.01% |
| Recall DoS | 76.50% |
| F1-Score   | 94.92% |

---

# 📊 Dataset

Dataset utama:

* CICIDS2017

Dataset tambahan:

* CICIDS2018 (Selected Samples)

Sumber Dataset:

https://www.unb.ca/cic/datasets/

---

# 🔒 Catatan Keamanan

Sistem ini dikembangkan untuk:

* Penelitian akademik
* Tugas akhir dan skripsi
* Pembelajaran keamanan jaringan
* Eksperimen Machine Learning

Sistem belum dirancang sebagai SOC produksi skala enterprise tanpa integrasi tambahan seperti:

* SIEM (Security Information and Event Management)
* Centralized Logging
* Continuous Model Retraining
* Infrastructure Hardening

---

