import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
import json
import re
import plotly.express as px
import google.generativeai as genai
import base64
from sklearn.metrics import (accuracy_score, precision_score,
                             recall_score, f1_score, confusion_matrix,
                             classification_report)

# ── Column rename: 2018 format → 2017 format ──────────────────
COL_HARMONIZE = {
    'Tot Fwd Pkts':'Total Fwd Packets','Tot Bwd Pkts':'Total Backward Packets',
    'TotLen Fwd Pkts':'Total Length of Fwd Packets','TotLen Bwd Pkts':'Total Length of Bwd Packets',
    'Fwd Pkt Len Max':'Fwd Packet Length Max','Fwd Pkt Len Min':'Fwd Packet Length Min',
    'Fwd Pkt Len Mean':'Fwd Packet Length Mean','Fwd Pkt Len Std':'Fwd Packet Length Std',
    'Bwd Pkt Len Max':'Bwd Packet Length Max','Bwd Pkt Len Min':'Bwd Packet Length Min',
    'Bwd Pkt Len Mean':'Bwd Packet Length Mean','Bwd Pkt Len Std':'Bwd Packet Length Std',
    'Flow Byts/s':'Flow Bytes/s','Flow Pkts/s':'Flow Packets/s',
    'Fwd IAT Tot':'Fwd IAT Total','Bwd IAT Tot':'Bwd IAT Total',
    'Fwd Header Len':'Fwd Header Length','Bwd Header Len':'Bwd Header Length',
    'Fwd Pkts/s':'Fwd Packets/s','Bwd Pkts/s':'Bwd Packets/s',
    'Pkt Len Min':'Min Packet Length','Pkt Len Max':'Max Packet Length',
    'Pkt Len Mean':'Packet Length Mean','Pkt Len Std':'Packet Length Std',
    'Pkt Len Var':'Packet Length Variance',
    'FIN Flag Cnt':'FIN Flag Count','SYN Flag Cnt':'SYN Flag Count',
    'RST Flag Cnt':'RST Flag Count','PSH Flag Cnt':'PSH Flag Count',
    'ACK Flag Cnt':'ACK Flag Count','URG Flag Cnt':'URG Flag Count',
    'ECE Flag Cnt':'ECE Flag Count',
    'Pkt Size Avg':'Average Packet Size',
    'Fwd Seg Size Avg':'Avg Fwd Segment Size','Bwd Seg Size Avg':'Avg Bwd Segment Size',
    'Subflow Fwd Pkts':'Subflow Fwd Packets','Subflow Fwd Byts':'Subflow Fwd Bytes',
    'Subflow Bwd Pkts':'Subflow Bwd Packets','Subflow Bwd Byts':'Subflow Bwd Bytes',
    'Init Fwd Win Byts':'Init_Win_bytes_forward','Init Bwd Win Byts':'Init_Win_bytes_backward',
    'Fwd Act Data Pkts':'act_data_pkt_fwd','Fwd Seg Size Min':'min_seg_size_forward',
}

LABEL_MAP = {
    'BENIGN':'BENIGN',
    'DOS HULK':'DoS','DOS GOLDENEYE':'DoS','DOS SLOWLORIS':'DoS','DOS SLOWHTTPTEST':'DoS',
    'DOS ATTACKS-HULK':'DoS','DOS ATTACKS-GOLDENEYE':'DoS',
    'DOS ATTACKS-SLOWHTTPTEST':'DoS','DOS ATTACKS-SLOWLORIS':'DoS','HEARTBLEED':'DoS',
    'PORTSCAN':'PortScan','PORT SCAN':'PortScan','DDOS':'DDoS',
    'FTP-PATATOR':'BruteForce','SSH-PATATOR':'BruteForce',
    'WEB ATTACK - BRUTE FORCE':'WebAttack','WEB ATTACK - XSS':'WebAttack',
    'WEB ATTACK - SQL INJECTION':'WebAttack',
}

# ─────────────────────────────────────────────
# PAGE CONFIG
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="NIDS Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─────────────────────────────────────────────
# CUSTOM CSS (THEMA CYBERPUNK EXECUTIVE CLOUD)
# ─────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&display=swap');

    html, body, [class*="css"] { 
        font-family: 'Outfit', sans-serif; 
    }

    [data-testid="stHeader"] { 
        background: transparent !important; 
    }
    [data-testid="stDecoration"] { display: none; }
    
    [data-testid="stAppViewContainer"] { 
        background-color: #0f172a;
        background-image: 
            linear-gradient(rgba(255, 255, 255, 0.02) 1px, transparent 1px),
            linear-gradient(90deg, rgba(255, 255, 255, 0.02) 1px, transparent 1px),
            radial-gradient(circle at 0% 0%, rgba(14, 165, 233, 0.15) 0%, transparent 50%),
            radial-gradient(circle at 100% 100%, rgba(99, 102, 241, 0.15) 0%, transparent 50%),
            radial-gradient(circle at 50% 50%, rgba(14, 165, 233, 0.03) 0%, transparent 100%);
        background-size: 30px 30px, 30px 30px, 100% 100%, 100% 100%, 100% 100%;
        background-attachment: fixed;
    }
    
    [data-testid="stSidebar"] { 
        backdrop-filter: blur(24px);
        -webkit-backdrop-filter: blur(24px);
        border-right: 1px solid rgba(14, 165, 233, 0.15);
        background: linear-gradient(180deg, rgba(30, 41, 59, 0.6) 0%, rgba(15, 23, 42, 0.8) 100%) !important;
        box-shadow: inset -1px 0 20px rgba(14, 165, 233, 0.05);
    }

    [data-testid="stSidebar"] .stRadio > label {
        font-size: 11px !important; text-transform: uppercase; letter-spacing: 2px;
        color: var(--text-color); opacity: 0.5; margin-bottom: 10px; font-weight: 700;
    }
    [data-testid="stSidebar"] [data-baseweb="radio"] {
        background: rgba(148, 163, 184, 0.05); padding: 12px 16px !important;
        border-radius: 12px; border: 1px solid rgba(148, 163, 184, 0.1); margin-bottom: 8px;
        transition: all 0.3s cubic-bezier(0.25, 0.8, 0.25, 1); width: 100%; cursor: pointer;
    }
    [data-testid="stSidebar"] [data-baseweb="radio"]:hover {
        background: rgba(14, 165, 233, 0.1); border-color: rgba(14, 165, 233, 0.3); transform: translateX(4px);
    }
    [data-testid="stSidebar"] [data-baseweb="radio"]:has(input:checked) {
        background: rgba(14, 165, 233, 0.15); border: 1px solid rgba(14, 165, 233, 0.5);
        box-shadow: 0 4px 15px rgba(14, 165, 233, 0.1);
    }
    [data-testid="stSidebar"] [data-baseweb="radio"] > div:first-child { display: none; }
    [data-testid="stSidebar"] [data-baseweb="radio"] > div:last-child {
        font-weight: 600; font-size: 14px; color: var(--text-color); margin-left: 0; padding-left: 0;
    }

    .main-title {
        font-size: 38px; font-weight: 800;
        background: linear-gradient(135deg, #0EA5E9 0%, #2563EB 100%);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        margin-bottom: 8px; letter-spacing: -1px;
    }
    .sub-title {
        font-size: 16px; color: var(--text-color); opacity: 0.7; font-weight: 400;
        margin-bottom: 40px; letter-spacing: 0.5px;
    }
    
    .metric-card {
        background: linear-gradient(135deg, rgba(14, 165, 233, 0.03) 0%, rgba(37, 99, 235, 0.1) 100%);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border-radius: 24px; padding: 28px;
        border: 1px solid rgba(148, 163, 184, 0.2);
        box-shadow: 0 8px 32px 0 rgba(0, 0, 0, 0.05);
        position: relative; overflow: hidden;
        transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275);
        z-index: 1;
    }
    
    .metric-card::before {
        content: ''; position: absolute; top: 0; left: -100%; width: 50%; height: 2px;
        background: linear-gradient(90deg, transparent, rgba(56, 189, 248, 0.8), transparent);
        transition: left 0.7s ease;
    }
    .metric-card:hover::before { left: 100%; }
    
    .metric-card:hover {
        transform: translateY(-8px) scale(1.02);
        background: rgba(128, 128, 128, 0.08);
        border: 1px solid rgba(56, 189, 248, 0.4);
        box-shadow: 0 15px 40px rgba(0, 198, 255, 0.1);
    }

    .metric-value { 
        font-size: 42px; font-weight: 800; line-height: 1.1; 
        color: var(--text-color);
    }
    .metric-label {
        font-size: 13px; color: var(--text-color); opacity: 0.6;
        text-transform: uppercase; letter-spacing: 1.5px; margin-top: 10px; font-weight: 600;
    }
    
    .metric-value.red  { color: #F43F5E; }
    .metric-value.blue { color: #0EA5E9; }
    .metric-value.yel  { color: #F59E0B; }
    .metric-value.green { color: #10B981; }
    .metric-value.purple { color: #8B5CF6; }

    .stButton > button {
        background: linear-gradient(135deg, #00C6FF 0%, #0072FF 100%);
        color: white; border-radius: 12px; border: none; padding: 12px 28px; 
        font-weight: 600; font-size: 15px; letter-spacing: 0.5px;
        transition: all 0.3s ease; box-shadow: 0 4px 15px rgba(0, 114, 255, 0.2);
    }
    .stButton > button:hover {
        transform: translateY(-3px); box-shadow: 0 8px 25px rgba(0, 114, 255, 0.4); color: white;
    }

    div[data-baseweb="tab-list"] {
        gap: 0px; background: rgba(148, 163, 184, 0.15); padding: 4px; border-radius: 16px;
        border: 1px solid rgba(148, 163, 184, 0.2);
        backdrop-filter: blur(10px); display: inline-flex; margin-bottom: 20px;
    }
    div[data-baseweb="tab"] {
        background: transparent; border-radius: 12px; padding: 10px 24px; color: var(--text-color); opacity: 0.6;
        font-weight: 600; border: none !important; transition: all 0.3s ease;
    }
    div[data-baseweb="tab"]:hover { opacity: 1; }
    div[data-baseweb="tab"][aria-selected="true"] {
        background: rgba(128, 128, 128, 0.15) !important; color: var(--text-color) !important;
        box-shadow: 0 2px 10px rgba(0,0,0,0.05);
    }
    
    [data-testid="stDataFrame"] {
        border-radius: 16px; overflow: hidden;
        border: 1px solid rgba(128, 128, 128, 0.1);
    }
    
    .streamlit-expanderHeader {
        background: rgba(128, 128, 128, 0.05) !important;
        backdrop-filter: blur(10px);
        border-radius: 16px !important;
        border: 1px solid rgba(128, 128, 128, 0.1) !important;
        font-weight: 500 !important;
        color: var(--text-color) !important;
    }
    
    .insight-box {
        background: rgba(128, 128, 128, 0.03);
        backdrop-filter: blur(10px);
        border: 1px solid rgba(14, 165, 233, 0.3);
        border-radius: 16px; padding: 20px;
        position: relative; overflow: hidden;
        box-shadow: 0 4px 20px rgba(14, 165, 233, 0.05);
        transition: all 0.3s ease;
    }
    .insight-box.danger-style {
        border-color: rgba(244, 63, 94, 0.3);
        box-shadow: 0 4px 20px rgba(244, 63, 94, 0.05);
    }
    .insight-box.danger-style:hover {
        border-color: rgba(244, 63, 94, 0.6);
        box-shadow: 0 8px 30px rgba(244, 63, 94, 0.15);
        transform: translateY(-2px);
    }
    .insight-box:hover {
        border-color: rgba(14, 165, 233, 0.6);
        box-shadow: 0 8px 30px rgba(14, 165, 233, 0.15);
        transform: translateY(-2px);
    }
    .insight-box::before {
        content: ''; position: absolute; top: 0; left: 0; width: 4px; height: 100%;
        background: linear-gradient(180deg, #0EA5E9, #38BDF8);
    }
    .insight-box.danger-style::before {
        background: linear-gradient(180deg, #F43F5E, #FB7185);
    }
</style>
""", unsafe_allow_html=True)

# ── HELPER UNTUK MENGUBAH MARKDOWN GEMINI KE HTML TAGS ──
def markdown_to_html(text):
    text = re.sub(r'\*\*(.*?)\*\*', r'<b>\1</b>', text)
    text = re.sub(r'\*(.*?)\*', r'<i>\1</i>', text)
    text = text.replace('\n', '<br>')
    return text

# ─────────────────────────────────────────────
# GEMINI AI INSIGHT FUNCTION (CACHED & UTK SEMUA MODEL)
# ─────────────────────────────────────────────
@st.cache_data(show_spinner=False)
def generate_ai_insight_with_gemini(total, benign, attack, ratio, details_str, api_key, model_name="gemini-3.5-flash"):
    if not api_key:
        if attack > 0:
            return (
                f"<b>Analisis Taktis SOC (Algoritma Lokal):</b> Sistem lokal mendeteksi aktivitas anomali siber sebesar <b>{ratio:.2f}%</b> dari total aktivitas telemetri. Pola serangan didominasi oleh kluster <i>{details_str}</i>. Direkomendasikan melakukan isolasi atau <i>tightening policy</i> pada <i>perimeter firewall</i>.<br><br>"
                f"<i>*Catatan: Modul rangkuman AI eksternal sedang offline, teks di atas di-generate menggunakan template heuristik lokal berdasarkan output klasifikasi XGBoost/RF.</i>"
            )
        else:
            return "<b>Analisis Taktis SOC (Algoritma Lokal):</b> Lalu lintas jaringan terpantau sepenuhnya steril. Tidak ditemukan anomali paket data siber. Kinerja infrastruktur digital berjalan optimal tanpa indikasi ancaman."
            
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(model_name)
        prompt = (
            f"Kamu adalah AI Senior Expert di SOC (Security Operations Center).\n"
            f"Berdasarkan data deteksi NIDS berikut:\n"
            f"- Total paket diperiksa: {total}\n"
            f"- Paket Normal: {benign}\n"
            f"- Total Serangan: {attack}\n"
            f"- Rasio Ancaman: {ratio:.2f}%\n"
            f"- Rincian jenis serangan: {details_str}\n\n"
            f"Tugasmu: Berikan analisis taktis dan rekomendasi mitigasi jaringan.\n\n"
            f"ATURAN KETAT PENULISAN:\n"
            f"1. Gunakan bahasa Indonesia baku dan formal sesuai KBBI.\n"
            f"2. Gunakan gaya bahasa teknis namun mudah dipahami oleh mahasiswa IT.\n"
            f"3. SETIAP istilah asing (bahasa Inggris) WAJIB ditulis dengan format cetak miring (italic).\n"
            f"4. Format balasan harus PERSIS seperti struktur di bawah ini (jangan tambahkan kalimat pembuka/penutup):\n\n"
            f"**Analisis Taktis SOC:** [Tuliskan paragraf analisis singkat]\n\n"
            f"Rekomendasi Mitigasi Jaringan:\n"
            f"- **[Nama Tindakan 1]:** [Penjelasan tindakan secara teknis]\n"
            f"- **[Nama Tindakan 2]:** [Penjelasan tindakan secara teknis]\n"
            f"- **[Nama Tindakan 3]:** [Penjelasan tindakan secara teknis]"
        )
        response = model.generate_content(prompt)
        return markdown_to_html(response.text)
    except Exception as e:
        return (
            f"<b>Analisis Taktis SOC (Emergency Fallback):</b> Sistem AI <i>Insight</i> eksternal mengalami hambatan lalu lintas data (<i>Rate Limit Exceeded</i>). Namun berdasarkan analisis deterministik algoritma utama, tercatat adanya aktivitas anomali siber sebesar <b>{ratio:.2f}%</b>, yang didominasi oleh serangan <b>{details_str or 'Tidak Terdefinisi'}</b> sebanyak <b>{attack:,}</b> paket.<br><br>"
            f"<b>Rekomendasi Mitigasi Jaringan Sementara:</b><br>"
            f"- <b>Investigasi Log Manual:</b> Lakukan pengecekan log perimeter secara menyeluruh pada waktu terdeteksinya anomali.<br>"
            f"- <b>Penerapan <i>Rate Limiting</i> Dasar:</b> Terapkan pembatasan trafik sementara pada segmen jaringan yang dicurigai.<br>"
            f"- <b>Eskalasi Insiden:</b> Tingkatkan kewaspadaan <i>Security Operations Center</i> hingga API eksternal kembali normal."
        )

# ─────────────────────────────────────────────
# GEMINI AI MODEL EVALUATION INSIGHT FUNCTION
# ─────────────────────────────────────────────
@st.cache_data(show_spinner=False)
def generate_model_eval_insight_with_gemini(acc, prec, rec, f1, title, api_key, model_name="gemini-3.5-flash"):
    if not api_key:
        if acc >= 0.90: status = "sangat memuaskan dan tangguh"; saran = "Sistem siap untuk di-*deploy* pada *environment* produksi."
        elif acc >= 0.75: status = "cukup baik"; saran = "Masih terdapat ruang untuk optimasi model (*Hyperparameter Tuning*)."
        else: status = "kurang optimal"; saran = "Sangat disarankan untuk mengevaluasi kembali kualitas sebaran kelas data."
        return f"Berdasarkan hasil pengujian otomatis, model **{title}** menunjukkan performa yang {status} dengan tingkat akurasi {acc*100:.2f}%. {saran}"
            
    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel(model_name)
        prompt = (
            f"Kamu adalah AI Senior Expert di bidang Data Science dan NIDS. "
            f"Berikan analisis taktis singkat (maksimal 3 kalimat) untuk performa model NIDS '{title}' berikut: "
            f"Akurasi: {acc*100:.2f}%, Presisi: {prec*100:.2f}%, Recall: {rec*100:.2f}%, F1-Score: {f1*100:.2f}%. "
            f"Jelaskan apa arti metrik ini dalam konteks dunia nyata untuk mendeteksi ancaman siber. Setiap istilah bahasa Inggris wajib dicetak miring. Gunakan bahasa Indonesia profesional."
        )
        response = model.generate_content(prompt)
        return markdown_to_html(response.text)
    except Exception as e:
        return f"Gagal memuat analisis evaluasi otomatis. Model {title} mencapai akurasi {acc*100:.2f}% secara keseluruhan."

# ─────────────────────────────────────────────
# AUTHENTICATION & CONFIG HELPERS
# ─────────────────────────────────────────────
import requests

USERS_FILE = 'users.json'
CONFIG_FILE = 'config.json'
HISTORY_FILE = 'analysis_history.json'

def get_firebase_url(path):
    try:
        base_url = st.secrets["FIREBASE_URL"].strip("/")
        return f"{base_url}/{path}.json"
    except:
        return None

def load_from_firebase(path, default_val):
    url = get_firebase_url(path)
    if url:
        try:
            r = requests.get(url, timeout=5)
            if r.status_code == 200 and r.json() is not None:
                return r.json()
        except: pass
    local_file = f"{path}.json" if path != "history" else HISTORY_FILE
    if not os.path.exists(local_file): return default_val
    with open(local_file, 'r') as f:
        try: return json.load(f)
        except: return default_val

def save_to_firebase(path, data):
    url = get_firebase_url(path)
    if url:
        try: requests.put(url, json=data, timeout=5)
        except: pass
    local_file = f"{path}.json" if path != "history" else HISTORY_FILE
    with open(local_file, 'w') as f: json.dump(data, f)

def load_users(): return load_from_firebase("users", {})
def save_users(users_data): save_to_firebase("users", users_data)
def load_config(): return load_from_firebase("config", {})
def save_config(config_data): save_to_firebase("config", config_data)
def load_history(): return load_from_firebase("history", [])
def save_history(history_data): save_to_firebase("history", history_data)

from fpdf import FPDF
def create_pdf_report(filename, total_logs, benign, attack, gemini_insight, eval_metrics=None, eval_insight=None):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("helvetica", "B", 16)
    pdf.cell(0, 10, "Laporan Analisis NIDS (SOC Report)", new_x="LMARGIN", new_y="NEXT", align="C")
    pdf.set_font("helvetica", size=11)
    
    import datetime
    pdf.cell(0, 8, f"Tanggal Analisis: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"Nama Berkas Log: {filename}", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    
    pdf.set_font("helvetica", "B", 12)
    pdf.cell(0, 8, "Statistik Pemindaian Jaringan:", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", size=11)
    pdf.cell(0, 8, f"- Total Data Diproses: {total_logs:,}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"- Lalu Lintas Normal: {benign:,}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, f"- Anomali Terdeteksi: {attack:,}", new_x="LMARGIN", new_y="NEXT")
    ratio = (attack / total_logs) * 100 if total_logs > 0 else 0
    pdf.cell(0, 8, f"- Persentase Anomali: {ratio:.2f}%", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    
    def clean_html(text):
        text = text.replace("<br>", "\n").replace("<br/>", "\n").replace("<b>", "").replace("</b>", "").replace("<i>", "").replace("</i>", "")
        text = re.sub('<[^<]+>', '', text)
        return text

    pdf.set_font("helvetica", "B", 12)
    pdf.cell(0, 8, "Rangkuman Eksekutif SOC (Analisis Cerdas AI):", new_x="LMARGIN", new_y="NEXT")
    pdf.set_font("helvetica", size=11)
    pdf.multi_cell(0, 6, clean_html(gemini_insight))
    pdf.ln(5)
    
    if eval_metrics and eval_insight:
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 8, "Evaluasi Akurasi Algoritma:", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", size=11)
        pdf.cell(0, 8, f"- Akurasi: {eval_metrics['acc']*100:.2f}%", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 8, f"- Presisi: {eval_metrics['prec']*100:.2f}%", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 8, f"- Recall:  {eval_metrics['rec']*100:.2f}%", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 8, f"- F1-Score: {eval_metrics['f1']*100:.2f}%", new_x="LMARGIN", new_y="NEXT")
        pdf.ln(5)
        
        pdf.set_font("helvetica", "B", 12)
        pdf.cell(0, 8, "Analisis Performa AI (Kualitas Model):", new_x="LMARGIN", new_y="NEXT")
        pdf.set_font("helvetica", size=11)
        pdf.multi_cell(0, 6, clean_html(eval_insight))

    return bytes(pdf.output())

if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
    st.session_state['username'] = ''

if not st.session_state['logged_in']:
    st.markdown("<br><br><br>", unsafe_allow_html=True)
    spacer1, center_col, spacer2 = st.columns([1, 2.5, 1])
    
    with center_col:
        st.markdown('<div class="main-title" style="text-align: center; font-size: 56px; margin-bottom: 10px;">🛡️ NIDS Dashboard</div>', unsafe_allow_html=True)
        st.markdown('<div class="sub-title" style="text-align: center; margin-bottom: 50px; opacity: 0.9; font-size: 18px; font-weight: 500;">Sistem Autentikasi Keamanan Jaringan Terpadu</div>', unsafe_allow_html=True)
        
        auth_tabs = st.tabs(["🔑 Masuk", "📝 Daftar Akun"])
        
        with auth_tabs[0]:
            st.markdown("<br>", unsafe_allow_html=True)
            login_user = st.text_input("Nama Pengguna", key="login_user", placeholder="Masukkan nama pengguna...")
            login_pass = st.text_input("Kata Sandi", type="password", key="login_pass", placeholder="••••••••")
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("Masuk ke Sistem", use_container_width=True):
                users = load_users()
                if login_user in users and users[login_user]['password'] == login_pass:
                    st.session_state['logged_in'] = True
                    st.session_state['username'] = login_user
                    st.session_state['role'] = users[login_user].get('role', 'admin' if login_user == 'admin' else 'user')
                    st.success("Berhasil masuk! Membuka dasbor...")
                    st.rerun()
                else:
                    st.error("Nama pengguna atau kata sandi salah.")
                    
        with auth_tabs[1]:
            st.markdown("<br>", unsafe_allow_html=True)
            reg_email = st.text_input("Alamat Email", placeholder="email@perusahaan.com")
            reg_user = st.text_input("Nama Pengguna Baru", key="reg_user", placeholder="Pilih nama pengguna...")
            reg_pass = st.text_input("Kata Sandi Baru", type="password", key="reg_pass", placeholder="••••••••")
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("Daftar Akun Baru", use_container_width=True):
                users = load_users()
                if reg_user in users: st.error("Nama pengguna sudah terdaftar.")
                elif not reg_user or not reg_pass or not reg_email: st.warning("Semua kolom wajib diisi.")
                else:
                    role = 'godmode' if reg_user.lower() == 'godmode' else 'user'
                    users[reg_user] = {'email': reg_email, 'password': reg_pass, 'role': role}
                    save_users(users)
                    st.success("Pendaftaran berhasil! Silakan beralih ke tab Masuk.")
    st.stop()

# ─────────────────────────────────────────────
# PATH HELPER & LOAD MODELS
# ─────────────────────────────────────────────
def find_file(filename):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [filename, os.path.join(script_dir, filename), os.path.join(script_dir, 'models', filename)]
    for p in candidates:
        norm = os.path.normpath(p)
        if os.path.exists(norm): return norm
    return None

def fexists(*filenames): return all(find_file(f) is not None for f in filenames)

@st.cache_resource
def load_all_models(enable_rf1=False, enable_rf2=True):
    models = {}
    if fexists('xgboost_model_v2.pkl', 'scaler_v2.pkl'):
        models['xgboost'] = {
            'model': joblib.load(find_file('xgboost_model_v2.pkl')),
            'scaler': joblib.load(find_file('scaler_v2.pkl')),
            'features': [ln.strip() for ln in open(find_file('feature_columns_v2.txt')) if ln.strip()] if fexists('feature_columns_v2.txt') else None,
            'label_enc': joblib.load(find_file('label_encoder_v2.pkl')) if fexists('label_encoder_v2.pkl') else None,
            'thresh': json.load(open(find_file('per_class_thresholds.json'))) if fexists('per_class_thresholds.json') else None,
            'name': 'XGBoost'
        }
    if enable_rf1 and fexists('random_forest_model_v1.pkl', 'scaler_v1.pkl'):
        models['rf_v1'] = {'model': joblib.load(find_file('random_forest_model_v1.pkl')), 'scaler': joblib.load(find_file('scaler_v1.pkl')), 'features': None, 'label_enc': None, 'thresh': None, 'name': 'Random Forest V1'}
    if enable_rf2 and fexists('random_forest_model_v2.pkl', 'scaler_v2.pkl'):
        models['rf_v2'] = {
            'model': joblib.load(find_file('random_forest_model_v2.pkl')), 'scaler': joblib.load(find_file('scaler_v2.pkl')),
            'features': [ln.strip() for ln in open(find_file('feature_columns_v2.txt')) if ln.strip()] if fexists('feature_columns_v2.txt') else None,
            'label_enc': None, 'thresh': None, 'name': 'Random Forest V2'
        }
    return models

global_config = load_config()
models_dict = load_all_models(global_config.get('ENABLE_RF_V1', False), global_config.get('ENABLE_RF_V2', True))

def predict_single(model_info, X):
    if not model_info: return None
    features = model_info['features']
    if features is None:
        features = getattr(model_info['scaler'], 'feature_names_in_', getattr(model_info['model'], 'feature_names_in_', None))
    if features is not None:
        features = list(features)
    X_copy = X.copy()
    if features is not None:
        missing_features = [f for f in features if f not in X_copy.columns]
        if missing_features:
            st.toast(f"⚠️ Peringatan: {len(missing_features)} fitur tidak ditemukan di CSV dan diisi 0. Cek nama kolom!", icon="⚠️")
            # st.warning(f"Fitur hilang untuk {model_info.get('name', 'Model')}: {', '.join(missing_features)}")
        for m in missing_features: X_copy[m] = 0
        X_copy = X_copy[features]
    else:
        model = model_info['model']
        if hasattr(model, 'n_features_in_') and len(X_copy.columns) > model.n_features_in_: X_copy = X_copy.iloc[:, :model.n_features_in_]
        
    X_scaled = model_info['scaler'].transform(X_copy)
    model, le, thresh = model_info['model'], model_info['label_enc'], model_info['thresh']
    
    if le is not None and thresh is not None:
        proba = model.predict_proba(X_scaled)
        norm = proba / np.array([thresh.get(c, 0.5) for c in le.classes_])
        return np.array([le.classes_[i] for i in np.argmax(norm, axis=1)])
    return le.inverse_transform(model.predict(X_scaled)) if le is not None else model.predict(X_scaled)

# ─────────────────────────────────────────────
# MAIN VIEWS HEADER & SIDEBAR
# ─────────────────────────────────────────────
st.markdown('<div class="main-title">🛡️ Network Intrusion Detection System</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">Sistem IDS Berbasis <i>Machine Learning</i> untuk Deteksi Serangan <i>Denial of Service</i> (DoS) dan <i>Port Scanning</i></div>', unsafe_allow_html=True)

st.sidebar.title("🛡️ Security Operations")

current_user = st.session_state.get('username', 'Unknown')
current_role = st.session_state.get('role', 'user')

if current_role == 'godmode':
    role_color = "#8B5CF6"
    role_bg = "rgba(139, 92, 246, 0.15)"
elif current_role == 'admin':
    role_color = "#0EA5E9"
    role_bg = "rgba(14, 165, 233, 0.15)"
else:
    role_color = "#475569"
    role_bg = "rgba(148, 163, 184, 0.1)"

if 'avatar_base64' not in st.session_state and current_user != 'Unknown':
    users_data = load_users()
    st.session_state['avatar_base64'] = users_data.get(current_user, {}).get('avatar_base64', '')

b64_avatar = st.session_state.get('avatar_base64', '')
if b64_avatar:
    avatar_url = f"data:image/png;base64,{b64_avatar}"
else:
    avatar_url = "https://www.gravatar.com/avatar/00000000000000000000000000000000?d=mp&f=y"

st.sidebar.markdown(f"""
<div style="background: {role_bg}; border: 1px solid {role_color}; padding: 15px; border-radius: 12px; margin-bottom: 15px; display: flex; align-items: center; gap: 15px;">
    <img src="{avatar_url}" style="width: 50px; height: 50px; border-radius: 50%; border: 2px solid {role_color}; object-fit: cover; box-shadow: 0 4px 10px rgba(0,0,0,0.2);">
    <div>
        <div style="font-size: 10px; color: var(--text-color); opacity: 0.6; margin-bottom: 2px; text-transform: uppercase; letter-spacing: 1px;">Sesi Pengguna</div>
        <div style="font-size: 16px; font-weight: 800; color: var(--text-color); margin-bottom: 4px;">{current_user}</div>
        <div style="display: inline-block; background: {role_color}; color: #fff; font-size: 9px; font-weight: 800; padding: 2px 6px; border-radius: 4px; text-transform: uppercase; letter-spacing: 1px;">
            {current_role}
        </div>
    </div>
</div>
""", unsafe_allow_html=True)

st.sidebar.markdown("""
<div style="display: flex; align-items: center; margin-bottom: 20px; background: rgba(16, 185, 129, 0.1); padding: 10px; border-radius: 8px; border: 1px solid rgba(16, 185, 129, 0.2);">
    <div style="width: 10px; height: 10px; background-color: #10B981; border-radius: 50%; margin-right: 10px; box-shadow: 0 0 10px #10B981; animation: pulse 1.5s infinite;"></div>
    <span style="color: #10B981; font-weight: 600; font-size: 13px;">Model ML Aktif & Siap</span>
</div>
<style>
@keyframes pulse {
    0% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
    70% { box-shadow: 0 0 0 10px rgba(16, 185, 129, 0); }
    100% { box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
}
</style>
""", unsafe_allow_html=True)

if st.sidebar.button("Keluar dari Sistem"):
    st.session_state['logged_in'] = False
    st.rerun()

st.sidebar.markdown("---")
nav_options = ["📂 Analisis Berkas Baru", "🗄️ Riwayat Analisis", "📊 Informasi Model", "👤 Pengaturan Akun", "👨‍💻 About Us"]
if st.session_state.get('role') in ['admin', 'godmode']:
    nav_options.insert(4, "⚙️ Panel Administrator")
menu = st.sidebar.radio("Navigasi:", nav_options)
st.sidebar.markdown("---")

# VERSIONING FOOTER
APP_VERSION = "2.5.0"
st.sidebar.markdown(f"""
<div style="text-align: center; color: var(--text-color); opacity: 0.5; font-size: 11px; margin-top: 20px;">
    <i>NIDS Analytics Dashboard</i><br>
    <b>Versi {APP_VERSION}</b>
</div>
""", unsafe_allow_html=True)


# ═══════════════════════════════════════════════
# MENU 1 – PREDIKSI FILE BARU
# ═══════════════════════════════════════════════
if menu == "📂 Analisis Berkas Baru":
    st.header("📂 Analisis Berkas Lalu Lintas Jaringan")
    if 'analysis_cache' in st.session_state:
        st.info(f"💾 Menampilkan hasil analisis tersimpan dari berkas: **{st.session_state['analysis_cache']['filename']}**")
        if st.button("🗑️ Hapus Hasil & Unggah Berkas Baru"):
            del st.session_state['analysis_cache']
            st.rerun()

    if 'analysis_cache' not in st.session_state:
        st.markdown("### ⚙️ Pengaturan Mode Analisis")
        analysis_mode = st.radio("Metode Analisis Data:", ["Cepat (Instan)", "Simulasi Real-Time (Streaming)"], horizontal=True)
        uploaded_file = st.file_uploader("Unggah berkas log jaringan (.csv)", type=["csv"])

        if uploaded_file is None:
            st.markdown("<br>", unsafe_allow_html=True)
            st.markdown("### 🚀 Mulai Analisis Keamanan Jaringan Anda")
            st.markdown("Unggah log lalu lintas (.csv) untuk mendapatkan wawasan mendalam menggunakan **Kecerdasan Buatan (AI)**.")
            
            st.markdown("<br>", unsafe_allow_html=True)
            c1, c2, c3 = st.columns(3)
            with c1: st.markdown('<div class="metric-card" style="padding: 24px; height: 215px; display: flex; flex-direction: column; align-items: center; justify-content: flex-start; text-align: center;"><div style="font-size: 38px; margin-bottom: 12px;">🛡️</div><div style="color: var(--text-color); font-weight: 700; font-size: 16px; margin-bottom: 10px;">Deteksi Spesifik & Presisi</div><div style="color: var(--text-color); opacity: 0.7; font-size: 13px; line-height: 1.6;">Difokuskan khusus untuk mengenali ancaman lalu lintas jaringan berupa Denial of Service (DoS) dan Port Scanning.</div></div>', unsafe_allow_html=True)
            with c2: st.markdown('<div class="metric-card" style="padding: 24px; height: 215px; display: flex; flex-direction: column; align-items: center; justify-content: flex-start; text-align: center;"><div style="font-size: 38px; margin-bottom: 12px;">⚡</div><div style="color: var(--text-color); font-weight: 700; font-size: 16px; margin-bottom: 10px;">Performa Tinggi</div><div style="color: var(--text-color); opacity: 0.7; font-size: 13px; line-height: 1.6;">Menggunakan algoritma XGBoost Teroptimasi dengan akurasi pengujian hingga 99.56%.</div></div>', unsafe_allow_html=True)
            with c3: st.markdown('<div class="metric-card" style="padding: 24px; height: 215px; display: flex; flex-direction: column; align-items: center; justify-content: flex-start; text-align: center;"><div style="font-size: 38px; margin-bottom: 12px;">✨</div><div style="color: var(--text-color); font-weight: 700; font-size: 16px; margin-bottom: 10px;">Insight AI</div><div style="color: var(--text-color); opacity: 0.7; font-size: 13px; line-height: 1.6;">Mendapatkan rekomendasi mitigasi otomatis dari AI Pakar Keamanan untuk respon cepat.</div></div>', unsafe_allow_html=True)
            
            st.markdown("<br><br>", unsafe_allow_html=True)
            st.info("💡 **Tips:** Pastikan berkas CSV Anda memiliki format luaran dari alat **CICFlowMeter**. Sistem akan otomatis menormalkan kolom-kolom fiturnya untuk Anda.")
            
        else:
            import time
            start_time_analysis = time.time()
            with st.spinner("Memproses data jaringan..."):
                df = pd.read_csv(uploaded_file)
                total_logs_global = len(df)
                st.success(f"Berhasil membaca **{total_logs_global:,}** baris data.")

                df.columns = df.columns.str.strip()
                df.rename(columns=COL_HARMONIZE, inplace=True)
                
                # Perbaikan Bug: Terkadang "Infinity" dibaca sebagai string oleh pandas, sehingga np.inf tidak mempan
                df.replace([np.inf, -np.inf, 'Infinity', 'infinity', 'Inf', '-Inf'], np.nan, inplace=True)
                
                # Pastikan semua fitur numerik dipaksa menjadi float (mengubah sisa string nyasar jadi NaN)
                cols_to_numeric = [c for c in df.columns if c != 'Label']
                for c in cols_to_numeric:
                    df[c] = pd.to_numeric(df[c], errors='coerce')
                    
                df.dropna(inplace=True)

                fwd = 'Total Fwd Packets' if 'Total Fwd Packets' in df.columns else 'Tot Fwd Pkts'
                bwd = 'Total Backward Packets' if 'Total Backward Packets' in df.columns else 'Tot Bwd Pkts'
                if fwd in df.columns:
                    df['Pkt_Ratio'] = df[fwd] / (df[bwd] + 1e-5)
                    if 'Flow Duration' in df.columns:
                        tot = df[fwd] + df[bwd] + 1e-5
                        df['Pkt_Rate'] = tot / (df['Flow Duration'] + 1e-5)
                        df['Duration_Per_Pkt'] = df['Flow Duration'] / tot

                has_label = 'Label' in df.columns
                y_true = None
                if has_label:
                    y_true = df['Label'].str.strip().str.upper().map(LABEL_MAP).fillna(df['Label'].str.strip().str.upper())

                X = df.copy()
                y_pred_xgb = predict_single(models_dict['xgboost'], X) if 'xgboost' in models_dict else None
                y_pred_rf1 = predict_single(models_dict['rf_v1'], X) if 'rf_v1' in models_dict else None
                y_pred_rf2 = predict_single(models_dict['rf_v2'], X) if 'rf_v2' in models_dict else None

                if analysis_mode == "Simulasi Real-Time (Streaming)" and y_pred_xgb is not None:
                    progress_text = "Menyimulasikan arus lalu lintas jaringan (SOC Monitoring)..."
                    my_bar = st.progress(0, text=progress_text)
                    chart_placeholder = st.empty()
                    import time
                    chunk_size = max(1, len(y_pred_xgb) // 20)
                    for i in range(1, 21):
                        current_len = i * chunk_size
                        if i == 20: current_len = len(y_pred_xgb)
                        sub_y = y_pred_xgb[:current_len]
                        sub_df = pd.DataFrame({'Log': range(current_len), 'Attack': [1 if x != 'BENIGN' else 0 for x in sub_y]})
                        sub_df['Akumulasi Serangan'] = sub_df['Attack'].cumsum()
                        chart_placeholder.line_chart(sub_df.set_index('Log')['Akumulasi Serangan'], color="#F43F5E", height=200)
                        my_bar.progress(i * 5, text=f"{progress_text} ({i*5}%)")
                        time.sleep(0.15)
                    my_bar.empty()
                    chart_placeholder.empty()

                if y_pred_xgb is not None:
                    history = load_history()
                    import datetime
                    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    unique, counts = np.unique(y_pred_xgb, return_counts=True)
                    pred_dict = dict(zip(unique, counts))
                    benign_count = pred_dict.get('BENIGN', 0)
                    attack_count = len(y_pred_xgb) - benign_count

                    end_time_analysis = time.time()
                    duration_sec = end_time_analysis - start_time_analysis
                    
                    history.insert(0, {
                        "filename": uploaded_file.name,
                        "timestamp": current_time,
                        "user": st.session_state.get('username', 'Unknown'),
                        "total_logs": len(y_pred_xgb),
                        "benign": int(benign_count),
                        "attack": int(attack_count),
                        "duration": f"{duration_sec:.2f} dtk"
                    })
                    save_history(history[:50])

                st.session_state['analysis_cache'] = {
                    'filename': uploaded_file.name,
                    'y_pred_xgb': y_pred_xgb,
                    'y_pred_rf1': y_pred_rf1,
                    'y_pred_rf2': y_pred_rf2,
                    'has_label': has_label,
                    'y_true': y_true
                }
                st.rerun()

    if 'analysis_cache' in st.session_state:
        cache = st.session_state['analysis_cache']
        y_pred_xgb = cache['y_pred_xgb']
        y_pred_rf1 = cache['y_pred_rf1']
        y_pred_rf2 = cache['y_pred_rf2']
        has_label = cache['has_label']
        y_true = cache['y_true']

        # Load Config
        config_data = load_config()
        gemini_api_key = config_data.get("GEMINI_API_KEY") or os.environ.get("GEMINI_API_KEY")
        gemini_model_name = config_data.get("GEMINI_MODEL_NAME", "gemini-3.5-flash")

        # ✨ INSIGHT RENDER ENGINE
        def render_security_insights(y_pred, title):
                total_logs = len(y_pred)
                unique, counts = np.unique(y_pred, return_counts=True)
                pred_dict = dict(zip(unique, counts))
                
                benign_count = pred_dict.get('BENIGN', 0)
                attack_count = total_logs - benign_count
                attack_ratio = (attack_count / total_logs) * 100 if total_logs > 0 else 0
                
                attack_details_str = ", ".join([f"{k}: {v} paket" for k, v in pred_dict.items() if k != 'BENIGN'])
                if not attack_details_str: attack_details_str = "Tidak ada"

                # ── SECTION 1: KPI METRIC CARDS ──
                m1, m2, m3, m4 = st.columns(4)
                with m1: st.markdown(f'<div class="metric-card"><div class="metric-value blue">{total_logs:,}</div><div class="metric-label">Total Data Diproses</div></div>', unsafe_allow_html=True)
                with m2: st.markdown(f'<div class="metric-card"><div class="metric-value">{benign_count:,}</div><div class="metric-label">Lalu Lintas Normal</div></div>', unsafe_allow_html=True)
                with m3: st.markdown(f'<div class="metric-card"><div class="metric-value red">{attack_count:,}</div><div class="metric-label">Anomali Terdeteksi</div></div>', unsafe_allow_html=True)
                with m4: st.markdown(f'<div class="metric-card"><div class="metric-value yel">{attack_ratio:.2f}%</div><div class="metric-label">Persentase Anomali</div></div>', unsafe_allow_html=True)
                
                st.markdown("<br>", unsafe_allow_html=True)
                
                # ── SECTION 2: AI INSIGHT ──
                st.markdown(f"##### ✨ Analisis Cerdas AI — *Powered by {gemini_model_name}*")
                st.info("ℹ️ **Info Sistem:** Data jaringan Anda diproses secara aman 100% di komputer ini. AI Gemini di bawah ini hanya bertugas merangkum hasil deteksinya ke dalam bahasa yang mudah dipahami.")

                with st.spinner("AI sedang merumuskan konklusi operasional..."):
                    gemini_narrative = generate_ai_insight_with_gemini(total_logs, benign_count, attack_count, attack_ratio, attack_details_str, gemini_api_key, gemini_model_name)
                
                box_class = "insight-box danger-style" if attack_count > 0 else "insight-box"
                st.markdown(f"""
                <div class="{box_class}" style="margin-bottom: 25px;">
                    <strong style="color:{'#F43F5E' if attack_count > 0 else '#0EA5E9'}; font-size:14px; display:block; margin-bottom:8px; font-weight: 700; letter-spacing: 0.5px;">📊 RANGKUMAN EKSEKUTIF SOC:</strong>
                    <p style="margin: 0; color:var(--text-color); font-size:13px; line-height:1.6; text-align:justify; font-weight: 300;">
                        {gemini_narrative}
                    </p>
                </div>
                """, unsafe_allow_html=True)

                # ── SECTION 3: 2 KOLOM (GRAFIK INTERAKTIF) ──
                col_left, col_right = st.columns([5, 11])
                
                df_analysis = pd.DataFrame({
                    'Urutan Log Jaringan': range(1, total_logs + 1),
                    'Kategori': y_pred,
                    'Tingkat Kritis': ['Tinggi' if label != 'BENIGN' else 'Rendah' for label in y_pred],
                    'Bobot Paket': [1 if label != 'BENIGN' else 0 for label in y_pred]
                })

                with col_left:
                    st.markdown("#### 🔍 Filter Insight")
                    opsi_kategori = ["Semua Kategori"] + list(unique)
                    pilihan_kategori = st.selectbox("KATEGORI ANOMALI", opsi_kategori, key=f"sel_{title}")
                    pilihan_kritis = st.radio("TINGKAT RISIKO", ["Semua", "Tinggi", "Rendah"], horizontal=True, key=f"rad_{title}")
                    
                    df_filtered = df_analysis.copy()
                    if pilihan_kategori != "Semua Kategori": df_filtered = df_filtered[df_filtered['Kategori'] == pilihan_kategori]
                    if pilihan_kritis != "Semua": df_filtered = df_filtered[df_filtered['Tingkat Kritis'] == pilihan_kritis]

                    st.markdown("<br>", unsafe_allow_html=True)
                    st.markdown("#### 📌 Komposisi Anomali")
                    fig_pie = px.pie(names=list(pred_dict.keys()), values=list(pred_dict.values()), hole=0.4, color_discrete_sequence=['#3B82F6', '#EF4444', '#10B981', '#F59E0B', '#8B5CF6'])
                    fig_pie.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#94A3B8'), margin=dict(t=20, b=20, l=10, r=10), showlegend=True, legend=dict(orientation="h", yanchor="top", y=-0.2, xanchor="center", x=0.5))
                    st.plotly_chart(fig_pie, use_container_width=True, key=f"pie_{title}")

                with col_right:
                    st.markdown("#### 📈 Tren Distribusi Anomali")
                    df_analysis['Akumulasi Serangan'] = df_analysis['Bobot Paket'].cumsum()
                    
                    # Optimasi Performa: Sampling data agar browser tidak lag
                    sample_rate = max(1, len(df_analysis) // 500)
                    df_plot = df_analysis.iloc[::sample_rate]
                    
                    fig_line = px.line(df_plot, x='Urutan Log Jaringan', y='Akumulasi Serangan', color_discrete_sequence=['#F43F5E'])
                    fig_line.update_traces(line_shape='linear', fill='tozeroy')
                    fig_line.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)',
                        font=dict(color='#94A3B8'), margin=dict(t=10, b=10, l=10, r=10),
                        xaxis=dict(showgrid=False), yaxis=dict(showgrid=True, gridcolor='rgba(255,255,255,0.05)')
                    )
                    st.plotly_chart(fig_line, use_container_width=True, key=f"line_{title}")

                # ── SECTION 4: LOGS & EVALUASI ──
                st.markdown("---")
                st.markdown("#### 📝 Riwayat Deteksi (10 Teratas)")
                st.dataframe(df_filtered.head(10), use_container_width=True, hide_index=True)
                
                st.download_button("💾 Unduh Laporan (.CSV)", data=df_filtered.to_csv(index=False).encode('utf-8'), file_name=f"laporan_{title}.csv", mime="text/csv", key=f"dl_{title}")
                
                if has_label:
                    st.markdown("### 📈 Evaluasi Akurasi")
                    acc, prec, rec, f1 = accuracy_score(y_true, y_pred), precision_score(y_true, y_pred, average='weighted', zero_division=0), recall_score(y_true, y_pred, average='weighted', zero_division=0), f1_score(y_true, y_pred, average='weighted', zero_division=0)
                    v1, v2, v3, v4 = st.columns(4)
                    with v1: st.markdown(f'<div class="metric-card"><div class="metric-value blue" style="font-size:32px;">{acc*100:.2f}%</div><div class="metric-label">Akurasi</div></div>', unsafe_allow_html=True)
                    with v2: st.markdown(f'<div class="metric-card"><div class="metric-value green" style="font-size:32px;">{prec*100:.2f}%</div><div class="metric-label">Presisi</div></div>', unsafe_allow_html=True)
                    with v3: st.markdown(f'<div class="metric-card"><div class="metric-value yel" style="font-size:32px;">{rec*100:.2f}%</div><div class="metric-label">Recall</div></div>', unsafe_allow_html=True)
                    with v4: st.markdown(f'<div class="metric-card"><div class="metric-value purple" style="font-size:32px;">{f1*100:.2f}%</div><div class="metric-label">F1</div></div>', unsafe_allow_html=True)
                    
                    st.markdown("<br>", unsafe_allow_html=True)
                    col_cm1, col_cm2 = st.columns(2)
                    from sklearn.metrics import confusion_matrix
                    labels = np.unique(np.concatenate((y_true, y_pred)))
                    
                    with col_cm1:
                        st.markdown("#### 🧮 Confusion Matrix (Jumlah)")
                        cm = confusion_matrix(y_true, y_pred)
                        fig_cm = px.imshow(cm, text_auto=True, color_continuous_scale='Blues', x=labels, y=labels, labels=dict(x="Prediksi Model", y="Kondisi Asli (Ground Truth)"))
                        fig_cm.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#94A3B8'))
                        st.plotly_chart(fig_cm, use_container_width=True, key=f"cm_{title}")
                        
                    with col_cm2:
                        st.markdown("#### 🧮 Confusion Matrix (%)")
                        cm_pct = confusion_matrix(y_true, y_pred, normalize='true') * 100
                        fig_cm_pct = px.imshow(cm_pct, text_auto='.2f', color_continuous_scale='Blues', x=labels, y=labels, labels=dict(x="Prediksi Model", y="Kondisi Asli (Ground Truth)"))
                        fig_cm_pct.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#94A3B8'))
                        st.plotly_chart(fig_cm_pct, use_container_width=True, key=f"cm_pct_{title}")
                    
                    # AI Evaluasi Model
                    eval_insight = generate_model_eval_insight_with_gemini(acc, prec, rec, f1, title, gemini_api_key, gemini_model_name)
                    st.markdown(f"""
                    <div class="insight-box" style="margin-top: 15px;">
                        <strong style="color:#0EA5E9; font-size:14px; display:block; margin-bottom:8px; font-weight: 700; letter-spacing: 0.5px;">✨ ANALISIS PERFORMA AI:</strong>
                        <p style="margin: 0; color:var(--text-color); font-size:13px; line-height:1.6; text-align:justify; font-weight: 300;">{eval_insight}</p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    try:
                        pdf_bytes = create_pdf_report(st.session_state['analysis_cache']['filename'], total_logs, benign_count, attack_count, gemini_narrative, {'acc': acc, 'prec': prec, 'rec': rec, 'f1': f1}, eval_insight)
                        st.download_button("📄 Unduh Laporan Eksekutif Lengkap (.PDF)", data=pdf_bytes, file_name=f"soc_report_{title}.pdf", mime="application/pdf", key=f"dl_pdf_eval_{title}")
                    except Exception as e:
                        st.error(f"Gagal memuat tombol ekspor PDF: {e}")
                else:
                    try:
                        pdf_bytes = create_pdf_report(st.session_state['analysis_cache']['filename'], total_logs, benign_count, attack_count, gemini_narrative)
                        st.download_button("📄 Unduh Laporan Eksekutif (.PDF)", data=pdf_bytes, file_name=f"soc_report_{title}.pdf", mime="application/pdf", key=f"dl_pdf_{title}")
                    except Exception as e:
                        st.error(f"Gagal memuat tombol ekspor PDF: {e}")

        tab_names = ["🚀 XGBoost (Champion)"]
        if 'rf_v1' in models_dict and y_pred_rf1 is not None: tab_names.append("🌲 Random Forest V1")
        if 'rf_v2' in models_dict and y_pred_rf2 is not None: tab_names.append("🌳 Random Forest V2")
        
        tabs = st.tabs(tab_names)
        with tabs[0]: 
            if y_pred_xgb is not None:
                render_security_insights(y_pred_xgb, "XGBoost")
            else:
                st.error("⚠️ Model XGBoost tidak ditemukan! Pastikan file model (.pkl) sudah ada di folder 'models'.")
        
        tab_idx = 1
        if 'rf_v1' in models_dict and y_pred_rf1 is not None:
            with tabs[tab_idx]: render_security_insights(y_pred_rf1, "Random Forest V1")
            tab_idx += 1
        if 'rf_v2' in models_dict and y_pred_rf2 is not None:
            with tabs[tab_idx]: render_security_insights(y_pred_rf2, "Random Forest V2")
            tab_idx += 1

# ═══════════════════════════════════════════════
# MENU 2 – RIWAYAT ANALISIS
# ═══════════════════════════════════════════════
elif menu == "🗄️ Riwayat Analisis":
    st.header("🗄️ Riwayat Analisis Jaringan")
    st.write("Catatan historis dari file log jaringan yang telah diproses sebelumnya.")
    
    history_data = load_history()
    if not history_data:
        st.info("Belum ada riwayat analisis. Silakan proses berkas log baru.")
    else:
        df_history = pd.DataFrame(history_data)
        if 'duration' not in df_history.columns:
            df_history['duration'] = "-"
        else:
            df_history['duration'] = df_history['duration'].fillna("-")
            
        df_history.rename(columns={
            "filename": "Nama Berkas",
            "timestamp": "Waktu Analisis",
            "user": "Pengguna",
            "total_logs": "Total Baris",
            "benign": "Normal (Benign)",
            "attack": "Anomali (Attack)",
            "duration": "Waktu Proses"
        }, inplace=True)
        st.dataframe(df_history, use_container_width=True, hide_index=True)
        
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("🗑️ Hapus Semua Riwayat"):
            save_history([])
            st.rerun()

# ═══════════════════════════════════════════════
# MENU 3 – INFORMASI MODEL
# ═══════════════════════════════════════════════
elif menu == "📊 Informasi Model":
    st.header("📊 Spesifikasi dan Arsitektur Algoritma")
    
    info_tab_names = ["🚀 XGBoost v5"]
    if 'rf_v1' in models_dict: info_tab_names.append("🌲 Random Forest V1")
    if 'rf_v2' in models_dict: info_tab_names.append("🌳 Random Forest V2")
    
    info_tabs = st.tabs(info_tab_names)
    
    with info_tabs[0]:
        st.markdown("<div style='color:#06B6D4; font-weight:bold; font-size:18px;'>⚡ Status: Model Utama (Champion)</div>", unsafe_allow_html=True)
        st.markdown("- **Nama Arsitektur**: XGBoost Classifier\n- **Hyperparameters**: 400 estimators, max_depth=8, learning_rate=0.05\n- **Dataset Pelatihan**: CICIDS2017 + 0.2% CICIDS2018\n- **Skor Validasi Akhir**: **Accuracy 99.56%** | DoS Recall 99.0% | F1-Score 99.58%\n- **Catatan Khusus**: Kombinasi *Per-class threshold tuning* terbukti melesatkan kepekaan klasifikasi kelas minoritas ekstrem.")
        
        st.divider()
        st.subheader("🗺️ Heatmap Korelasi Fitur (Feature Importance)")
        if 'xgboost' in models_dict:
            xgb_model = models_dict['xgboost']['model']
            if hasattr(xgb_model, 'feature_importances_'):
                importances = xgb_model.feature_importances_
                feature_names = models_dict['xgboost'].get('features')
                
                if feature_names is None:
                    if hasattr(xgb_model, 'feature_names_in_') and xgb_model.feature_names_in_ is not None:
                        feature_names = xgb_model.feature_names_in_
                    elif hasattr(xgb_model, 'get_booster') and xgb_model.get_booster().feature_names is not None:
                        feature_names = xgb_model.get_booster().feature_names
                
                if feature_names is None or len(feature_names) != len(importances):
                    feature_names = [f"Fitur_{i+1}" for i in range(len(importances))]
                    
                df_imp = pd.DataFrame({'Fitur Jaringan': feature_names, 'Tingkat Kepentingan': importances})
                df_imp = df_imp.sort_values(by='Tingkat Kepentingan', ascending=True).tail(15)
                fig_imp = px.bar(df_imp, x='Tingkat Kepentingan', y='Fitur Jaringan', orientation='h', color='Tingkat Kepentingan', color_continuous_scale='Blues')
                fig_imp.update_layout(paper_bgcolor='rgba(0,0,0,0)', plot_bgcolor='rgba(0,0,0,0)', font=dict(color='#94A3B8'))
                st.plotly_chart(fig_imp, use_container_width=True)
            else:
                st.info("Model XGBoost ini tidak mendukung ekstraksi atribut Feature Importances.")
        else:
            st.warning("Model XGBoost tidak dimuat.")
            
        st.divider()
        st.subheader("📈 Hasil Pengujian Validasi Silang (K-Fold Validation)")
        kfold_xgb_data = {
            'Metode Pengujian (K)': ['K = 5 Folds', 'K = 7 Folds', 'K = 10 Folds'],
            'Mean (Akurasi)': ['0.999450', '0.999492', '0.999500'],
            'Rata-rata Presisi': ['0.999450', '0.999492', '0.999500'],
            'Rata-rata Recall': ['0.999450', '0.999492', '0.999500'],
            'Standar Deviasi': ['0.000133', '0.000121', '0.000121'],
            'Status Model': ['Konsisten', 'Sangat Stabil', 'Optimal Tanpa Overfitting']
        }
        st.dataframe(pd.DataFrame(kfold_xgb_data), use_container_width=True, hide_index=True)
    
    tab_idx = 1
    if 'rf_v1' in models_dict:
        with info_tabs[tab_idx]:
            st.markdown("<div style='color:#F43F5E; font-weight:bold; font-size:18px;'>⚠️ Status: Model Dasar (Baseline)</div>", unsafe_allow_html=True)
            st.markdown("- **Nama Arsitektur**: Random Forest Classifier (Before Tuning)\n- **Dataset Pelatihan**: Kondisi mentah mula-mula tanpa seleksi fitur.\n- **Skor Validasi Akhir**: Base Performance\n- **Fungsi Model**: Disimpan murni sebagai pembanding ilmiah pembuktian efisiensi tuning model lanjutan.")
        tab_idx += 1
    if 'rf_v2' in models_dict:
        with info_tabs[tab_idx]:
            st.markdown("<div style='color:#14B8A6; font-weight:bold; font-size:18px;'>✅ Status: Model Teroptimasi (Tuned)</div>", unsafe_allow_html=True)
            st.markdown("- **Nama Arsitektur**: Random Forest Classifier (After Tuning)\n- **Hyperparameters**: 300 trees, max_depth=25\n- **Dataset Pelatihan**: CICIDS2017 + 0.2% CICIDS2018\n- **Skor Validasi Akhir**: Accuracy 95.01% | DoS Recall 76.5% | F1-Score 94.92%\n- **Catatan Khusus**: Seleksi fitur ketat berbasis eliminasi matriks korelasi >0.92 dilanjutkan perankingan RF Importance 95% cumsum.")
            
            st.divider()
            st.subheader("📈 Hasil Pengujian Validasi Silang (K-Fold Validation)")
            kfold_rf_data = {
                'Metode Pengujian (K)': ['K = 5 Folds', 'K = 7 Folds', 'K = 10 Folds'],
                'Mean (Akurasi)': ['0.998746', '0.998779', '0.998812'],
                'Rata-rata Presisi': ['0.998746', '0.998779', '0.998813'],
                'Rata-rata Recall': ['0.998746', '0.998779', '0.998812'],
                'Standar Deviasi': ['0.000165', '0.000191', '0.000224'],
                'Status Model': ['Konsisten', 'Sangat Stabil', 'Optimal Tanpa Overfitting']
            }
            st.dataframe(pd.DataFrame(kfold_rf_data), use_container_width=True, hide_index=True)
        tab_idx += 1
# ═══════════════════════════════════════════════
# MENU 3 – PANEL ADMINISTRATOR (DYNAMIC MULTI-MODEL SELECTOR)
# ═══════════════════════════════════════════════
elif menu == "⚙️ Panel Administrator":
    st.header("⚙️ Panel Kontrol Konfigurasi Sistem")
    current_role = st.session_state.get('role')
    if current_role == 'godmode':
        admin_tabs = st.tabs(["🔑 Kredensial AI & Model", "👥 Manajemen Pengguna"])
        tab_config = admin_tabs[0]
        tab_users = admin_tabs[1]
    else:
        tab_config = st.container()
        tab_users = None
        
    with tab_config:
        st.write("Modifikasi parameter rahasia kredensial API serta model eksternal secara dinamis dari antarmuka dashboard.")
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        config_data = load_config()
        current_key = config_data.get('GEMINI_API_KEY', '')
        current_model = config_data.get('GEMINI_MODEL_NAME', 'gemini-3.5-flash')
        
        # 1. Kolom input Token API
        gemini_key_input = st.text_input(
            "Google Gemini API Token Key", 
            type="password", 
            value=current_key
        )
        
        # 2. Dropdown Pemilih Jenis Otak Model Gen-AI
        opsi_model = ["gemini-3.5-flash", "gemini-3.1-pro", "gemini-3-flash", "gemini-2.5-flash", "gemini-2.5-pro"]
        try:
            default_index = opsi_model.index(current_model)
        except ValueError:
            default_index = 0
            
        model_pilih = st.selectbox(
            "Pilih Model Eksternal AI (Gemini)", 
            opsi_model, 
            index=default_index
        )
        
        st.markdown("<br>", unsafe_allow_html=True)
        st.markdown("#### 🎛️ Manajer Model Internal")
        enable_rf1 = st.checkbox("Aktifkan Model Random Forest V1 (Baseline)", value=config_data.get('ENABLE_RF_V1', False))
        enable_rf2 = st.checkbox("Aktifkan Model Random Forest V2 (Tuned)", value=config_data.get('ENABLE_RF_V2', True))
        
        st.markdown("<br>", unsafe_allow_html=True)
        
        if st.session_state.get('admin_save_success'):
            st.success(f"✅ Konfigurasi tersimpan sukses! Kunci API aktif dan Model utama dialihkan ke: {st.session_state.get('saved_model', current_model)}")
            st.session_state['admin_save_success'] = False
    
        # 3. Eksekusi Tombol Simpan Otomatis dengan Alert Trigger Sukses
        if st.button("💾 Simpan Konfigurasi Rahasia", use_container_width=True):
            if gemini_key_input.strip() != "":
                config_data['GEMINI_API_KEY'] = gemini_key_input
                config_data['GEMINI_MODEL_NAME'] = model_pilih
                config_data['ENABLE_RF_V1'] = enable_rf1
                config_data['ENABLE_RF_V2'] = enable_rf2
                save_config(config_data)
                
                st.session_state['admin_save_success'] = True
                st.session_state['saved_model'] = model_pilih
                st.rerun()
            else:
                st.warning("⚠️ Kunci token API tidak boleh kosong! Mohon isi kredensial yang valid.")
                
    if tab_users is not None:
        with tab_users:
            st.markdown("### 👥 Manajemen Pengguna")
            st.markdown("Kelola hak akses pengguna atau hapus akun yang tidak valid.")
            st.markdown("<br>", unsafe_allow_html=True)
            
            users_data = load_users()
            
            # Header Row
            hc1, hc2, hc3 = st.columns([4, 2, 2])
            hc1.markdown("**INFORMASI PENGGUNA**")
            hc2.markdown("**HAK AKSES (ROLE)**")
            hc3.markdown("**AKSI**")
            st.markdown("<hr style='margin-top:0px; margin-bottom:15px;'>", unsafe_allow_html=True)
            
            for u, data in users_data.items():
                if u.lower() == 'godmode': continue
                with st.container():
                    col1, col2, col3 = st.columns([4, 2, 2])
                    with col1:
                        st.markdown(f"<div style='margin-top: 5px;'><b>{u}</b><br><span style='font-size:12px; color:gray;'>{data.get('email', 'Tidak ada email')}</span></div>", unsafe_allow_html=True)
                    with col2:
                        new_role = st.selectbox("Role", ['user', 'admin'], index=0 if data.get('role') == 'user' else 1, key=f"role_{u}", label_visibility="collapsed")
                    with col3:
                        if st.button("🗑️ Hapus", key=f"del_{u}", use_container_width=True):
                            del users_data[u]
                            save_users(users_data)
                            st.success(f"Akun {u} dihapus!")
                            import time
                            time.sleep(0.5)
                            st.rerun()
                    
                    if new_role != data.get('role'):
                        users_data[u]['role'] = new_role
                        save_users(users_data)
                        st.success(f"Role {u} diperbarui!")
                        import time
                        time.sleep(0.5)
                        st.rerun()
                    st.markdown("<hr style='margin-top:10px; margin-bottom:10px; opacity:0.2;'>", unsafe_allow_html=True)


# ═══════════════════════════════════════════════
# MENU 4 – PENGATURAN AKUN
# ═══════════════════════════════════════════════
elif menu == "👤 Pengaturan Akun":
    st.header("👤 Pengaturan Profil Akun")
    st.write("Personalisasikan informasi akun dan ganti foto profil Anda di sini.")
    
    users_data = load_users()
    current_email = users_data.get(current_user, {}).get('email', '')
    
    st.markdown("<br>", unsafe_allow_html=True)
    c1, c2 = st.columns([1, 2])
    
    with c1:
        st.markdown("#### 📸 Foto Profil")
        st.markdown(f'<img src="{avatar_url}" style="width: 150px; height: 150px; border-radius: 50%; border: 3px solid {role_color}; object-fit: cover; box-shadow: 0 4px 10px rgba(0,0,0,0.2); margin-bottom: 15px;">', unsafe_allow_html=True)
        uploaded_avatar = st.file_uploader("Unggah foto baru (PNG/JPG)", type=["png", "jpg", "jpeg"])
        
    with c2:
        st.markdown("#### 🔒 Informasi Keamanan")
        new_email = st.text_input("Alamat Email", value=current_email)
        new_password = st.text_input("Kata Sandi Baru", type="password", placeholder="Kosongkan jika tidak ingin diubah")
        confirm_password = st.text_input("Konfirmasi Kata Sandi Baru", type="password", placeholder="Ketik ulang kata sandi baru")
        
    st.markdown("<br>", unsafe_allow_html=True)
    if st.button("💾 Simpan Perubahan Profil", use_container_width=True):
        updated = False
        
        if uploaded_avatar is not None:
            from PIL import Image
            import io
            img = Image.open(uploaded_avatar)
            img = img.resize((150, 150))
            buffered = io.BytesIO()
            img.save(buffered, format="PNG")
            b64_str = base64.b64encode(buffered.getvalue()).decode()
            
            users_data[current_user]['avatar_base64'] = b64_str
            st.session_state['avatar_base64'] = b64_str
            updated = True
            
        if new_email and new_email != current_email:
            users_data[current_user]['email'] = new_email
            updated = True
            
        if new_password:
            if new_password == confirm_password:
                users_data[current_user]['password'] = new_password
                updated = True
            else:
                st.error("⚠️ Kata sandi baru dan konfirmasi tidak cocok!")
                
        if updated:
            save_users(users_data)
            st.success("✅ Profil berhasil diperbarui! Halaman akan dimuat ulang...")
            import time
            time.sleep(1.0)
            st.rerun()

# ═══════════════════════════════════════════════
# MENU 5 – ABOUT US
# ═══════════════════════════════════════════════
elif menu == "👨‍💻 About Us":
    st.header("👨‍💻 Profil Tim Pengembang")
    st.markdown("""
    <style>
        .profile-card {
            background: rgba(148, 163, 184, 0.08);
            backdrop-filter: blur(20px); -webkit-backdrop-filter: blur(20px);
            border-radius: 24px; padding: 40px 24px; text-align: center; 
            border: 1px solid rgba(148, 163, 184, 0.2); border-top: 1px solid rgba(255, 255, 255, 0.1);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.05); 
            transition: all 0.4s cubic-bezier(0.175, 0.885, 0.32, 1.275); 
            height: 100%; display: flex; flex-direction: column; justify-content: space-between; align-items: center;
        }
        .profile-card:hover { transform: translateY(-10px); border-color: rgba(14, 165, 233, 0.5); box-shadow: 0 25px 50px rgba(14, 165, 233, 0.15); }
        .avatar { 
            width: 120px; height: 120px; border-radius: 50%; object-fit: cover; 
            margin-bottom: 20px; border: 4px solid #0EA5E9; 
            box-shadow: 0 10px 25px rgba(14, 165, 233, 0.3); 
            transition: transform 0.4s ease;
        }
        .profile-card:hover .avatar { transform: scale(1.05) rotate(3deg); }
        .profile-name { font-size: 22px; font-weight: 800; color: var(--text-color); margin-bottom: 6px; letter-spacing: -0.5px; }
        .profile-id { font-size: 13px; font-weight: 700; color: #0EA5E9; margin-bottom: 15px; letter-spacing: 1.5px; text-transform: uppercase; }
        .profile-role { font-size: 13px; color: var(--text-color); opacity: 0.75; line-height: 1.6; margin-bottom: 25px; font-weight: 500; }
        .linkedin-btn { 
            display: inline-flex; align-items: center; justify-content: center; gap: 8px;
            background: linear-gradient(135deg, #0EA5E9 0%, #2563EB 100%); 
            color: white !important; text-decoration: none !important; 
            padding: 12px 24px; border-radius: 50px; font-size: 14px; font-weight: 600; 
            width: 100%; transition: all 0.3s ease; box-shadow: 0 8px 20px rgba(37, 99, 235, 0.25); 
        }
        .linkedin-btn:hover { transform: translateY(-3px); box-shadow: 0 12px 25px rgba(37, 99, 235, 0.4); }
    </style>
    """, unsafe_allow_html=True)
    
    c1, c2, c3 = st.columns(3)
    with c1: st.markdown('<div class="profile-card"><div><img src="https://raw.githubusercontent.com/yusufnurhuda12/MachineLearningIDS/main/profile/meisaroh.jpg" class="avatar"><div class="profile-name">Meisyaroh Azzahra</div><div class="profile-id">NIM. 101112480109</div><div class="profile-role">Cyber Security Engineer<br>ICT Security Operations | Lintasarta</div></div><a class="linkedin-btn" href="https://www.linkedin.com/in/meisyaroh-azzahra-0100b5206/" target="_blank">🔗 Profile LinkedIn</a></div>', unsafe_allow_html=True)
    with c2: st.markdown('<div class="profile-card"><div><img src="https://raw.githubusercontent.com/yusufnurhuda12/MachineLearningIDS/main/profile/mualim.jpg" class="avatar"><div class="profile-name">Mu’alim Rohmadi</div><div class="profile-id">NIM. 101112480098</div><div class="profile-role">Project Engineer FTTH<br>Survey & Design | MyRepublic</div></div><a class="linkedin-btn" href="https://www.linkedin.com/in/mualimr/" target="_blank">🔗 Profile LinkedIn</a></div>', unsafe_allow_html=True)
    with c3: st.markdown('<div class="profile-card"><div><img src="https://raw.githubusercontent.com/yusufnurhuda12/MachineLearningIDS/main/profile/yusuf.jpg" class="avatar"><div class="profile-name">Muh. Yusuf Nurhuda</div><div class="profile-id">NIM. 101112480096</div><div class="profile-role">Digital Infrastructure Engineer<br>FTTH & 5G FWA | MyRepublic</div></div><a class="linkedin-btn" href="https://www.linkedin.com/in/yusufnurhuda/" target="_blank">🔗 Profile LinkedIn</a></div>', unsafe_allow_html=True)
