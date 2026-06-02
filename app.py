import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
import json
import re
import plotly.express as px
import google.generativeai as genai
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
        background-image: radial-gradient(circle at 15% 50%, rgba(128, 128, 128, 0.08), transparent);
    }
    
    [data-testid="stSidebar"] { 
        backdrop-filter: blur(20px);
        -webkit-backdrop-filter: blur(20px);
        border-right: 1px solid rgba(128, 128, 128, 0.1);
        background: rgba(128, 128, 128, 0.03) !important;
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
USERS_FILE = 'users.json'
CONFIG_FILE = 'config.json'

def load_users():
    if not os.path.exists(USERS_FILE): return {}
    with open(USERS_FILE, 'r') as f: return json.load(f)

def save_users(users_data):
    with open(USERS_FILE, 'w') as f: json.dump(users_data, f)

def load_config():
    if not os.path.exists(CONFIG_FILE): return {}
    with open(CONFIG_FILE, 'r') as f: return json.load(f)

def save_config(config_data):
    with open(CONFIG_FILE, 'w') as f: json.dump(config_data, f)

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
                    users[reg_user] = {'email': reg_email, 'password': reg_pass}
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
def load_all_models():
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
    if fexists('random_forest_model_v1.pkl', 'scaler_v1.pkl'):
        models['rf_v1'] = {'model': joblib.load(find_file('random_forest_model_v1.pkl')), 'scaler': joblib.load(find_file('scaler_v1.pkl')), 'features': None, 'label_enc': None, 'thresh': None, 'name': 'Random Forest V1'}
    if fexists('random_forest_model_v2.pkl', 'scaler_v2.pkl'):
        models['rf_v2'] = {
            'model': joblib.load(find_file('random_forest_model_v2.pkl')), 'scaler': joblib.load(find_file('scaler_v2.pkl')),
            'features': [ln.strip() for ln in open(find_file('feature_columns_v2.txt')) if ln.strip()] if fexists('feature_columns_v2.txt') else None,
            'label_enc': None, 'thresh': None, 'name': 'Random Forest V2'
        }
    return models

models_dict = load_all_models()

def predict_single(model_info, X):
    if not model_info: return None
    features = model_info['features']
    if features is None:
        features = getattr(model_info['scaler'], 'feature_names_in_', getattr(model_info['model'], 'feature_names_in_', None))
    if features is not None:
        features = list(features)
    X_copy = X.copy()
    if features is not None:
        for m in [f for f in features if f not in X_copy.columns]: X_copy[m] = 0
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
menu = st.sidebar.radio("Navigasi:", ["📂 Analisis Berkas Baru", "📊 Informasi Model", "⚙️ Panel Administrator", "👨‍💻 About Us"])
st.sidebar.markdown("---")


# ═══════════════════════════════════════════════
# MENU 1 – PREDIKSI FILE BARU
# ═══════════════════════════════════════════════
if menu == "📂 Analisis Berkas Baru":
    st.header("📂 Analisis Berkas Lalu Lintas Jaringan")
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
        st.info("💡 **Tips:** Pastikan berkas CSV Anda memiliki format log jaringan standar. Sistem akan otomatis menormalkan fitur-fiturnya untuk Anda.")
        
    else:
        with st.spinner("Memproses data jaringan..."):
            df = pd.read_csv(uploaded_file)
            total_logs_global = len(df)
            st.success(f"Berhasil membaca **{total_logs_global:,}** baris data.")

            df.columns = df.columns.str.strip()
            df.rename(columns=COL_HARMONIZE, inplace=True)
            df.replace([np.inf, -np.inf], np.nan, inplace=True)
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
            if has_label:
                y_true = df['Label'].str.strip().str.upper().map(LABEL_MAP).fillna(df['Label'].str.strip().str.upper())

            # Load Config
            config_data = load_config()
            gemini_api_key = config_data.get("GEMINI_API_KEY") or os.environ.get("GEMINI_API_KEY")
            gemini_model_name = config_data.get("GEMINI_MODEL_NAME", "gemini-3.5-flash")

            # ✨ INSIGHT RENDER ENGINE
            def render_glukometer_insights(y_pred, title):
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
                    fig_line = px.line(df_analysis, x='Urutan Log Jaringan', y='Akumulasi Serangan', color_discrete_sequence=['#F43F5E'])
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
                    with v2: st.markdown(f'<div class="metric-card"><div class="metric-value blue" style="font-size:32px;">{prec*100:.2f}%</div><div class="metric-label">Presisi</div></div>', unsafe_allow_html=True)
                    with v3: st.markdown(f'<div class="metric-card"><div class="metric-value blue" style="font-size:32px;">{rec*100:.2f}%</div><div class="metric-label">Recall</div></div>', unsafe_allow_html=True)
                    with v4: st.markdown(f'<div class="metric-card"><div class="metric-value blue" style="font-size:32px;">{f1*100:.2f}%</div><div class="metric-label">F1</div></div>', unsafe_allow_html=True)
                    
                    # AI Evaluasi Model
                    eval_insight = generate_model_eval_insight_with_gemini(acc, prec, rec, f1, title, gemini_api_key, gemini_model_name)
                    st.markdown(f"""
                    <div class="insight-box" style="margin-top: 15px;">
                        <strong style="color:#0EA5E9; font-size:14px; display:block; margin-bottom:8px; font-weight: 700; letter-spacing: 0.5px;">✨ ANALISIS PERFORMA AI:</strong>
                        <p style="margin: 0; color:var(--text-color); font-size:13px; line-height:1.6; text-align:justify; font-weight: 300;">{eval_insight}</p>
                    </div>
                    """, unsafe_allow_html=True)

            X = df.copy()
            y_pred_xgb = predict_single(models_dict['xgboost'], X) if 'xgboost' in models_dict else None
            y_pred_rf1 = predict_single(models_dict['rf_v1'], X) if 'rf_v1' in models_dict else None
            y_pred_rf2 = predict_single(models_dict['rf_v2'], X) if 'rf_v2' in models_dict else None
            
            tabs = st.tabs(["🚀 XGBoost (Champion)", "🌲 Random Forest V1", "🌳 Random Forest V2"])
            with tabs[0]: render_glukometer_insights(y_pred_xgb, "XGBoost")
            with tabs[1]: render_glukometer_insights(y_pred_rf1, "Random Forest V1")
            with tabs[2]: render_glukometer_insights(y_pred_rf2, "Random Forest V2")

# ═══════════════════════════════════════════════
# MENU 2 – INFORMASI MODEL
# ═══════════════════════════════════════════════
elif menu == "📊 Informasi Model":
    st.header("📊 Spesifikasi dan Arsitektur Algoritma")
    info_tabs = st.tabs(["🚀 XGBoost v5", "🌲 Random Forest V1", "🌳 Random Forest V2"])
    
    with info_tabs[0]:
        st.markdown("<div style='color:#06B6D4; font-weight:bold; font-size:18px;'>⚡ Status: Model Utama (Champion)</div>", unsafe_allow_html=True)
        st.markdown("- **Nama Arsitektur**: XGBoost Classifier\n- **Hyperparameters**: 400 estimators, max_depth=8, learning_rate=0.05\n- **Dataset Pelatihan**: CICIDS2017 + 0.2% CICIDS2018\n- **Skor Validasi Akhir**: **Accuracy 99.56%** | DoS Recall 99.0% | F1-Score 99.58%\n- **Catatan Khusus**: Kombinasi *Per-class threshold tuning* terbukti melesatkan kepekaan klasifikasi kelas minoritas ekstrem.")
    with info_tabs[1]:
        st.markdown("<div style='color:#F43F5E; font-weight:bold; font-size:18px;'>⚠️ Status: Model Dasar (Baseline)</div>", unsafe_allow_html=True)
        st.markdown("- **Nama Arsitektur**: Random Forest Classifier (Before Tuning)\n- **Dataset Pelatihan**: Kondisi mentah mula-mula tanpa seleksi fitur.\n- **Skor Validasi Akhir**: Base Performance\n- **Fungsi Model**: Disimpan murni sebagai pembanding ilmiah pembuktian efisiensi tuning model lanjutan.")
    with info_tabs[2]:
        st.markdown("<div style='color:#14B8A6; font-weight:bold; font-size:18px;'>✅ Status: Model Teroptimasi (Tuned)</div>", unsafe_allow_html=True)
        st.markdown("- **Nama Arsitektur**: Random Forest Classifier (After Tuning)\n- **Hyperparameters**: 300 trees, max_depth=25\n- **Dataset Pelatihan**: CICIDS2017 + 0.2% CICIDS2018\n- **Skor Validasi Akhir**: Accuracy 95.01% | DoS Recall 76.5% | F1-Score 94.92%\n- **Catatan Khusus**: Seleksi fitur ketat berbasis eliminasi matriks korelasi >0.92 dilanjutkan perankingan RF Importance 95% cumsum.")

    st.divider()
    st.subheader("📈 Hasil Pengujian Validasi Silang (K-Fold Validation)")
    kfold_data = {'Metode Pengujian (K)': ['K = 5 Folds', 'K = 7 Folds', 'K = 10 Folds'], 'Rata-rata Akurasi': ['~94.8%', '~95.0%', '~95.1%'], 'Rata-rata Presisi': ['~94.5%', '~94.8%', '~94.9%'], 'Rata-rata Recall': ['~94.8%', '~95.0%', '~95.1%'], 'Status Model': ['Konsisten', 'Sangat Stabil', 'Optimal Tanpa Overfitting']}
    st.dataframe(pd.DataFrame(kfold_data), use_container_width=True, hide_index=True)
# ═══════════════════════════════════════════════
# MENU 3 – PANEL ADMINISTRATOR (DYNAMIC MULTI-MODEL SELECTOR)
# ═══════════════════════════════════════════════
elif menu == "⚙️ Panel Administrator":
    st.header("⚙️ Panel Kontrol Konfigurasi Sistem")
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
    
    if st.session_state.get('admin_save_success'):
        st.success(f"✅ Konfigurasi tersimpan sukses! Kunci API aktif dan Model utama dialihkan ke: {st.session_state.get('saved_model', current_model)}")
        st.session_state['admin_save_success'] = False

    # 3. Eksekusi Tombol Simpan Otomatis dengan Alert Trigger Sukses
    if st.button("💾 Simpan Konfigurasi Rahasia", use_container_width=True):
        if gemini_key_input.strip() != "":
            config_data['GEMINI_API_KEY'] = gemini_key_input
            config_data['GEMINI_MODEL_NAME'] = model_pilih
            save_config(config_data)
            
            st.session_state['admin_save_success'] = True
            st.session_state['saved_model'] = model_pilih
            st.rerun()
        else:
            st.warning("⚠️ Kunci token API tidak boleh kosong! Mohon isi kredensial yang valid.")


# ═══════════════════════════════════════════════
# MENU 4 – ABOUT US
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