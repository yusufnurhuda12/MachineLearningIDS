import streamlit as st
import pandas as pd
import numpy as np
import joblib
import os
import json
import plotly.express as px
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
# CUSTOM CSS
# ─────────────────────────────────────────────
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;800&display=swap');

    html, body, [class*="css"] { font-family: 'Inter', sans-serif; }

    .main-title {
        font-size: 42px; font-weight: 800;
        background: linear-gradient(45deg, #1E3A8A, #3B82F6, #8B5CF6);
        -webkit-background-clip: text; -webkit-text-fill-color: transparent;
        text-align: center; margin-bottom: 8px;
    }
    .sub-title {
        font-size: 17px; color: #6B7280;
        text-align: center; margin-bottom: 36px; font-weight: 400;
    }
    .metric-card {
        background: rgba(255,255,255,0.05);
        backdrop-filter: blur(10px);
        border-radius: 16px; padding: 20px;
        text-align: center;
        border: 1px solid rgba(255,255,255,0.1);
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .metric-value { font-size: 32px; font-weight: 700; color: #10B981; }
    .metric-label {
        font-size: 12px; color: #9CA3AF;
        text-transform: uppercase; letter-spacing: 0.05em; margin-top: 4px;
    }
    .metric-value.red  { color: #EF4444; }
    .metric-value.blue { color: #3B82F6; }
    .metric-value.yel  { color: #F59E0B; }
</style>
""", unsafe_allow_html=True)
# ─────────────────────────────────────────────
# AUTHENTICATION (LOGIN & REGISTER)
# ─────────────────────────────────────────────
USERS_FILE = 'users.json'

def load_users():
    if not os.path.exists(USERS_FILE):
        return {}
    with open(USERS_FILE, 'r') as f:
        return json.load(f)

def save_users(users_data):
    with open(USERS_FILE, 'w') as f:
        json.dump(users_data, f)

if 'logged_in' not in st.session_state:
    st.session_state['logged_in'] = False
    st.session_state['username'] = ''

if not st.session_state['logged_in']:
    st.markdown('<div class="main-title">🛡️ NIDS Dashboard</div>', unsafe_allow_html=True)
    st.markdown('<div class="sub-title">Silakan Login atau Registrasi untuk melanjutkan</div>', unsafe_allow_html=True)
    
    auth_tabs = st.tabs(["🔑 Login", "📝 Register"])
    
    with auth_tabs[0]:
        st.subheader("Login Akun")
        login_user = st.text_input("Username", key="login_user")
        login_pass = st.text_input("Password", type="password", key="login_pass")
        if st.button("Login"):
            users = load_users()
            if login_user in users and users[login_user]['password'] == login_pass:
                st.session_state['logged_in'] = True
                st.session_state['username'] = login_user
                st.success("Login berhasil!")
                st.rerun()
            else:
                st.error("Username atau password salah.")
                
    with auth_tabs[1]:
        st.subheader("Registrasi Akun Baru")
        reg_email = st.text_input("Email")
        reg_user = st.text_input("Username", key="reg_user")
        reg_pass = st.text_input("Password", type="password", key="reg_pass")
        if st.button("Register"):
            users = load_users()
            if reg_user in users:
                st.error("Username sudah terdaftar. Silakan gunakan username lain.")
            elif not reg_user or not reg_pass or not reg_email:
                st.warning("Semua kolom harus diisi.")
            else:
                users[reg_user] = {'email': reg_email, 'password': reg_pass}
                save_users(users)
                st.success("Registrasi berhasil! Silakan login di tab sebelah.")
    
    st.stop() # Hentikan eksekusi script selanjutnya jika belum login


# ─────────────────────────────────────────────
# PATH HELPER — cari file di beberapa lokasi
# ─────────────────────────────────────────────
def find_file(filename):
    """Cari file di CWD, direktori script, parent dir, dan /code (HF Spaces)."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        filename,                                        # CWD
        os.path.join(script_dir, filename),              # sama dengan script
        os.path.join(script_dir, 'models', filename),    # folder models
        os.path.join(script_dir, '..', filename),        # parent (HF: /code)
        os.path.join('/code', filename),                 # HF Spaces root
    ]
    for p in candidates:
        norm = os.path.normpath(p)
        if os.path.exists(norm):
            return norm
    return None   # tidak ditemukan

def fexists(*filenames):
    """Return True jika SEMUA file ditemukan."""
    return all(find_file(f) is not None for f in filenames)

# ─────────────────────────────────────────────
# ─────────────────────────────────────────────
# LOAD 3 MODELS (XGBoost, RF V1, RF V2)
# ─────────────────────────────────────────────
@st.cache_resource
def load_all_models():
    models = {}
    
    # ── XGBoost v2 (v5) ──
    if fexists('xgboost_model_v2.pkl', 'scaler_v2.pkl'):
        model_xgb = joblib.load(find_file('xgboost_model_v2.pkl'))
        scaler_xgb = joblib.load(find_file('scaler_v2.pkl'))
        le_xgb = joblib.load(find_file('label_encoder_v2.pkl')) if fexists('label_encoder_v2.pkl') else None
        
        features_xgb = None
        if fexists('feature_columns_v2.txt'):
            with open(find_file('feature_columns_v2.txt')) as f:
                features_xgb = [ln.strip() for ln in f if ln.strip()]
                
        thresh_xgb = None
        if fexists('per_class_thresholds.json'):
            with open(find_file('per_class_thresholds.json')) as f:
                thresh_xgb = json.load(f)
                
        models['xgboost'] = {
            'model': model_xgb, 'scaler': scaler_xgb, 'features': features_xgb,
            'label_enc': le_xgb, 'thresh': thresh_xgb, 'name': 'XGBoost'
        }
    
    # ── RF V1 (Before tuning) ──
    if fexists('random_forest_model_v1.pkl', 'scaler_v1.pkl'):
        model_rf1 = joblib.load(find_file('random_forest_model_v1.pkl'))
        scaler_rf1 = joblib.load(find_file('scaler_v1.pkl'))
        models['rf_v1'] = {
            'model': model_rf1, 'scaler': scaler_rf1, 'features': None,
            'label_enc': None, 'thresh': None, 'name': 'Random Forest V1'
        }

    # ── RF V2 (After tuning) ──
    if fexists('random_forest_model_v2.pkl', 'scaler_v2.pkl'):
        model_rf2 = joblib.load(find_file('random_forest_model_v2.pkl'))
        scaler_rf2 = joblib.load(find_file('scaler_v2.pkl'))
        features_rf2 = None
        if fexists('feature_columns_v2.txt'):
            with open(find_file('feature_columns_v2.txt')) as f:
                features_rf2 = [ln.strip() for ln in f if ln.strip()]
        models['rf_v2'] = {
            'model': model_rf2, 'scaler': scaler_rf2, 'features': features_rf2,
            'label_enc': None, 'thresh': None, 'name': 'Random Forest V2'
        }
        
    return models

models_dict = load_all_models()

def predict_single(model_info, X):
    if not model_info: return None
    
    features = model_info['features']
    # Fallback to feature_names_in_ from scaler/model if available
    if not features and hasattr(model_info['scaler'], 'feature_names_in_'):
        features = list(model_info['scaler'].feature_names_in_)
    elif not features and hasattr(model_info['model'], 'feature_names_in_'):
        features = list(model_info['model'].feature_names_in_)
        
    X_copy = X.copy()
    if features:
        missing = [f for f in features if f not in X_copy.columns]
        for m in missing:
            X_copy[m] = 0
        X_copy = X_copy[features]
    else:
        # Fallback jika tidak ada feature_cols spesifik (mungkin perlu disesuaikan dgn n_features_in_)
        # Ambil sejumlah fitur yg dimau model (jika punya attr tersebut)
        model = model_info['model']
        if hasattr(model, 'n_features_in_') and len(X_copy.columns) > model.n_features_in_:
            X_copy = X_copy.iloc[:, :model.n_features_in_]
        
    X_scaled = model_info['scaler'].transform(X_copy)
    
    model = model_info['model']
    le = model_info['label_enc']
    thresh = model_info['thresh']
    
    if le is not None and thresh is not None:
        classes = le.classes_
        proba = model.predict_proba(X_scaled)
        thresh_arr = np.array([thresh.get(c, 0.5) for c in classes])
        norm = proba / thresh_arr
        idx = np.argmax(norm, axis=1)
        return np.array([classes[i] for i in idx])
    elif le is not None:
        return le.inverse_transform(model.predict(X_scaled))
    else:
        return model.predict(X_scaled)

# ─────────────────────────────────────────────
# HEADER
# ─────────────────────────────────────────────
st.markdown('<div class="main-title">🛡️ Network Intrusion Detection System</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">Deteksi Serangan Jaringan Menggunakan Machine Learning – XGBoost + Random Forest</div>', unsafe_allow_html=True)

if not models_dict:
    st.error("⚠️ Model belum ditemukan! Pastikan model berada di dalam folder `models/`.")
    st.stop()

# ─────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────
st.sidebar.title("🛡️ NIDS Dashboard")
if st.sidebar.button("Logout"):
    st.session_state['logged_in'] = False
    st.rerun()

menu = st.sidebar.radio("Pilih Menu:", ["📂 Prediksi File Baru", "📊 Informasi Model", "👨‍💻 About Us"])
st.sidebar.success(f"Login sebagai: {st.session_state.get('username', 'User')}")


# ═══════════════════════════════════════════════
# MENU 1 – PREDIKSI FILE BARU
# ═══════════════════════════════════════════════
if menu == "📂 Prediksi File Baru":
    st.header("📂 Upload Dataset untuk Prediksi")
    st.write("Unggah file CSV berisi traffic jaringan. Dashboard akan mendeteksi apakah ada serangan.")

    uploaded_file = st.file_uploader("Pilih file CSV", type=["csv"])

    if uploaded_file is not None:
        with st.spinner("Membaca dan memproses data (semua baris)... Harap tunggu ⏳"):
            df = pd.read_csv(uploaded_file)
            total_rows = len(df)
            st.write(f"✅ Berhasil memuat **{total_rows:,}** baris data.")

            st.subheader("Preview Data Asli")
            st.dataframe(df.head())

            # ── Preprocessing ──
            df.columns = df.columns.str.strip()
            # Feature harmonization: rename kolom 2018 → 2017
            df.rename(columns=COL_HARMONIZE, inplace=True)
            df.replace([np.inf, -np.inf], np.nan, inplace=True)
            df.dropna(inplace=True)

            # Feature engineering
            fwd = 'Total Fwd Packets' if 'Total Fwd Packets' in df.columns else 'Tot Fwd Pkts'
            bwd = 'Total Backward Packets' if 'Total Backward Packets' in df.columns else 'Tot Bwd Pkts'
            if fwd in df.columns:
                df['Pkt_Ratio'] = df[fwd] / (df[bwd] + 1e-5)
                if 'Flow Duration' in df.columns:
                    tot = df[fwd] + df[bwd] + 1e-5
                    df['Pkt_Rate']         = tot / (df['Flow Duration'] + 1e-5)
                    df['Duration_Per_Pkt'] = df['Flow Duration'] / tot

            # Label harmonization
            has_label = 'Label' in df.columns
            if has_label:
                y_true = df['Label'].str.strip().str.upper()
                y_true = y_true.map(LABEL_MAP).fillna(y_true)

            def render_prediction_results(y_pred, title):
                st.subheader(f"Hasil: {title}")
                # ── Distribusi + Tabel ──
                col1, col2 = st.columns(2)

                with col1:
                    st.markdown("**Distribusi Prediksi**")
                    pred_counts = pd.Series(y_pred).value_counts().reset_index()
                    pred_counts.columns = ['Status', 'Jumlah']
                    fig_pie = px.pie(pred_counts, values='Jumlah', names='Status',
                                     hole=0.42,
                                     color_discrete_sequence=px.colors.qualitative.Safe)
                    fig_pie.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)',
                        font=dict(color='#E5E7EB'),
                        margin=dict(t=10, b=10, l=10, r=10)
                    )
                    st.plotly_chart(fig_pie, use_container_width=True, key=f"pie_{title}")

                with col2:
                    st.markdown("**Tabel Hasil (10 baris pertama)**")
                    df_res = pd.DataFrame({'Hasil_Prediksi': y_pred})
                    st.dataframe(df_res.head(10))
                    
                    csv_data = df_res.to_csv(index=False).encode('utf-8')
                    st.download_button(
                        label="⬇️ Download Hasil Prediksi",
                        data=csv_data,
                        file_name=f"hasil_{title}.csv",
                        mime="text/csv",
                        key=f"dl_{title}"
                    )

                # ── Evaluasi (jika ada label) ──
                if has_label:
                    st.divider()
                    st.markdown("**📊 Evaluasi vs Label Asli**")

                    acc  = accuracy_score(y_true, y_pred)
                    prec = precision_score(y_true, y_pred, average='weighted', zero_division=0)
                    rec  = recall_score(y_true, y_pred, average='weighted', zero_division=0)
                    f1   = f1_score(y_true, y_pred, average='weighted', zero_division=0)

                    m1, m2, m3, m4 = st.columns(4)
                    with m1:
                        st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-value">{acc*100:.2f}%</div>
                            <div class="metric-label">Accuracy</div>
                        </div>""", unsafe_allow_html=True)
                    with m2:
                        st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-value blue">{prec*100:.2f}%</div>
                            <div class="metric-label">Precision</div>
                        </div>""", unsafe_allow_html=True)
                    with m3:
                        st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-value yel">{rec*100:.2f}%</div>
                            <div class="metric-label">Recall</div>
                        </div>""", unsafe_allow_html=True)
                    with m4:
                        st.markdown(f"""
                        <div class="metric-card">
                            <div class="metric-value red">{f1*100:.2f}%</div>
                            <div class="metric-label">F1-Score</div>
                        </div>""", unsafe_allow_html=True)

                    st.markdown("<br>", unsafe_allow_html=True)

                    # Classification Report
                    with st.expander("📋 Lihat Classification Report"):
                        report = classification_report(y_true, y_pred,
                                                       zero_division=0, output_dict=True)
                        st.dataframe(pd.DataFrame(report).transpose().round(4))

                    # Confusion Matrix
                    st.markdown("**🔢 Confusion Matrix**")
                    labels_cm = sorted(y_true.unique())
                    cm = confusion_matrix(y_true, y_pred, labels=labels_cm)

                    fig_cm = px.imshow(
                        cm,
                        text_auto=True,
                        x=labels_cm, y=labels_cm,
                        labels=dict(x="Predicted", y="Actual", color="Jumlah"),
                        color_continuous_scale="Blues",
                        title="Confusion Matrix"
                    )
                    fig_cm.update_layout(
                        paper_bgcolor='rgba(0,0,0,0)',
                        font=dict(color='#E5E7EB'),
                    )
                    st.plotly_chart(fig_cm, use_container_width=True, key=f"cm_{title}")

            X = df.copy()

            try:
                st.write("Mengeksekusi model Machine Learning...")
                prog_bar = st.progress(0)
                
                y_pred_xgb, y_pred_rf1, y_pred_rf2 = None, None, None
                
                if 'xgboost' in models_dict:
                    y_pred_xgb = predict_single(models_dict['xgboost'], X)
                prog_bar.progress(33)
                
                if 'rf_v1' in models_dict:
                    y_pred_rf1 = predict_single(models_dict['rf_v1'], X)
                prog_bar.progress(66)
                
                if 'rf_v2' in models_dict:
                    y_pred_rf2 = predict_single(models_dict['rf_v2'], X)
                prog_bar.progress(100)
                
                st.success("🎉 Prediksi dari semua model Selesai!")

                # Menampilkan 3 tab untuk setiap hasil model
                tabs = st.tabs(["XGBoost v5", "Random Forest V1", "Random Forest V2"])
                
                with tabs[0]:
                    if y_pred_xgb is not None:
                        render_prediction_results(y_pred_xgb, "XGBoost")
                    else:
                        st.warning("Model XGBoost tidak ditemukan.")
                
                with tabs[1]:
                    if y_pred_rf1 is not None:
                        render_prediction_results(y_pred_rf1, "Random Forest V1")
                    else:
                        st.warning("Model Random Forest V1 tidak ditemukan.")
                        
                with tabs[2]:
                    if y_pred_rf2 is not None:
                        render_prediction_results(y_pred_rf2, "Random Forest V2")
                    else:
                        st.warning("Model Random Forest V2 tidak ditemukan.")

            except Exception as e:
                st.error(f"Terjadi kesalahan saat memproses data: {e}")
                st.info("Pastikan file CSV memiliki fitur yang sama dengan dataset latihan.")


# ═══════════════════════════════════════════════
# MENU 2 – INFORMASI MODEL
# ═══════════════════════════════════════════════
elif menu == "📊 Informasi Model":
    st.header("📊 Informasi Model")

    st.markdown("<br>", unsafe_allow_html=True)
    st.subheader("🤖 Informasi 3 Model Machine Learning")
    
    info_tabs = st.tabs(["XGBoost v5", "Random Forest V1", "Random Forest V2"])
    
    with info_tabs[0]:
        st.markdown("""
        **Pipeline & Konfigurasi**
        - **Algoritma**: XGBoost Classifier
        - **Hyperparameters**: 400 estimators, max_depth=8, learning_rate=0.05
        - **Dataset**: CICIDS2017 + 0.2% CICIDS2018 (Training)
        - **Performa**: Accuracy 99.56% | DoS Recall 99.0% | F1-Score 99.58%
        - **Fitur Khusus**: Per-class threshold tuning untuk meningkatkan deteksi kelas minoritas.
        """)
        
    with info_tabs[1]:
        st.markdown("""
        **Pipeline & Konfigurasi**
        - **Algoritma**: Random Forest Classifier (Before Tuning)
        - **Dataset**: Kondisi awal tanpa seleksi fitur atau optimasi yang ketat.
        - **Performa**: Base performance.
        - **Catatan**: Model ini disimpan sebagai baseline perbandingan dengan model yang telah dioptimasi.
        """)
        
    with info_tabs[2]:
        st.markdown("""
        **Pipeline & Konfigurasi**
        - **Algoritma**: Random Forest Classifier (After Tuning)
        - **Hyperparameters**: 300 trees, max_depth=25
        - **Dataset**: CICIDS2017 + 0.2% CICIDS2018 (Training)
        - **Performa**: Accuracy 95.01% | DoS Recall 76.5% | F1-Score 94.92%
        - **Fitur Khusus**: Feature Selection dengan Korelasi >0.92 + RF Importance 95% cumsum.
        """)

    st.divider()
    
    st.subheader("📈 Informasi Evaluasi K-Fold (Random Forest)")
    st.markdown("Hasil evaluasi *Cross Validation K-Fold* yang dijalankan pada Google Colab untuk memastikan konsistensi model Random Forest:")
    
    kfold_data = {
        'Fold (K)': ['K = 5', 'K = 7', 'K = 10'],
        'Mean Accuracy': ['~94.8%', '~95.0%', '~95.1%'],
        'Mean Precision': ['~94.5%', '~94.8%', '~94.9%'],
        'Mean Recall': ['~94.8%', '~95.0%', '~95.1%'],
        'Status': ['Stabil', 'Sangat Stabil', 'Sangat Stabil (Optimal)']
    }
    st.dataframe(pd.DataFrame(kfold_data), use_container_width=True, hide_index=True)
    st.info("💡 **Kesimpulan K-Fold**: Model menunjukkan variansi yang sangat kecil di antara lipatan (folds), menandakan bahwa model tidak overfitting dan dapat menggeneralisasi dengan baik pada data baru.")

# ═══════════════════════════════════════════════
# MENU 3 – ABOUT US
# ═══════════════════════════════════════════════
elif menu == "👨‍💻 About Us":
    st.header("👨‍💻 Identitas Tim")
    st.markdown("Kenali tim pengembang hebat di balik pembuatan aplikasi NIDS Dashboard ini.")
    
    st.markdown("<br>", unsafe_allow_html=True)
    
    # Custom CSS tambahan khusus buat efek kartu profil modern & foto bulat
    st.markdown("""
    <style>
        .profile-card {
            background: linear-gradient(135deg, rgba(255, 255, 255, 0.07) 0%, rgba(255, 255, 255, 0.03) 100%);
            backdrop-filter: blur(15px);
            -webkit-backdrop-filter: blur(15px);
            border-radius: 20px;
            padding: 30px 20px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.15);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
            transition: transform 0.3s ease, border-color 0.3s ease;
            height: 100%;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            align-items: center;
        }
        .profile-card:hover {
            transform: translateY(-5px);
            border-color: #3B82F6;
        }
        .avatar {
            width: 90px;
            height: 90px;
            border-radius: 50%;
            object-fit: cover;
            margin-bottom: 15px;
            border: 3px solid #3B82F6;
            box-shadow: 0 4px 10px rgba(0,0,0,0.3);
        }
        .profile-name {
            font-size: 20px;
            font-weight: 700;
            color: #FFFFFF;
            margin-bottom: 6px;
            min-height: 56px; 
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .profile-id {
            font-size: 14px;
            color: #9CA3AF;
            letter-spacing: 0.05em;
            margin-bottom: 25px;
        }
        .linkedin-btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            background: #0077B5;
            color: #FFFFFF !important;
            text-decoration: none !important;
            padding: 10px 20px;
            border-radius: 50px;
            font-size: 13px;
            font-weight: 600;
            width: 85%;
            transition: background 0.2s ease, transform 0.1s ease;
            box-shadow: 0 4px 12px rgba(0, 119, 181, 0.3);
        }
        .linkedin-btn:hover {
            background: #005987;
            transform: scale(1.02);
        }
    </style>
    """, unsafe_allow_html=True)
    
    # Bikin 3 Kolom Responsif
    c1, c2, c3 = st.columns(3)
    
    with c1:
        st.markdown("""
        <div class="profile-card">
            <div>
                <img src="https://raw.githubusercontent.com/yusufnurhuda12/MachineLearningIDS/main/profile/meisaroh.jpg" class="avatar" alt="Meisyaroh">
                <div class="profile-name">Meisyaroh Azzahra</div>
                <div class="profile-id">NIM. 101112480109</div>
                <div class="profile-id">Cyber Security Engineer | ICT Security Operations | Network Defense & Endpoint Compliance at Lintasarta</div>
            </div>
            <a class="linkedin-btn" href="https://www.linkedin.com/in/meisyaroh-azzahra-0100b5206/" target="_blank">
                🔗 Connect LinkedIn
            </a>
        </div>
        """, unsafe_allow_html=True)
        
    with c2:
        st.markdown("""
        <div class="profile-card">
            <div>
                <img src="https://raw.githubusercontent.com/yusufnurhuda12/MachineLearningIDS/main/profile/mualim.jpg" class="avatar" alt="Mu'alim">
                <div class="profile-name">Mu’alim Rohmadi</div>
                <div class="profile-id">NIM. 101112480098</div>
                <div class="profile-id">Project Engineer FTTH | Survey&Design | Cyber Security Entusiasm at MyRepublic</div>
            </div>
            <a class="linkedin-btn" href="https://www.linkedin.com/in/mualimr/" target="_blank">
                🔗 Connect LinkedIn
            </a>
        </div>
        """, unsafe_allow_html=True)
        
    with c3:
        st.markdown("""
        <div class="profile-card">
            <div>
                <img src="https://raw.githubusercontent.com/yusufnurhuda12/MachineLearningIDS/main/profile/yusuf.jpg" class="avatar" alt="Yusuf">
                <div class="profile-name">Muhammad Yusuf Nurhuda</div>
                <div class="profile-id">NIM. 101112480096</div>
                <div class="profile-id">Telecommunications & Digital Infrastructure Engineer | FTTH | 5G FWA | Awarded “Best SND Staff 2024” and “Top 10th SND Staff 2025” at MyRepublic (Sinarmas Group)</div>
            </div>
            <a class="linkedin-btn" href="https://www.linkedin.com/in/yusufnurhuda/" target="_blank">
                🔗 Connect LinkedIn
            </a>
        </div>
        """, unsafe_allow_html=True)
