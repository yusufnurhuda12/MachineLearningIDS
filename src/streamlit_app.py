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
# PATH HELPER — cari file di beberapa lokasi
# ─────────────────────────────────────────────
def find_file(filename):
    """Cari file di CWD, direktori script, parent dir, dan /code (HF Spaces)."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        filename,                                        # CWD
        os.path.join(script_dir, filename),              # sama dengan script
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
# LOAD MODEL (XGBoost v5 utama, RF v2 fallback)
# ─────────────────────────────────────────────
@st.cache_resource
def load_model_and_scaler():
    # ── XGBoost v5 (dari NIDS_v5_MIXING) ──
    if fexists('xgboost_model_v2.pkl', 'scaler_v2.pkl'):
        model  = joblib.load(find_file('xgboost_model_v2.pkl'))
        scaler = joblib.load(find_file('scaler_v2.pkl'))
        le     = joblib.load(find_file('label_encoder_v2.pkl')) if find_file('label_encoder_v2.pkl') else None
        features = None
        if find_file('feature_columns_v2.txt'):
            with open(find_file('feature_columns_v2.txt')) as f:
                features = [ln.strip() for ln in f if ln.strip()]
        thresholds = None
        if find_file('per_class_thresholds.json'):
            with open(find_file('per_class_thresholds.json')) as f:
                thresholds = json.load(f)
        return model, scaler, features, "XGBoost v5 (Accuracy 99.56% | DoS Recall 99%)", le, thresholds, 'xgboost'
    # ── RF v2 fallback ──
    elif fexists('random_forest_model_v2.pkl', 'scaler_v2.pkl'):
        model  = joblib.load(find_file('random_forest_model_v2.pkl'))
        scaler = joblib.load(find_file('scaler_v2.pkl'))
        features = None
        if find_file('feature_columns_v2.txt'):
            with open(find_file('feature_columns_v2.txt')) as f:
                features = [ln.strip() for ln in f if ln.strip()]
        return model, scaler, features, "Random Forest v2 (Accuracy 95%)", None, None, 'rf'
    else:
        return None, None, None, None, None, None, None



model, scaler, feature_cols, model_name, label_enc, per_class_thresh, model_type = load_model_and_scaler()

def predict(X_scaled):
    """Prediksi dengan model aktif, kembalikan array label string."""
    if model_type == 'xgboost' and label_enc is not None:
        if per_class_thresh:
            classes = label_enc.classes_
            proba   = model.predict_proba(X_scaled)
            thresh  = np.array([per_class_thresh.get(c, 0.5) for c in classes])
            norm    = proba / thresh
            idx     = np.argmax(norm, axis=1)
            return np.array([classes[i] for i in idx])
        else:
            return label_enc.inverse_transform(model.predict(X_scaled))
    return model.predict(X_scaled)

# ─────────────────────────────────────────────
# HEADER
# ─────────────────────────────────────────────
st.markdown('<div class="main-title">🛡️ Network Intrusion Detection System</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">Deteksi Serangan Jaringan Menggunakan Machine Learning – XGBoost + Random Forest</div>', unsafe_allow_html=True)

if model is None:
    st.error("⚠️ Model belum ditemukan! Jalankan notebook `NIDS_v5_MIXING.ipynb` terlebih dahulu.")
    st.stop()

# ─────────────────────────────────────────────
# SIDEBAR
# ─────────────────────────────────────────────
st.sidebar.title("🛡️ NIDS Dashboard")
menu = st.sidebar.radio("Pilih Menu:", ["📂 Prediksi File Baru", "📊 Informasi Model"])
st.sidebar.success(f"Model aktif: {model_name}")
st.sidebar.info(f"Jumlah fitur: {len(feature_cols) if feature_cols else '?'}")


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

            # Cek fitur
            missing = [f for f in feature_cols if f not in df.columns]
            if missing:
                st.warning(f"⚠️ {len(missing)} kolom tidak ditemukan, akan diisi 0: {missing[:5]}{'...' if len(missing)>5 else ''}")
                for m in missing:
                    df[m] = 0

            X = df[feature_cols]

            try:
                X_scaled = scaler.transform(X)
                y_pred   = predict(X_scaled)
                df['Hasil_Prediksi'] = y_pred

                st.success("🎉 Prediksi Selesai!")

                # ── Distribusi + Tabel ──
                col1, col2 = st.columns(2)

                with col1:
                    st.subheader("Distribusi Prediksi")
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
                    st.plotly_chart(fig_pie, use_container_width=True)

                with col2:
                    st.subheader("Tabel Hasil Prediksi (10 baris pertama)")
                    st.dataframe(df[['Hasil_Prediksi']].head(10))
                    st.download_button(
                        label="⬇️ Download Hasil Prediksi (CSV)",
                        data=df[['Hasil_Prediksi']].to_csv(index=False).encode('utf-8'),
                        file_name="hasil_prediksi.csv",
                        mime="text/csv"
                    )

                # ── Evaluasi (jika ada label) ──
                if has_label:
                    st.divider()
                    st.subheader("📊 Evaluasi vs Label Asli")

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
                    st.subheader("🔢 Confusion Matrix")
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
                    st.plotly_chart(fig_cm, use_container_width=True)

            except Exception as e:
                st.error(f"Terjadi kesalahan saat memproses data: {e}")
                st.info("Pastikan file CSV memiliki fitur yang sama dengan dataset latihan.")


# ═══════════════════════════════════════════════
# MENU 2 – INFORMASI MODEL
# ═══════════════════════════════════════════════
elif menu == "📊 Informasi Model":
    st.header("📊 Informasi Model")

    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value blue" style="font-size:20px;">🤖 {model_name}</div>
            <div class="metric-label">Model Aktif</div>
        </div>""", unsafe_allow_html=True)
    with col_b:
        st.markdown(f"""
        <div class="metric-card">
            <div class="metric-value" style="font-size:26px;">{len(feature_cols) if feature_cols else '?'}</div>
            <div class="metric-label">Jumlah Fitur</div>
        </div>""", unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    st.subheader("📖 Tentang Pipeline")
    st.markdown("""
    Pipeline ini menggunakan **XGBoost** sebagai model utama dan **Random Forest** sebagai backup
    untuk mendeteksi serangan jaringan secara otomatis.

    | Properti | Detail |
    |----------|--------|
    | **Model Utama** | XGBoost (400 estimators, max_depth=8, lr=0.05) |
    | **Model Backup** | Random Forest (300 trees, max_depth=25) |
    | **Dataset Training** | CICIDS2017 + 0.2% CICIDS2018 |
    | **Dataset Testing** | 99.8% CICIDS2018 (pure unseen) |
    | **Akurasi Test** | 99.56% (XGBoost) \| 95.01% (RF) |
    | **DoS Recall** | 99% (XGBoost) \| 76.5% (RF) |
    | **Balancing** | Per-class max 80k samples |
    | **Feature Selection** | Korelasi >0.92 + RF Importance 95% cumsum |
    | **Normalisasi** | StandardScaler |
    | **Threshold** | Per-class threshold tuning |
    """)

    # Performa metrics
    st.subheader("📈 Performa Model pada CICIDS2018")
    perf_data = {
        'Model'    : ['XGBoost (Utama)', 'Random Forest (Backup)'],
        'Accuracy' : ['99.56%', '95.01%'],
        'Precision': ['99.60%', '94.88%'],
        'Recall'   : ['99.56%', '95.01%'],
        'F1-Score' : ['99.58%', '94.92%'],
        'DoS Recall': ['99.0%', '76.5%'],
    }
    st.dataframe(pd.DataFrame(perf_data), use_container_width=True, hide_index=True)

    if feature_cols:
        st.subheader("🔍 Daftar Fitur yang Digunakan")
        feat_df = pd.DataFrame({'No': range(1, len(feature_cols)+1), 'Nama Fitur': feature_cols})
        st.dataframe(feat_df, use_container_width=True, hide_index=True)
