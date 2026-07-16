# NIDS Analytics Dashboard 🛡️

A comprehensive Network Intrusion Detection System (NIDS) Dashboard built with Streamlit and Machine Learning. This application provides real-time and file-based network traffic analysis to detect malicious activities like Denial of Service (DoS) attacks and Port Scanning, enhanced with AI-driven tactical insights.

## ✨ Features

- **Advanced ML Detection**: Utilizes optimized XGBoost and Random Forest models for high-accuracy threat detection based on network traffic flow.
- **AI Security Insights**: Integrates with Google Gemini API to generate automated SOC (Security Operations Center) tactical analysis and mitigation recommendations.
- **Interactive Dashboard**: Beautiful UI with Dark/Light mode support, interactive metric cards, and responsive layouts.
- **Authentication System**: Built-in secure login system with Role-Based Access Control (RBAC) supporting `user`, `admin`, and `godmode` roles.
- **Data Harmonization**: Automatically normalizes datasets and handles legacy formats (e.g., CICFlowMeter format conversions).
- **PDF Reporting**: Generates downloadable executive security reports in PDF format summarizing the scan results and AI insights.
- **Cloud Database Sync (Firebase)**: Seamlessly synchronize user accounts, settings, and analysis history online using Firebase Realtime Database with automatic fallback to local JSON storage.
- **Real-time Simulation**: Features a "Streaming" mode to simulate real-time SOC monitoring with progress and accumulated attack metrics.

## 🛠️ Technology Stack

- **Frontend/Backend Web Framework**: [Streamlit](https://streamlit.io/)
- **Data Processing**: Pandas, NumPy
- **Machine Learning**: Scikit-Learn, XGBoost, Joblib
- **Generative AI**: Google Generative AI (Gemini)
- **Visualizations**: Plotly Express
- **PDF Generation**: FPDF
- **Cloud Storage**: Firebase Realtime Database (via REST API) / Local JSON Fallback

## 🚀 Installation & Setup

1. **Clone the repository** (if applicable) or place the files in your project folder.
2. **Install the required dependencies**:
   ```bash
   pip install streamlit pandas numpy joblib plotly google-generativeai scikit-learn fpdf requests streamlit-cookies-manager
   ```

3. **Prepare the Models**:
   Ensure the following model files are present in the root directory or a `models/` subdirectory:
   - `xgboost_model_v2.pkl`, `scaler_v2.pkl`, `feature_columns_v2.txt`, `label_encoder_v2.pkl`, `per_class_thresholds.json`
   - `random_forest_model_v1.pkl`, `scaler_v1.pkl` (Optional)
   - `random_forest_model_v2.pkl`, `scaler_v2.pkl` (Optional)

4. **Run the Dashboard**:
   ```bash
   streamlit run app.py
   ```

## ⚙️ Configuration (Firebase & Gemini AI)

The dashboard is designed to be highly flexible, offering both local storage and cloud synchronization.

### 1. Firebase Realtime Database (Cloud Sync)
By default, the app saves `users`, `history`, and `config` to local JSON files. To enable online synchronization across multiple sessions or deployments, you can connect it to Firebase Realtime Database.

1. Go to the [Firebase Console](https://console.firebase.google.com/) and create a project.
2. Create a **Realtime Database** and copy its Database URL (e.g., `https://your-project-default-rtdb.firebaseio.com/`).
3. In your project directory, create a `.streamlit/secrets.toml` file (if deploying to Streamlit Cloud, add this to the Secrets manager).
4. Add the following line:
   ```toml
   FIREBASE_URL = "https://your-project-default-rtdb.firebaseio.com/"
   ```
*Once configured, the app will automatically prioritize saving and fetching `users.json`, `config.json`, and `analysis_history.json` directly to/from your Firebase Realtime Database.*

### 2. Google Gemini API (AI Insights)
To activate the AI Security Analyst for automated reporting, provide a Gemini API Key.
- You can store it in `.streamlit/secrets.toml` as `GEMINI_API_KEY = "your_api_key_here"` or as a system environment variable.
- You can also configure this dynamically within the app settings by updating the `config.json` configuration file.

## 🔐 Default Authentication & Users

If no `users.json` or Firebase users exist yet, you can register a new account directly on the login page.
- **Godmode Account**: Register with the username `godmode` to get top-level privileges and UI accents.
- **Admin Account**: Register with the username `admin` for administrative access.

Session management is securely handled using `streamlit-cookies-manager`.

## 📂 File Structure

- `app.py`: Main Streamlit application script containing the UI and logic.
- `.streamlit/secrets.toml`: Local secrets file containing API keys and Firebase connection strings.
- `users.json` / `config.json` / `analysis_history.json`: Local fallback storage files.
- `models/`: Suggested directory to store your pre-trained ML models and scalers.

## 🛡️ Important Note

This system is designed as a tactical dashboard for Security Operations Centers (SOC) to assist network administrators in identifying anomalous traffic behavior and determining the best course of action using AI. Always pair this tool with dedicated firewall policies and other defense-in-depth strategies.
