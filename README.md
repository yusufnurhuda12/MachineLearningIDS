# NIDS Analytics Dashboard 🛡️

A comprehensive Network Intrusion Detection System (NIDS) Dashboard built with Streamlit and Machine Learning. This application provides real-time and file-based network traffic analysis to detect malicious activities like Denial of Service (DoS) attacks and Port Scanning, enhanced with AI-driven tactical insights.

## ✨ Features

- **Advanced ML Detection**: Utilizes optimized XGBoost and Random Forest models for high-accuracy threat detection based on network traffic flow.
- **AI Security Insights**: Integrates with Google Gemini API to generate automated SOC (Security Operations Center) tactical analysis and mitigation recommendations.
- **Interactive Dashboard**: Beautiful UI with Dark/Light mode support, interactive metric cards, and responsive layouts.
- **Authentication System**: Built-in secure login system with Role-Based Access Control (RBAC) supporting `user`, `admin`, and `godmode` roles.
- **Data Harmonization**: Automatically normalizes datasets and handles legacy formats (e.g., CICFlowMeter format conversions).
- **PDF Reporting**: Generates downloadable executive security reports in PDF format summarizing the scan results and AI insights.
- **Real-time Simulation**: Features a "Streaming" mode to simulate real-time SOC monitoring with progress and accumulated attack metrics.

## 🛠️ Technology Stack

- **Frontend/Backend Web Framework**: [Streamlit](https://streamlit.io/)
- **Data Processing**: Pandas, NumPy
- **Machine Learning**: Scikit-Learn, XGBoost, Joblib
- **Generative AI**: Google Generative AI (Gemini)
- **Visualizations**: Plotly Express
- **PDF Generation**: FPDF
- **Storage**: Local JSON files (can be extended to Firebase Realtime Database)

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

4. **Configure API Keys**:
   You can set your Gemini API key in a `config.json` file, Streamlit secrets, or as an environment variable `GEMINI_API_KEY`.
   *(Optional)* If you plan to use Firebase, configure the `FIREBASE_URL` in `.streamlit/secrets.toml`.

5. **Run the Dashboard**:
   ```bash
   streamlit run app.py
   ```

## 🔐 Default Authentication & Users

If no `users.json` is found, you can register a new account directly on the login page.
- **Godmode Account**: Register with the username `godmode` to get top-level privileges and UI accents.
- **Admin Account**: Register with the username `admin` for administrative access.

Session management is securely handled using `streamlit-cookies-manager`.

## 📂 File Structure

- `app.py`: Main Streamlit application script containing the UI and logic.
- `users.json`: Local storage for user credentials and roles.
- `config.json`: Configuration settings (including Gemini API model and key).
- `analysis_history.json`: History log of processed network traffic analyses.
- `models/`: Suggested directory to store your pre-trained ML models and scalers.

## 🛡️ Important Note

This system is designed as a tactical dashboard for Security Operations Centers (SOC) to assist network administrators in identifying anomalous traffic behavior and determining the best course of action using AI. Always pair this tool with dedicated firewall policies and other defense-in-depth strategies.
