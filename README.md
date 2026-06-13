# 🛡️ NIDS Analytics Dashboard

A modern **Network Intrusion Detection System (NIDS)** powered by **Machine Learning**, designed to detect malicious network activities such as **DoS**, **DDoS**, **Port Scanning**, **Brute Force**, and **Web Attacks** through an interactive SOC-style dashboard.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-red)
![XGBoost](https://img.shields.io/badge/XGBoost-Champion_Model-green)
![RandomForest](https://img.shields.io/badge/RandomForest-Ensemble-orange)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## 📌 Overview

NIDS Analytics Dashboard is a cybersecurity monitoring platform that combines:

* Machine Learning-based intrusion detection
* Interactive Security Operations Center (SOC) dashboard
* AI-generated security recommendations
* Automated PDF reporting
* User authentication and role management

The system is trained using the **CICIDS2017** dataset and enhanced with selected samples from **CICIDS2018** to improve attack detection capability.

---

## ✨ Features

### 🔍 Intrusion Detection

Detects multiple attack categories:

* DoS (Denial of Service)
* DDoS
* Port Scanning
* Brute Force
* Web Attack
* Normal Traffic (BENIGN)

---

### 🚀 Machine Learning Models

#### Champion Model

* XGBoost Classifier
* 400 Estimators
* Max Depth = 8
* Learning Rate = 0.05
* Per-Class Threshold Tuning

#### Supporting Models

* Random Forest V1 (Baseline)
* Random Forest V2 (Tuned)

---

### 📊 Interactive Dashboard

Provides:

* Threat distribution charts
* Attack trend visualization
* Real-time monitoring simulation
* Confusion matrix
* Performance metrics
* Historical analysis records

---

### 🤖 AI Security Insight

Integrated with Google Gemini AI:

* Executive security summary
* Threat assessment
* Mitigation recommendations
* SOC-style incident explanation

---

### 📄 Automated Reporting

Export:

* CSV Analysis Report
* Executive PDF Security Report

Generated reports include:

* Threat statistics
* Attack ratio
* AI-generated recommendations
* Model evaluation metrics

---

### 👥 User Authentication

Supports:

* Login
* Registration
* Role-based access

Roles:

| Role    | Access                    |
| ------- | ------------------------- |
| User    | Analysis Dashboard        |
| Admin   | Dashboard + Configuration |
| Godmode | Full System Control       |

---

## 🏗️ System Architecture

```text
Network Traffic CSV
          │
          ▼
Data Cleaning & Normalization
          │
          ▼
Feature Engineering
          │
          ▼
Machine Learning Models
 ├── XGBoost
 ├── Random Forest V1
 └── Random Forest V2
          │
          ▼
Prediction Engine
          │
          ▼
SOC Dashboard
          │
          ├── Visualization
          ├── AI Insight
          ├── PDF Report
          └── Historical Analysis
```

---

## 📂 Project Structure

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
│
├── reports/
│
├── requirements.txt
│
└── README.md
```

---

## ⚙️ Installation

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/nids-dashboard.git
cd nids-dashboard
```

### 2. Create Virtual Environment

```bash
python -m venv venv
```

Linux/Mac:

```bash
source venv/bin/activate
```

Windows:

```bash
venv\Scripts\activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## 📦 Required Packages

```bash
streamlit
pandas
numpy
joblib
plotly
scikit-learn
xgboost
google-generativeai
fpdf2
requests
```

---

## 🔑 Gemini AI Configuration

Create:

```json
config.json
```

Example:

```json
{
  "GEMINI_API_KEY": "YOUR_API_KEY",
  "GEMINI_MODEL_NAME": "gemini-3.5-flash"
}
```

Or configure via:

```bash
export GEMINI_API_KEY=YOUR_API_KEY
```

---

## 🚀 Running The Application

```bash
streamlit run app.py
```

Default URL:

```text
http://localhost:8501
```

---

## 📈 Model Performance

### XGBoost (Champion)

| Metric    | Score  |
| --------- | ------ |
| Accuracy  | 99.56% |
| Precision | 99.56% |
| Recall    | 99.00% |
| F1-Score  | 99.58% |

### Random Forest V2

| Metric       | Score  |
| ------------ | ------ |
| Accuracy     | 95.01% |
| Recall (DoS) | 76.5%  |
| F1 Score     | 94.92% |

---

## 📊 Dataset

Primary Dataset:

* CICIDS2017

Additional Dataset:

* CICIDS2018 (Selected Samples)

Source:

https://www.unb.ca/cic/datasets/

---

## 🔒 Security Notes

This project is intended for:

* Educational research
* Academic projects
* Security monitoring simulation
* Intrusion detection experimentation

Not recommended as a standalone production SOC platform without:

* SIEM integration
* Centralized logging
* Continuous model retraining
* Infrastructure hardening

---
