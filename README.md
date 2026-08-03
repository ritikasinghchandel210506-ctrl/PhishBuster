# 🛡️ PhishBuster — AI-Powered Phishing Email Detector & Classifier

**PhishBuster** is an end-to-end intelligent cybersecurity web application designed to detect, classify, and analyze email phishing attempts in real time. Powered by Machine Learning, Natural Language Processing (NLP), and an intuitive React interface, PhishBuster provides comprehensive threat intelligence, highlights suspicious email content, and guides users through interactive post-incident remediation workflows.

---

## 🌟 Key Features

* **🤖 AI/ML Phishing Detection:** Accurately classifies emails as **Genuine** or **Phishing** using trained Machine Learning models (TF-IDF + Scikit-Learn classifiers / Transformers).
* **📊 Risk Scoring & Danger Levels:** Provides a precise risk percentage ($0–100\%$) alongside dynamic danger categories (*Low*, *Medium*, *High*, *Critical*).
* **🏷️ Scam Type Classification:** Categorizes detected phishing threats into specific scam types (e.g., *Credential Harvesting*, *CEO Fraud / BEC*, *Financial / Tax Scam*, *Tech Support Fraud*, *Lottery / Prize Scam*).
* **📝 Automatic Content Summarization:** Generates quick, executive-level summaries of long or confusing emails so users don't have to read risky messages in full.
* **🔎 Fishy Text & Link Highlighter:** Scans the email body using NLP heuristics and regex patterns to visually highlight suspicious URLs, fake urgency triggers, sensitive request keywords, and domain mismatches.
* **🗺️ Interactive Remediation & Action Guide:**
  * Asks the user structured questions (*"Did you open this email?"*, *"Did you click any links?"*, *"Did you download attachments or enter passwords?"*).
  * Provides real-time, step-by-step incident response advice based on user inputs (e.g., password resets, device isolation, reporting instructions).

---

## 📂 Project Architecture & Directory Structure

```text
phishbuster/
├── backend/
│   ├── app.py                   # Main Flask Application & API Routes
│   ├── config.py                # App Configurations (Paths, CORS, Secret Keys)
│   ├── requirements.txt         # Python Dependencies
│   ├── models/
│   │   ├── classifier.pkl       # Serialized ML Model (Exported from Notebook)
│   │   ├── vectorizer.pkl       # Serialized TF-IDF / Tokenizer
│   │   └── train_model.py       # Standalone Script to Retrain Model
│   ├── services/
│   │   ├── nlp_service.py       # Text Summarization & Suspicious Token Extraction
│   │   └── prediction_service.py # Model Inference, Risk Calculation & Classification
│   └── utils/
│       └── scam_types.py        # Mapping Rules & Taxonomy for Scam Types
│
├── frontend/
│   ├── package.json             # Node.js Dependencies & Scripts
│   ├── public/
│   │   └── index.html           # Main HTML Template
│   └── src/
│       ├── App.jsx              # Core React Component & Application State
│       ├── index.jsx            # React Entry Point
│       ├── api.js               # API Client Service (Fetch / Axios)
│       ├── components/
│       │   ├── Header.jsx       # Header & Navigation Bar
│       │   ├── EmailInput.jsx   # Input Form for Email Body / Headers
│       │   ├── ResultSummary.jsx# Threat Badges, Risk Gauge & Summary
│       │   ├── FishyHighlighter.jsx # Interactive Text Display with Highlighting
│       │   └── ActionGuide.jsx  # Decision Tree Questionnaire & Steps
│       └── styles/
│           └── App.css          # Styling & Utility Rules
└── README.md                    # Project Documentation
```
---

## 🛠️ Tech Stack

### **Frontend**
  
* Framework: React.js (Vite / CRA)

* Styling: CSS3 / Tailwind CSS

* Icons: Lucide-React / React-Icons

* HTTP Client: Axios / Native Fetch API

### **Backend**
  
* Web Framework: Python Flask

* ML / NLP Libraries: Scikit-Learn, NLTK / Spacy, Joblib, NumPy, Pandas

* API Standards: RESTful JSON APIs
