#🛡️ Phishing URL Detector (ML + Hybrid Rules)
A machine learning-based web application designed to detect phishing URLs in real-time. This project uses a Random Forest classifier trained on thousands of malicious and legitimate URLs, combined with rule-based heuristics to minimize false positives.

🎯 The Problem
Phishing is the #1 initial attack vector for data breaches, especially in the banking and financial sectors. Traditional blacklists cannot catch zero-day phishing sites. This project demonstrates how machine learning can analyze the lexical and structural patterns of a URL to predict if it is malicious before the user clicks it.

✨ Features
Machine Learning Core: Uses a Random Forest algorithm trained on 87 distinct features (e.g., URL length, presence of IP, suspicious TLDs, domain age proxies).

Live Feature Extraction: Extracts 87 data points on-the-fly from any pasted URL.

Hybrid Detection Engine: Combines the ML model with a rule-based Whitelist to prevent False Positives (blocking legitimate domains like .edu or .gov).

Interactive Web UI: A clean, dark-mode web interface built with FastAPI and JavaScript for instant scanning.

🏗️ Architecture & Tech Stack
Machine Learning: scikit-learn, pandas, numpy

Backend API: FastAPI, uvicorn

Feature Extraction: tldextract, urllib

Frontend: HTML5, CSS3, Vanilla JavaScript

🚀 How to Run Locally
1. Clone the repository
bash
git clone https://github.com/yourusername/phishing-url-detector.git
cd phishing-url-detector
2. Create a virtual environment and install dependencies
bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
3. Train the Model (Optional)
If you don't have the phishing_model.pkl file, train it using the dataset:

bash
python train_model.py
4. Start the Web App
bash
uvicorn app:app --reload
Open http://127.0.0.1:8000 in your browser to use the detector!

📊 Dataset
The model was trained using the Phishing Dataset (11,000+ URLs) which includes 87 extracted features based on URL structure, domain properties, and HTML/JavaScript behavior.

🔮 Future Improvements
Integrate WHOIS API to check real-time domain registration age (domains < 30 days old are highly suspicious).

Add Google Safe Browsing API or VirusTotal API for third-party threat intelligence.

Implement Homoglyph detection (e.g., detecting аpple.com using a Cyrillic 'а').

Developed as a cybersecurity portfolio project.

