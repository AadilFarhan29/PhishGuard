# PhishGuard

PhishGuard is a hybrid phishing detection system built with **Flask**, **machine learning**, and **browser-extension support**.  
It analyzes suspicious URLs using multiple layers of checks instead of relying on a single model.

The project is designed to classify links as:

- **Likely Safe**
- **Suspicious**
- **Potential Phishing**

---

## Features

PhishGuard combines multiple detection layers:

- **Machine Learning URL Classification**
- **URL Feature Extraction**
- **NLP-Based Keyword Analysis**
- **Domain Validation**
- **Redirect Analysis**
- **Live Webpage Inspection**
- **Google Safe Browsing Check**
- **Hybrid Risk Scoring Engine**
- **Browser Extension Support for Chrome / Edge**

---

## How It Works

When a URL is submitted, PhishGuard processes it through several stages:

1. **Google Safe Browsing**
   - Checks whether the URL is already known as a malicious or unsafe link.

2. **Feature Extraction**
   - Extracts structural URL features such as:
   - length
   - subdomains
   - suspicious symbols
   - shortening service usage
   - redirection indicators

3. **NLP Analysis**
   - Detects phishing-related keywords such as:
   - login
   - verify
   - password
   - billing
   - update
   - secure

4. **Redirect Analysis**
   - Tracks where the submitted URL actually leads.

5. **Domain Validation**
   - Checks whether the domain appears deceptive, suspicious, or mismatched.

6. **Live Page Inspection**
   - Looks at page-level signals such as forms, password fields, and suspicious behavior.

7. **Hybrid Risk Evaluation**
   - Combines all signals into a final verdict and score.

---

## Project Structure

```bash
PhishGuard/
│
├── app.py
├── requirements.txt
├── README.md
│
├── model/
│   ├── phishguard_live_model.pkl
│   └── live_feature_columns.pkl
│
├── utils/
│   ├── features.py
│   ├── nlp_analyzer.py
│   ├── domain_validator.py
│   ├── redirect_analyzer.py
│   ├── page_analyzer.py
│   ├── risk_engine.py
│   └── safe_browsing.py
│
├── templates/
│   └── index.html
│
├── static/
│   └── style.css
│
└── extension/
    ├── manifest.json
    ├── service-worker.js
    ├── popup.html
    ├── popup.js
    └── popup.css
Tech Stack
Python
Flask
Pandas
Joblib
Scikit-learn
Flask-CORS
HTML / CSS / JavaScript
Chrome / Edge Extension (Manifest V3)
Web Application

The web version allows a user to paste a suspicious URL and receive:

verdict
risk level
score
summary
supporting reasons
Browser Extension

PhishGuard also supports a browser extension for Chrome / Edge.

Current functionality
Right-click any hyperlink
Select Scan with PhishGuard
Receive a phishing verdict
View result in a popup interface

This allows PhishGuard to work across websites such as:

WhatsApp Web
Reddit
Gmail
forums
other browser pages containing links
Installation
1. Clone the repository
git clone https://github.com/AadilFarhan29/PhishGuard.git
cd PhishGuard
2. Install dependencies
pip install -r requirements.txt
3. Run the Flask app
python app.py

The app should start locally on:

http://127.0.0.1:10000
API Usage

PhishGuard exposes an API endpoint for URL scanning:

Endpoint
POST /api/scan
Example request body
{
  "url": "https://github.com"
}
Example response
{
  "success": true,
  "result": {
    "result": "Likely Safe",
    "risk_level": "Low",
    "final_score": 14.61
  }
}
Extension Setup
Open your browser extensions page:
chrome://extensions
or edge://extensions
Enable Developer mode
Click Load unpacked
Select the extension/ folder
Right-click a link and choose Scan with PhishGuard
Deployment

PhishGuard can be deployed as a Flask web service on platforms such as Render.

The browser extension can be configured to call either:

a local Flask server
or the hosted Render deployment
Use Case

PhishGuard is designed to help users quickly inspect suspicious URLs before opening them.

It is especially useful for links received through:

social media
forums
email
messaging platforms
unknown websites
Current Status

PhishGuard is currently a working hybrid phishing detection project with:

live web interface
hosted API support
browser extension integration
multi-layer detection logic
Future Improvements

Planned improvements include:

stronger explanation prioritization
improved popup visual insights
faster extension response handling
link history / caching
broader browser support
stronger model retraining pipeline
more advanced phishing heuristics
Disclaimer

PhishGuard is a research and educational cybersecurity project.
It is intended to assist with phishing detection, but should not be treated as a guaranteed replacement for enterprise-grade secure browsing protections.

Author

Aadil Farhan
Cybersecurity / Automation / AI Systems
GitHub: AadilFarhan29