import os
import joblib
import pandas as pd
from flask import Flask, render_template, request, jsonify
from flask_cors import CORS
from utils.features import extract_url_features
from utils.nlp_analyzer import analyze_url_nlp
from utils.page_analyzer import analyze_webpage
from utils.domain_validator import validate_domain
from utils.redirect_analyzer import analyze_redirects
from utils.risk_engine import evaluate_risk
from utils.safe_browsing import check_url_safe_browsing

app = Flask(__name__)

MODEL_PATH = "model/phishguard_live_model.pkl"
FEATURE_COLUMNS_PATH = "model/live_feature_columns.pkl"
CORS(app, resources={r"/api/*": {"origins": "*"}})

model = None
feature_columns = None

if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)

if os.path.exists(FEATURE_COLUMNS_PATH):
    feature_columns = joblib.load(FEATURE_COLUMNS_PATH)


def normalize_url(url):
    url = (url or "").strip()
    if url and not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def generate_explanations(features):
    reasons = []

    if features.get("length_url", 0) > 75:
        reasons.append("The URL is unusually long.")

    if features.get("length_hostname", 0) > 30:
        reasons.append("The domain name is unusually long.")

    if features.get("ip", 0) == 1:
        reasons.append("The link uses an IP address instead of a normal domain name.")

    if features.get("nb_subdomains", 0) > 2:
        reasons.append("The URL contains many subdomains, which can be used to mimic trusted sites.")

    if features.get("prefix_suffix", 0) == 1:
        reasons.append("The domain contains a hyphen, which is sometimes used in deceptive domains.")

    if features.get("shortening_service", 0) == 1:
        reasons.append("The URL uses a shortening service, which can hide the real destination.")

    if features.get("nb_at", 0) > 0:
        reasons.append("The URL contains an '@' symbol, which is commonly used in misleading links.")

    if features.get("nb_percent", 0) > 0:
        reasons.append("The URL contains encoded or obfuscated characters.")

    if features.get("nb_qm", 0) > 1 or features.get("nb_and", 0) > 2 or features.get("nb_eq", 0) > 2:
        reasons.append("The URL contains excessive query parameters.")

    if features.get("https_token", 0) == 0:
        reasons.append("The link does not appear to use HTTPS properly.")

    if features.get("tld_in_subdomain", 0) == 1:
        reasons.append("The URL contains a TLD-like word inside the subdomain, which can be deceptive.")

    if features.get("abnormal_subdomain", 0) == 1:
        reasons.append("The subdomain appears to imitate a known brand or trusted domain structure.")

    if features.get("phish_hints", 0) >= 2:
        reasons.append("The URL contains multiple phishing-related keywords.")

    if features.get("nb_redirection", 0) > 0:
        reasons.append("The URL structure suggests possible embedded redirection.")

    if features.get("ratio_digits_url", 0) > 0.3:
        reasons.append("The URL contains an unusually high number of digits.")

    if features.get("longest_words_raw", 0) > 20:
        reasons.append("The URL contains unusually long word segments.")

    if not reasons:
        reasons.append("No strong suspicious indicators were detected from the URL structure.")

    return reasons


def run_phishguard_scan(submitted_url):
    submitted_url = normalize_url(submitted_url)

    scan_data = {
        "submitted_url": submitted_url,
        "result": None,
        "risk_level": None,
        "final_score": None,
        "analysis_confidence": None,
        "reasons": [],
        "top_findings": [],
        "nlp_score": None,
        "suspicious_keywords": [],
        "brand_keywords": [],
        "page_result": None,
        "domain_result": None,
        "redirect_result": None,
        "hybrid_result": None,
        "ml_result": None,
        "ml_confidence": None,
        "safe_browsing_result": None,
        "error": None
    }

    if not submitted_url:
        scan_data["error"] = "No URL provided."
        return scan_data

    if model is None or feature_columns is None:
        scan_data["result"] = "Model unavailable"
        scan_data["risk_level"] = "Unavailable"
        scan_data["reasons"] = ["The live model or feature configuration could not be loaded."]
        scan_data["error"] = "Model unavailable."
        return scan_data

    try:
        safe_browsing_result = check_url_safe_browsing(submitted_url)
        scan_data["safe_browsing_result"] = safe_browsing_result

        if safe_browsing_result.get("api_available") and safe_browsing_result.get("is_threat"):
            threat_type = safe_browsing_result.get("threat_type", "THREAT")

            scan_data["result"] = "Potential Phishing"
            scan_data["risk_level"] = "High"
            scan_data["final_score"] = 95
            scan_data["analysis_confidence"] = 99
            scan_data["reasons"] = [
                f"Google Safe Browsing flagged this URL as: {threat_type.replace('_', ' ').title()}.",
                "This URL appears in Google's actively maintained threat database.",
                "Confirmed threat — do not visit this link."
            ]
            scan_data["top_findings"] = ["Confirmed by Google Safe Browsing"]

            return scan_data

        extracted_features = extract_url_features(submitted_url)

        nlp_result = analyze_url_nlp(submitted_url)
        scan_data["nlp_score"] = nlp_result.get("nlp_risk_score")
        scan_data["suspicious_keywords"] = nlp_result.get("suspicious_keywords", [])
        scan_data["brand_keywords"] = nlp_result.get("brand_keywords", [])

        redirect_result = analyze_redirects(
            submitted_url,
            brand_keywords=scan_data["brand_keywords"]
        )
        scan_data["redirect_result"] = redirect_result

        final_analysis_url = redirect_result.get("final_url") if redirect_result else submitted_url

        page_result = analyze_webpage(final_analysis_url)
        scan_data["page_result"] = page_result

        domain_result = validate_domain(
            submitted_url,
            brand_keywords=scan_data["brand_keywords"],
            final_url=final_analysis_url
        )
        scan_data["domain_result"] = domain_result

        feature_row = {col: extracted_features.get(col, 0) for col in feature_columns}
        feature_df = pd.DataFrame([feature_row])

        prediction = model.predict(feature_df)[0]

        proba = None
        if hasattr(model, "predict_proba"):
            proba = model.predict_proba(feature_df)[0]

        if prediction == 1:
            ml_result = "Likely Safe"
            ml_confidence = round(proba[1] * 100, 2) if proba is not None else None
        else:
            ml_result = "Potential Phishing"
            ml_confidence = round(proba[0] * 100, 2) if proba is not None else None

        scan_data["ml_result"] = ml_result
        scan_data["ml_confidence"] = ml_confidence

        url_reasons = generate_explanations(extracted_features)

        hybrid_result = evaluate_risk(
            ml_prediction=prediction,
            ml_confidence=ml_confidence,
            nlp_result=nlp_result,
            page_result=page_result,
            domain_result=domain_result,
            redirect_result=redirect_result,
            extracted_features=extracted_features,
            url_reasons=url_reasons
        )
        scan_data["hybrid_result"] = hybrid_result

        scan_data["result"] = hybrid_result.get("final_result")
        scan_data["risk_level"] = hybrid_result.get("final_risk_level")
        scan_data["final_score"] = hybrid_result.get("final_score")
        scan_data["analysis_confidence"] = hybrid_result.get("final_confidence")
        scan_data["reasons"] = hybrid_result.get("reasons", [])
        scan_data["top_findings"] = hybrid_result.get("top_findings", [])

    except Exception as e:
        scan_data["result"] = "Scan failed"
        scan_data["risk_level"] = "Error"
        scan_data["reasons"] = [f"An error occurred during analysis: {str(e)}"]
        scan_data["error"] = str(e)

    return scan_data


@app.route("/", methods=["GET", "POST"])
def index():
    scan_data = {
        "submitted_url": "",
        "result": None,
        "risk_level": None,
        "final_score": None,
        "analysis_confidence": None,
        "reasons": [],
        "top_findings": [],
        "nlp_score": None,
        "suspicious_keywords": [],
        "brand_keywords": [],
        "page_result": None,
        "domain_result": None,
        "redirect_result": None,
        "hybrid_result": None,
        "ml_result": None,
        "ml_confidence": None,
        "safe_browsing_result": None
    }

    if request.method == "POST":
        submitted_url = request.form.get("url", "").strip()
        scan_data = run_phishguard_scan(submitted_url)

    return render_template(
        "index.html",
        result=scan_data["result"],
        risk_level=scan_data["risk_level"],
        final_score=scan_data["final_score"],
        analysis_confidence=scan_data["analysis_confidence"],
        reasons=scan_data["reasons"],
        top_findings=scan_data["top_findings"],
        submitted_url=scan_data["submitted_url"],
        nlp_score=scan_data["nlp_score"],
        suspicious_keywords=scan_data["suspicious_keywords"],
        brand_keywords=scan_data["brand_keywords"],
        page_result=scan_data["page_result"],
        domain_result=scan_data["domain_result"],
        redirect_result=scan_data["redirect_result"],
        hybrid_result=scan_data["hybrid_result"],
        ml_result=scan_data["ml_result"],
        ml_confidence=scan_data["ml_confidence"],
        safe_browsing_result=scan_data["safe_browsing_result"]
    )


@app.route("/api/scan", methods=["POST"])
def api_scan():
    try:
        data = request.get_json(silent=True) or {}
        submitted_url = data.get("url", "").strip()

        if not submitted_url:
            return jsonify({
                "success": False,
                "error": "No URL provided."
            }), 400

        scan_data = run_phishguard_scan(submitted_url)

        if scan_data.get("error") and scan_data.get("result") == "Scan failed":
            return jsonify({
                "success": False,
                "error": scan_data["error"],
                "result": scan_data
            }), 500

        return jsonify({
            "success": True,
            "result": scan_data
        }), 200

    except Exception as e:
        return jsonify({
            "success": False,
            "error": str(e)
        }), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)