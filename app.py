import os
import joblib
import pandas as pd
from flask import Flask, render_template, request

from utils.features_old import extract_url_features
from utils.nlp_analyzer import analyze_url_nlp
from utils.page_analyzer import analyze_webpage
from utils.domain_validator import validate_domain
from utils.redirect_analyzer import analyze_redirects
from utils.risk_engine import evaluate_risk
from utils.safe_browsing import check_url_safe_browsing

app = Flask(__name__)

MODEL_PATH = "model/phishguard_live_model.pkl"
FEATURE_COLUMNS_PATH = "model/live_feature_columns.pkl"

model = None
feature_columns = None

if os.path.exists(MODEL_PATH):
    model = joblib.load(MODEL_PATH)

if os.path.exists(FEATURE_COLUMNS_PATH):
    feature_columns = joblib.load(FEATURE_COLUMNS_PATH)


def generate_explanations(features):
    reasons = []

    if features["URLLength"] > 75:
        reasons.append("The URL is unusually long.")

    if features["IsDomainIP"] == 1:
        reasons.append("The link uses an IP address instead of a normal domain.")

    if features["NoOfSubDomain"] > 2:
        reasons.append("The URL contains many subdomains.")

    if features["HasObfuscation"] == 1:
        reasons.append("The URL contains obfuscation characters such as '%' or '@'.")

    if features["UsesShortener"] == 1:
        reasons.append("The URL uses a shortening service.")

    if features["HasSuspiciousKeyword"] == 1:
        reasons.append("The URL path or query contains suspicious phishing-related keywords.")

    if features["NoOfQMarkInURL"] > 1 or features["NoOfAmpersandInURL"] > 2:
        reasons.append("The URL contains excessive query parameters.")

    if features["NoOfOtherSpecialCharsInURL"] > 5:
        reasons.append("The URL contains an unusual number of special characters.")

    if features["IsHTTPS"] == 0:
        reasons.append("The link does not use HTTPS encryption.")

    if not reasons:
        reasons.append("No strong suspicious indicators were detected from the URL structure.")

    return reasons


@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    risk_level = None
    final_score = None
    analysis_confidence = None
    reasons = []
    top_findings = []
    submitted_url = ""

    nlp_score = None
    suspicious_keywords = []
    brand_keywords = []

    page_result = None
    domain_result = None
    redirect_result = None
    hybrid_result = None

    ml_result = None
    ml_confidence = None
    safe_browsing_result = None

    if request.method == "POST":
        submitted_url = request.form.get("url", "").strip()

        if submitted_url:
            if not submitted_url.startswith(("http://", "https://")):
                submitted_url = "https://" + submitted_url

            if model is None or feature_columns is None:
                result = "Model unavailable"
                risk_level = "Unavailable"
                reasons = ["The live model or feature configuration could not be loaded."]
            else:
                # --- Google Safe Browsing Check (runs first) ---
                safe_browsing_result = check_url_safe_browsing(submitted_url)

                if safe_browsing_result.get("api_available") and safe_browsing_result.get("is_threat"):
                    # Google confirmed threat — skip ML pipeline, return immediately
                    threat_type = safe_browsing_result.get("threat_type", "THREAT")
                    result = "Potential Phishing"
                    risk_level = "High"
                    final_score = 95
                    analysis_confidence = 99
                    reasons = [
                        f"Google Safe Browsing flagged this URL as: {threat_type.replace('_', ' ').title()}.",
                        "This URL appears in Google's actively maintained threat database.",
                        "Confirmed threat — do not visit this link."
                    ]
                    top_findings = ["Confirmed by Google Safe Browsing"]

                else:
                    extracted_features = extract_url_features(submitted_url)

                    nlp_result = analyze_url_nlp(submitted_url)
                    nlp_score = nlp_result["nlp_risk_score"]
                    suspicious_keywords = nlp_result["suspicious_keywords"]
                    brand_keywords = nlp_result["brand_keywords"]

                    redirect_result = analyze_redirects(submitted_url, brand_keywords=brand_keywords)
                    final_analysis_url = redirect_result.get("final_url") if redirect_result else submitted_url
                    page_result = analyze_webpage(final_analysis_url)
                    domain_result = validate_domain(
                        submitted_url,
                        brand_keywords=brand_keywords,
                        final_url=final_analysis_url
                    )

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

                    result = hybrid_result["final_result"]
                    risk_level = hybrid_result["final_risk_level"]
                    final_score = hybrid_result["final_score"]
                    analysis_confidence = hybrid_result["final_confidence"]
                    reasons = hybrid_result["reasons"]
                    top_findings = hybrid_result["top_findings"]

    return render_template(
        "index.html",
        result=result,
        risk_level=risk_level,
        final_score=final_score,
        analysis_confidence=analysis_confidence,
        reasons=reasons,
        top_findings=top_findings,
        submitted_url=submitted_url,
        nlp_score=nlp_score,
        suspicious_keywords=suspicious_keywords,
        brand_keywords=brand_keywords,
        page_result=page_result,
        domain_result=domain_result,
        redirect_result=redirect_result,
        hybrid_result=hybrid_result,
        ml_result=ml_result,
        ml_confidence=ml_confidence,
        safe_browsing_result=safe_browsing_result
    )


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 10000))
    app.run(host="0.0.0.0", port=port)