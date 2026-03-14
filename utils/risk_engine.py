def evaluate_risk(ml_prediction, ml_confidence, nlp_result, page_result):
    """
    Combines:
    - ML prediction
    - ML confidence
    - NLP URL analysis
    - Webpage inspection

    Returns:
    {
        "final_result": "...",
        "final_risk_level": "...",
        "final_confidence": ...,
        "risk_reasons": [...]
    }
    """

    risk_score = 0
    reasons = []

    # -----------------------------
    # 1. Machine Learning Layer
    # Dataset mapping:
    # 1 = legitimate
    # 0 = phishing
    # -----------------------------
    if ml_prediction == 0:
        risk_score += 45
        reasons.append("The machine learning model classified the URL as phishing.")
    else:
        risk_score -= 20
        reasons.append("The machine learning model classified the URL as likely legitimate.")

    if ml_confidence is not None:
        if ml_prediction == 0 and ml_confidence >= 90:
            risk_score += 15
            reasons.append("The phishing prediction confidence is very high.")
        elif ml_prediction == 0 and ml_confidence >= 70:
            risk_score += 8
            reasons.append("The phishing prediction confidence is moderately high.")
        elif ml_prediction == 1 and ml_confidence >= 90:
            risk_score -= 10
            reasons.append("The legitimate prediction confidence is very high.")

    # -----------------------------
    # 2. NLP Layer
    # -----------------------------
    nlp_score = nlp_result.get("nlp_risk_score", 0)
    suspicious_keywords = nlp_result.get("suspicious_keywords", [])
    brand_keywords = nlp_result.get("brand_keywords", [])

    if nlp_score >= 80:
        risk_score += 30
        reasons.append("NLP analysis found very strong phishing-related language patterns.")
    elif nlp_score >= 50:
        risk_score += 18
        reasons.append("NLP analysis found multiple suspicious URL keywords.")
    elif nlp_score >= 20:
        risk_score += 8
        reasons.append("NLP analysis found mild suspicious language patterns.")
    else:
        risk_score -= 8
        reasons.append("NLP analysis found little to no suspicious language.")

    if suspicious_keywords:
        reasons.append(f"Suspicious keywords detected: {', '.join(suspicious_keywords)}")

    if brand_keywords and suspicious_keywords:
        risk_score += 10
        reasons.append(
            f"Brand-related terms combined with suspicious words were detected: {', '.join(brand_keywords)}"
        )

    # -----------------------------
    # 3. Webpage Inspection Layer
    # -----------------------------
    if page_result:
        if page_result.get("page_accessible"):
            reasons.append("Webpage inspection was completed successfully.")

            forms = page_result.get("forms", 0)
            password_fields = page_result.get("password_fields", 0)
            iframes = page_result.get("iframes", 0)
            external_scripts = page_result.get("external_scripts", 0)
            external_links = page_result.get("external_links", 0)
            has_favicon = page_result.get("has_favicon", False)

            if password_fields > 0:
                risk_score += 20
                reasons.append("The webpage contains password input fields.")

            if forms > 2:
                risk_score += 10
                reasons.append("The webpage contains multiple forms.")

            if iframes > 0:
                risk_score += 10
                reasons.append("The webpage contains iframe elements.")

            if external_scripts > 40:
                risk_score += 8
                reasons.append("The webpage loads a large number of external scripts.")

            if external_links > 30:
                risk_score += 8
                reasons.append("The webpage contains many external links.")

            if has_favicon:
                risk_score -= 3
                reasons.append("The webpage includes a favicon, which is a mild legitimacy signal.")

            # Safe-ish override conditions
            if (
                password_fields == 0
                and forms <= 5
                and iframes == 0
                and not suspicious_keywords
                and nlp_score < 20
            ):
                risk_score -= 18
                reasons.append("Webpage structure appears relatively normal and does not reinforce phishing suspicion.")

        else:
            reasons.append("Webpage inspection could not be completed, so the final result relies more on ML and NLP.")
    else:
        reasons.append("No webpage inspection data was available.")

    # -----------------------------
    # 4. Clamp score
    # -----------------------------
    risk_score = max(0, min(risk_score, 100))

    # -----------------------------
    # 5. Final verdict
    # -----------------------------
    if risk_score >= 70:
        final_result = "Potential Phishing"
        final_risk_level = "High"
    elif risk_score >= 40:
        final_result = "Suspicious - Review Needed"
        final_risk_level = "Medium"
    else:
        final_result = "Likely Safe"
        final_risk_level = "Low"

    return {
        "final_result": final_result,
        "final_risk_level": final_risk_level,
        "final_confidence": round(risk_score, 2),
        "risk_reasons": reasons
    }