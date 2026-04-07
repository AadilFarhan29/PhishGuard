def _append_unique(items, item):
    if item and item not in items:
        items.append(item)


def _clamp_score(score):
    return max(0, min(100, round(score, 2)))


def _build_ml_score(ml_prediction, ml_confidence):
    reasons = []

    confidence = ml_confidence if ml_confidence is not None else 70

    if ml_prediction == 0:
        score = 65 + min(30, max(0, confidence - 50) * 0.6)
        reasons.append("The machine learning classifier labeled the URL as phishing-oriented.")
        if confidence >= 90:
            reasons.append("The ML phishing confidence is very high.")
        elif confidence >= 75:
            reasons.append("The ML phishing confidence is moderately high.")
        summary = "ML features strongly resemble the phishing patterns learned during training."
    else:
        score = 32 - min(24, max(0, confidence - 50) * 0.4)
        reasons.append("The machine learning classifier labeled the URL as more likely legitimate.")
        if confidence >= 90:
            reasons.append("The ML legitimate confidence is strong.")
        summary = "ML URL-structure signals are closer to the benign patterns seen during training."

    return _clamp_score(score), summary, reasons


def _build_nlp_score(nlp_result):
    nlp_score = _clamp_score(nlp_result.get("nlp_risk_score", 0))
    suspicious_keywords = nlp_result.get("suspicious_keywords", [])
    brand_keywords = nlp_result.get("brand_keywords", [])
    reasons = []

    if suspicious_keywords:
        reasons.append(f"Suspicious keywords detected: {', '.join(suspicious_keywords)}.")
    else:
        reasons.append("No strong phishing-related keywords were detected in the URL text.")

    if brand_keywords:
        reasons.append(f"Brand terms detected: {', '.join(brand_keywords)}.")

    summary = nlp_result.get("nlp_summary") or "NLP analysis reviewed brand and phishing language in the URL."
    return nlp_score, summary, reasons


def _build_domain_score(domain_result):
    domain_score = _clamp_score((domain_result or {}).get("domain_risk_score", 25))
    reasons = list((domain_result or {}).get("domain_reasons", []))

    if domain_result and domain_result.get("brand_domain_match"):
        summary = "The detected brand context lines up with an official trusted domain."
    elif domain_result and domain_result.get("brand_spoofing_suspected"):
        summary = "Brand or trust indicators do not align cleanly with the resolved domain."
    elif domain_result and domain_result.get("trusted_domain"):
        summary = "Domain validation found trust signals and limited spoofing evidence."
    else:
        summary = "Domain validation found mixed trust signals without a decisive brand match."

    return domain_score, summary, reasons


def _build_page_score(page_result):
    page_score = _clamp_score((page_result or {}).get("page_risk_score", 24))
    reasons = list((page_result or {}).get("page_reasons", []))

    if page_result and page_result.get("password_form_external_actions", 0) > 0:
        summary = "The page collects credentials and routes at least one form to an external destination."
    elif page_result and page_result.get("password_fields", 0) > 0:
        summary = "The page appears to collect credentials, which raises the importance of domain trust."
    elif page_result and page_result.get("page_accessible"):
        summary = "Webpage inspection found some structural cues, but not a strong credential-stealing pattern."
    else:
        summary = "Webpage inspection could not fully verify the page, so webpage evidence is limited."

    return page_score, summary, reasons


def _build_redirect_score(redirect_result):
    redirect_score = _clamp_score((redirect_result or {}).get("redirect_risk_score", 0))
    reasons = list((redirect_result or {}).get("redirect_reasons", []))

    if redirect_result and redirect_result.get("brand_mismatch_detected"):
        summary = "Redirect behavior moved the URL toward a destination that does not fit the detected brand context."
    elif redirect_result and redirect_result.get("final_brand_match"):
        summary = "Redirect inspection resolved the URL to an official brand destination, reducing concern."
    elif redirect_result and redirect_result.get("redirect_hops", 0) > 0:
        summary = "Redirect inspection observed intermediate hops before the final page loaded."
    else:
        summary = "Redirect inspection found little destination-changing behavior."

    return redirect_score, summary, reasons


def _apply_adjustment(engine_points, key, amount):
    engine_points[key] = max(0, engine_points[key] + amount)


def _calculate_verdict_confidence(final_score, raw_scores, risk_level):
    if not raw_scores:
        return 50

    if risk_level == "High":
        aligned = sum(score >= 55 for score in raw_scores)
        confidence = 58 + aligned * 6 + max(0, final_score - 70) * 0.35
    elif risk_level == "Low":
        aligned = sum(score <= 40 for score in raw_scores)
        confidence = 58 + aligned * 6 + max(0, 35 - final_score) * 0.4
    else:
        aligned = sum(35 <= score <= 70 for score in raw_scores)
        confidence = 54 + aligned * 5 + max(0, 18 - abs(50 - final_score)) * 0.45

    return _clamp_score(min(95, confidence))


def evaluate_risk(
    ml_prediction,
    ml_confidence,
    nlp_result,
    page_result,
    domain_result=None,
    redirect_result=None,
    extracted_features=None,
    url_reasons=None
):
    if extracted_features is None:
        extracted_features = {}

    if url_reasons is None:
        url_reasons = []

    reasons = []
    top_findings = []
    context_reasons = []

    ml_score, ml_summary, ml_reasons = _build_ml_score(ml_prediction, ml_confidence)
    nlp_score, nlp_summary, nlp_reasons = _build_nlp_score(nlp_result)
    domain_score, domain_summary, domain_reasons = _build_domain_score(domain_result)
    page_score, page_summary, page_reasons = _build_page_score(page_result)
    redirect_score, redirect_summary, redirect_reasons = _build_redirect_score(redirect_result)

    weights = {
        "ml": 0.34,
        "nlp": 0.16,
        "domain": 0.18,
        "page": 0.20,
        "redirect": 0.12,
    }

    engine_points = {
        "ml": round(ml_score * weights["ml"], 2),
        "nlp": round(nlp_score * weights["nlp"], 2),
        "domain": round(domain_score * weights["domain"], 2),
        "page": round(page_score * weights["page"], 2),
        "redirect": round(redirect_score * weights["redirect"], 2),
    }

    suspicious_keywords = nlp_result.get("suspicious_keywords", [])
    brand_keywords = nlp_result.get("brand_keywords", [])
    uses_shortener = extracted_features.get("UsesShortener") == 1
    password_fields = (page_result or {}).get("password_fields", 0)
    same_domain_forms = (page_result or {}).get("same_domain_form_actions", 0)
    external_form_actions = (page_result or {}).get("external_form_actions", 0)
    suspicious_form_actions = (page_result or {}).get("suspicious_form_actions", 0)
    brand_mismatch = (
        (domain_result or {}).get("brand_spoofing_suspected")
        or (redirect_result or {}).get("brand_mismatch_detected")
    )
    redirect_mismatch = (redirect_result or {}).get("final_domain_differs") and not (redirect_result or {}).get("final_domain_trusted")
    trusted_domain = (domain_result or {}).get("trusted_domain") or (redirect_result or {}).get("final_domain_trusted")
    final_redirect_matches_brand = (redirect_result or {}).get("final_brand_match")
    login_page_context = password_fields > 0 or nlp_result.get("login_intent_detected", False)
    low_nlp = nlp_score < 25

    if brand_mismatch:
        _append_unique(top_findings, "Brand mismatch detected")
    if suspicious_keywords:
        _append_unique(top_findings, "Suspicious login keywords")
    if redirect_mismatch:
        _append_unique(top_findings, "Redirect destination differs")
    if trusted_domain:
        _append_unique(top_findings, "Trusted official domain")
    if password_fields > 0:
        _append_unique(top_findings, "Password field detected")
    if external_form_actions > 0:
        _append_unique(top_findings, "External form submission")
    if uses_shortener:
        _append_unique(top_findings, "URL shortener used")

    if brand_keywords and brand_mismatch and password_fields > 0:
        _apply_adjustment(engine_points, "domain", 8)
        _apply_adjustment(engine_points, "page", 10)
        _apply_adjustment(engine_points, "redirect", 4)
        _append_unique(
            context_reasons,
            "Brand keywords, domain mismatch, and password collection appeared together, which is a strong phishing pattern."
        )

    if suspicious_keywords and uses_shortener and redirect_mismatch:
        _apply_adjustment(engine_points, "nlp", 6)
        _apply_adjustment(engine_points, "redirect", 6)
        _apply_adjustment(engine_points, "domain", 2)
        _append_unique(
            context_reasons,
            "Suspicious wording combined with a URL shortener and a mismatched final redirect raises the risk substantially."
        )

    if external_form_actions > 0 and password_fields > 0:
        _apply_adjustment(engine_points, "page", 12)
        _apply_adjustment(engine_points, "domain", 4)
        _append_unique(
            context_reasons,
            "The inspected page contains password input fields and submits at least one form to an external destination."
        )

    if suspicious_form_actions > 0:
        _apply_adjustment(engine_points, "page", 6)
        _append_unique(
            context_reasons,
            "Form endpoints include suspicious handler paths or script-driven submissions."
        )

    if trusted_domain and login_page_context and low_nlp and same_domain_forms > 0 and external_form_actions == 0:
        _apply_adjustment(engine_points, "domain", -8)
        _apply_adjustment(engine_points, "page", -8)
        _apply_adjustment(engine_points, "nlp", -4)
        _append_unique(
            context_reasons,
            "The page looks like a login flow on a trusted domain with same-domain form submission and limited suspicious language, so the risk is reduced."
        )

    if final_redirect_matches_brand:
        _apply_adjustment(engine_points, "redirect", -8)
        _apply_adjustment(engine_points, "domain", -6)
        _append_unique(
            context_reasons,
            "The redirect chain finishes on the official trusted brand domain, reducing suspicion."
        )

    if (redirect_result or {}).get("redirect_hops", 0) >= 3 and (redirect_result or {}).get("final_domain_differs"):
        _apply_adjustment(engine_points, "redirect", 5)
        _apply_adjustment(engine_points, "domain", 3)
        _append_unique(
            context_reasons,
            "Multiple redirect hops ending on a different domain make the destination harder to trust."
        )

    for reason in context_reasons:
        _append_unique(reasons, reason)

    for group in (url_reasons, ml_reasons, nlp_reasons, domain_reasons, redirect_reasons, page_reasons):
        for reason in group:
            _append_unique(reasons, reason)

    if not top_findings:
        _append_unique(top_findings, "No strong phishing indicators")

    final_score = _clamp_score(sum(engine_points.values()))

    # --- Trusted Domain Score Cap ---
    # If the domain is verified trusted, the system should never return
    # a "Phishing" verdict purely due to URL complexity or NLP hits.
    trusted_domain = (domain_result or {}).get("trusted_domain", False)

    if trusted_domain:
        if ml_prediction == 1:
            # ML says safe + trusted domain → hard cap at Safe zone
            if final_score > 41:
                final_score = 41
                _append_unique(
                    reasons,
                    "Score capped: domain is verified trusted and ML classified this URL as legitimate."
                )
        else:
            # ML says phishing but domain is trusted → cap at Suspicious max (never Phishing)
            if final_score > 65:
                final_score = 65
                _append_unique(
                    reasons,
                    "Score capped: domain is verified trusted, so phishing verdict is limited to Suspicious."
                )

    if final_score >= 72:
        final_result = "Potential Phishing"
        final_risk_level = "High"
    elif final_score >= 42:
        final_result = "Suspicious - Review Needed"
        final_risk_level = "Medium"
    else:
        final_result = "Likely Safe"
        final_risk_level = "Low"

    final_confidence = _calculate_verdict_confidence(
        final_score,
        [ml_score, nlp_score, domain_score, page_score, redirect_score],
        final_risk_level
    )

    engine_breakdown = {
        "ml": {
            "title": "Machine Learning",
            "score": ml_score,
            "contribution": round(engine_points["ml"], 2),
            "summary": ml_summary,
            "details": ml_reasons[:3],
        },
        "nlp": {
            "title": "NLP Analysis",
            "score": nlp_score,
            "contribution": round(engine_points["nlp"], 2),
            "summary": nlp_summary,
            "details": nlp_reasons[:3],
        },
        "domain": {
            "title": "Domain Intelligence",
            "score": domain_score,
            "contribution": round(engine_points["domain"], 2),
            "summary": domain_summary,
            "details": domain_reasons[:3],
        },
        "page": {
            "title": "Webpage / Form Inspection",
            "score": page_score,
            "contribution": round(engine_points["page"], 2),
            "summary": page_summary,
            "details": page_reasons[:3],
        },
        "redirect": {
            "title": "Redirect Intelligence",
            "score": redirect_score,
            "contribution": round(engine_points["redirect"], 2),
            "summary": redirect_summary,
            "details": redirect_reasons[:3],
        },
    }

    return {
        "final_result": final_result,
        "final_risk_level": final_risk_level,
        "final_confidence": final_confidence,
        "final_score": final_score,
        "reasons": reasons[:12],
        "top_findings": top_findings[:6],
        "ml_score": ml_score,
        "nlp_score": nlp_score,
        "domain_score": domain_score,
        "page_score": page_score,
        "redirect_score": redirect_score,
        "engine_breakdown": engine_breakdown,
        "chart_data": {
            "radar_labels": ["ML Risk", "NLP Risk", "Domain Risk", "Page Risk", "Redirect Risk"],
            "radar_values": [ml_score, nlp_score, domain_score, page_score, redirect_score],
            "radar_explanations": [ml_summary, nlp_summary, domain_summary, page_summary, redirect_summary],
            "contribution_labels": ["ML", "NLP", "Domain", "Page", "Redirect"],
            "contribution_values": [
                round(engine_points["ml"], 2),
                round(engine_points["nlp"], 2),
                round(engine_points["domain"], 2),
                round(engine_points["page"], 2),
                round(engine_points["redirect"], 2),
            ],
            "contribution_explanations": [
                f"{ml_summary} Contribution reflects ML influence on the final verdict.",
                f"{nlp_summary} Contribution reflects keyword and intent evidence.",
                f"{domain_summary} Contribution reflects trust and brand-alignment signals.",
                f"{page_summary} Contribution reflects visible page and form behavior.",
                f"{redirect_summary} Contribution reflects destination changes and redirect trust.",
            ],
        },
    }