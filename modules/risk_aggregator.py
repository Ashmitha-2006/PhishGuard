def aggregate_risk(url_result, brand_result, page_result, ml_result):
    """Combine all engine scores into one final verdict with proof."""

    url_score   = url_result["score"]
    brand_score = brand_result["score"]
    page_score  = page_result["score"]
    ml_score    = ml_result["score"]

    url_has_real   = any(f["severity"] != "Info" for f in url_result["findings"])
    brand_has_real = any(f["severity"] != "Info" for f in brand_result["findings"])
    page_has_real  = any(f["severity"] != "Info" for f in page_result["findings"])

    weights = {"url": 0.35, "brand": 0.25, "page": 0.20, "ml": 0.20}

    final_score = (
        url_score   * weights["url"] +
        brand_score * weights["brand"] +
        page_score  * weights["page"] +
        ml_score    * weights["ml"]
    )
    final_score = round(final_score, 1)

    if url_has_real and ml_score >= 50:
        final_score = max(final_score, 55.0)

    if brand_has_real:
        final_score = max(final_score, 65.0)

    if any(f["check"] == "Form submits to external domain" for f in page_result["findings"]):
        final_score = max(final_score, 80.0)

    if final_score <= 20:
        verdict = "SAFE"
        verdict_color = "green"
        summary = "This URL appears to be legitimate. No significant phishing indicators detected."
        recommendation = "This link appears safe to visit. Always stay cautious online."
    elif final_score <= 50:
        verdict = "SUSPICIOUS"
        verdict_color = "orange"
        summary = "This URL has some phishing indicators. Proceed with extreme caution."
        recommendation = "Do not enter any personal information, passwords, or payment details on this site."
    else:
        verdict = "PHISHING"
        verdict_color = "red"
        summary = "This URL shows strong phishing indicators. This is very likely a malicious website."
        recommendation = "Do NOT visit this link. Report it to your IT security team immediately."

    all_findings = []
    for finding in url_result["findings"]:
        finding["engine"] = "URL Analyser"
        all_findings.append(finding)
    for finding in brand_result["findings"]:
        finding["engine"] = "Brand Checker"
        all_findings.append(finding)
    for finding in page_result["findings"]:
        finding["engine"] = "Page Analyser"
        all_findings.append(finding)

    severity_order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
    all_findings.sort(key=lambda x: severity_order.get(x["severity"], 4))

    high_count   = sum(1 for f in all_findings if f["severity"] == "High")
    medium_count = sum(1 for f in all_findings if f["severity"] == "Medium")
    low_count    = sum(1 for f in all_findings if f["severity"] == "Low")

    # Build proof summary
    proof_lines = []
    for f in all_findings:
        if f["severity"] != "Info":
            pts = f.get("points", "?")
            proof_lines.append(f"[{f['severity']}] {f['check']} — {f['engine']}")

    ml_proof = ml_result.get("proof", "")
    if ml_proof:
        proof_lines.append(f"[ML] {ml_proof}")

    return {
        "final_score":    final_score,
        "verdict":        verdict,
        "verdict_color":  verdict_color,
        "summary":        summary,
        "recommendation": recommendation,
        "all_findings":   all_findings,
        "total_flags":    len(all_findings),
        "high_count":     high_count,
        "medium_count":   medium_count,
        "low_count":      low_count,
        "proof_lines":    proof_lines,
        "ml_proof":       ml_proof,
        "engine_scores": {
            "url_score":   url_score,
            "brand_score": brand_score,
            "page_score":  page_score,
            "ml_score":    ml_score
        }
    }