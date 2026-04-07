import re
from modules.url_analyser import analyse_url
from modules.brand_checker import check_brand_impersonation
from modules.page_analyser import analyse_page
from modules.ml_scorer import get_ml_score
from modules.risk_aggregator import aggregate_risk
from concurrent.futures import ThreadPoolExecutor

def extract_urls(text):
    """Extract all URLs from email content."""
    url_pattern = re.compile(
        r'https?://[^\s<>"{}|\\^`\[\]\']+|'
        r'www\.[^\s<>"{}|\\^`\[\]\']+'
    )
    urls = url_pattern.findall(text)
    clean_urls = []
    for url in urls:
        url = url.rstrip('.,;:!?)')
        if not url.startswith('http'):
            url = 'http://' + url
        if url not in clean_urls:
            clean_urls.append(url)
    return clean_urls

def scan_email(email_content):
    """Scan email content for phishing URLs."""

    urls = extract_urls(email_content)

    if not urls:
        return {
            "urls_found": 0,
            "urls": [],
            "overall_verdict": "SAFE",
            "overall_color": "green",
            "summary": "No URLs found in this email content.",
            "dangerous_count": 0,
            "suspicious_count": 0,
            "safe_count": 0
        }

    url_results = []

    for url in urls[:10]:
        try:
            with ThreadPoolExecutor(max_workers=4) as executor:
                future_url   = executor.submit(analyse_url, url)
                future_brand = executor.submit(check_brand_impersonation, url)
                future_page  = executor.submit(analyse_page, url)
                future_ml    = executor.submit(get_ml_score, url)

                url_result   = future_url.result()
                brand_result = future_brand.result()
                page_result  = future_page.result()
                ml_result    = future_ml.result()

            final = aggregate_risk(url_result, brand_result, page_result, ml_result)

            url_results.append({
                "url":          url,
                "verdict":      final["verdict"],
                "score":        final["final_score"],
                "color":        final["verdict_color"],
                "summary":      final["summary"],
                "findings":     [
                    f for f in final["all_findings"]
                    if f["severity"] != "Info"
                ],
                "engine_scores": final["engine_scores"]
            })

        except Exception as e:
            url_results.append({
                "url":      url,
                "verdict":  "ERROR",
                "score":    0,
                "color":    "gray",
                "summary":  f"Could not scan this URL: {str(e)}",
                "findings": [],
                "engine_scores": {}
            })

    dangerous_count  = sum(1 for r in url_results if r["verdict"] == "PHISHING")
    suspicious_count = sum(1 for r in url_results if r["verdict"] == "SUSPICIOUS")
    safe_count       = sum(1 for r in url_results if r["verdict"] == "SAFE")

    if dangerous_count > 0:
        overall_verdict = "PHISHING DETECTED"
        overall_color   = "red"
        overall_summary = f"WARNING!! {dangerous_count} phishing link(s) found in this email. Do NOT click any links."
    elif suspicious_count > 0:
        overall_verdict = "SUSPICIOUS"
        overall_color   = "orange"
        overall_summary = f"{suspicious_count} suspicious link(s) found. Proceed with extreme caution."
    else:
        overall_verdict = "SAFE"
        overall_color   = "green"
        overall_summary = "All links in this email appear to be safe."

    return {
        "urls_found":       len(urls),
        "urls_scanned":     len(url_results),
        "urls":             url_results,
        "overall_verdict":  overall_verdict,
        "overall_color":    overall_color,
        "overall_summary":  overall_summary,
        "dangerous_count":  dangerous_count,
        "suspicious_count": suspicious_count,
        "safe_count":       safe_count
    }