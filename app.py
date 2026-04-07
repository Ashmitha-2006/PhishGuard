from flask import Flask, render_template, request, send_file, jsonify
from concurrent.futures import ThreadPoolExecutor
import urllib3
import os
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

from modules.url_analyser import analyse_url
from modules.brand_checker import check_brand_impersonation
from modules.page_analyser import analyse_page
from modules.ml_scorer import get_ml_score
from modules.risk_aggregator import aggregate_risk
from report_generator import generate_pdf_report

app = Flask(__name__)
scan_history = []

def run_scan(url):
    with ThreadPoolExecutor(max_workers=4) as executor:
        future_url   = executor.submit(analyse_url, url)
        future_brand = executor.submit(check_brand_impersonation, url)
        future_page  = executor.submit(analyse_page, url)
        future_ml    = executor.submit(get_ml_score, url)

        url_result   = future_url.result()
        brand_result = future_brand.result()
        page_result  = future_page.result()
        ml_result    = future_ml.result()

    return aggregate_risk(url_result, brand_result, page_result, ml_result)

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html', history=scan_history)

@app.route('/scan', methods=['POST'])
def scan():
    url = request.form.get('url', '').strip()

    if not url:
        return render_template('index.html', error="Please enter a URL to scan.", history=scan_history)

    if not url.startswith('http'):
        url = 'http://' + url

    final = run_scan(url)

    scan_history.insert(0, {
        "url": url,
        "verdict": final["verdict"],
        "score": final["final_score"],
        "color": final["verdict_color"]
    })

    if len(scan_history) > 5:
        scan_history.pop()

    filename, filepath = generate_pdf_report(url, final)

    return render_template('result.html', url=url, result=final, report_file=filename)

@app.route('/download/<filename>')
def download(filename):
    filepath = os.path.join("reports", filename)
    return send_file(filepath, as_attachment=True)

# ── URL SCAN API ─────────────────────────────────────────
@app.route('/api/scan', methods=['POST'])
def api_scan():
    data = request.get_json()

    if not data or 'url' not in data:
        return jsonify({
            "error": "Missing URL",
            "message": "Please provide a URL in the request body: { 'url': 'https://example.com' }"
        }), 400

    url = data['url'].strip()
    if not url.startswith('http'):
        url = 'http://' + url

    try:
        final = run_scan(url)
        return jsonify({
            "url": url,
            "verdict": final["verdict"],
            "risk_score": final["final_score"],
            "summary": final["summary"],
            "recommendation": final["recommendation"],
            "engine_scores": {
                "url_analyser":  final["engine_scores"]["url_score"],
                "brand_checker": final["engine_scores"]["brand_score"],
                "page_analyser": final["engine_scores"]["page_score"],
                "ml_scorer":     final["engine_scores"]["ml_score"]
            },
            "findings": [
                {
                    "check":       f["check"],
                    "severity":    f["severity"],
                    "explanation": f["explanation"],
                    "engine":      f["engine"]
                }
                for f in final["all_findings"]
                if f["severity"] != "Info"
            ],
            "stats": {
                "high":   final["high_count"],
                "medium": final["medium_count"],
                "low":    final["low_count"],
                "total":  final["total_flags"]
            }
        }), 200

    except Exception as e:
        return jsonify({"error": "Scan failed", "message": str(e)}), 500

# ── HEALTH CHECK ─────────────────────────────────────────
@app.route('/api/health', methods=['GET'])
def api_health():
    return jsonify({
        "status": "online",
        "tool": "PhishGuard",
        "version": "1.0.0",
        "endpoints": {
            "scan":         "POST /api/scan",
            "health":       "GET /api/health",
            "email_scan":   "POST /api/email/scan"
        }
    }), 200

# ── EMAIL SCANNER ─────────────────────────────────────────
@app.route('/email', methods=['GET'])
def email_index():
    return render_template('email.html')

@app.route('/email/scan', methods=['POST'])
def email_scan():
    from modules.email_scanner import scan_email
    email_content = request.form.get('email_content', '').strip()

    if not email_content:
        return render_template('email.html', error="Please paste email content to scan.")

    result = scan_email(email_content)
    return render_template('email_result.html', result=result)

# ── EMAIL SCAN API ────────────────────────────────────────
@app.route('/api/email/scan', methods=['POST'])
def api_email_scan():
    data = request.get_json()

    if not data or 'email_content' not in data:
        return jsonify({
            "error": "Missing email content",
            "message": "Please provide email_content in the request body"
        }), 400

    from modules.email_scanner import scan_email
    result = scan_email(data['email_content'])

    return jsonify({
        "urls_found":       result["urls_found"],
        "overall_verdict":  result["overall_verdict"],
        "overall_summary":  result["overall_summary"],
        "dangerous_count":  result["dangerous_count"],
        "suspicious_count": result["suspicious_count"],
        "safe_count":       result["safe_count"],
        "urls": [
            {
                "url":     r["url"],
                "verdict": r["verdict"],
                "score":   r["score"],
                "summary": r["summary"],
                "findings": [
                    {
                        "check":    f["check"],
                        "severity": f["severity"],
                        "engine":   f["engine"]
                    }
                    for f in r["findings"]
                ]
            }
            for r in result["urls"]
        ]
    }), 200

if __name__ == '__main__':
    app.run(debug=True)