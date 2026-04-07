import requests
from bs4 import BeautifulSoup
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from config import REQUEST_TIMEOUT, SUSPICIOUS_KEYWORDS
from urllib.parse import urlparse

def analyse_page(url):
    """Visit the page and detect fake login pages and suspicious content."""
    findings = []
    score = 0

    try:
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        }

        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        page_text = soup.get_text().lower()

        # ================= EXISTING CHECKS (UNCHANGED) =================

        password_fields = soup.find_all('input', {'type': 'password'})
        if password_fields:
            findings.append({
                "check": "Password input field detected",
                "detail": f"Found {len(password_fields)} password field(s)",
                "severity": "Medium",
                "explanation": "Page contains a password field — could be a fake login page."
            })
            score += 20

        forms = soup.find_all('form', action=True)
        current_domain = url.split('/')[2] if '//' in url else url
        for form in forms:
            action = form['action'].lower()
            if action.startswith('http') and current_domain not in action:
                findings.append({
                    "check": "Form submits to external domain",
                    "detail": f"Form action points to: {form['action']}",
                    "severity": "High",
                    "explanation": "The login form sends your data to a completely different website — classic phishing."
                })
                score += 50
                break

        found_keywords = [kw for kw in SUSPICIOUS_KEYWORDS if kw in page_text]
        if len(found_keywords) >= 2:
            findings.append({
                "check": "Suspicious keywords detected",
                "detail": f"Found: {', '.join(found_keywords)}",
                "severity": "Medium",
                "explanation": "Page contains multiple suspicious keywords commonly used in phishing attacks."
            })
            score += 20

        word_count = len(page_text.split())
        if word_count < 50:
            findings.append({
                "check": "Very sparse page content",
                "detail": f"Page has only {word_count} words",
                "severity": "Low",
                "explanation": "Phishing pages often have very little content — just enough to fool the victim."
            })
            score += 10

        scripts = soup.find_all('script')
        for script in scripts:
            script_text = script.get_text().lower()
            if 'contextmenu' in script_text or 'event.keycode' in script_text:
                findings.append({
                    "check": "Right-click or keyboard disabled",
                    "detail": "Page tries to disable right-click or keyboard shortcuts",
                    "severity": "Medium",
                    "explanation": "Hiding page source is a common phishing tactic to prevent inspection."
                })
                score += 25
                break

        meta_refresh = soup.find('meta', attrs={'http-equiv': lambda x: x and 'refresh' in x.lower()})
        if meta_refresh:
            findings.append({
                "check": "Auto-redirect detected",
                "detail": "Page uses meta refresh to redirect visitors",
                "severity": "High",
                "explanation": "Automatic redirects are used to quickly move victims to malicious pages."
            })
            score += 35

        # ================= NEW ADVANCED CHECKS (ADDED) =================

        parsed = urlparse(url)
        domain = parsed.netloc

        # NEW 1: Suspicious iframe usage (hidden phishing pages)
        iframes = soup.find_all("iframe")
        if len(iframes) > 2:
            findings.append({
                "check": "Multiple iframes detected",
                "detail": f"{len(iframes)} iframes found",
                "severity": "Medium",
                "explanation": "Phishing pages often use hidden iframes to load malicious content."
            })
            score += 15

        # NEW 2: External scripts (possible malicious JS)
        external_scripts = [s for s in soup.find_all("script", src=True) if domain not in s['src']]
        if len(external_scripts) > 3:
            findings.append({
                "check": "Multiple external scripts",
                "detail": f"{len(external_scripts)} external scripts loaded",
                "severity": "Medium",
                "explanation": "Loading many external scripts can indicate injected or malicious content."
            })
            score += 15

        # NEW 3: Suspicious title (common phishing patterns)
        if soup.title:
            title_text = soup.title.string.lower()
            suspicious_title_words = ["login", "verify", "update", "secure", "account"]
            if any(word in title_text for word in suspicious_title_words):
                findings.append({
                    "check": "Suspicious page title",
                    "detail": f"Title: {soup.title.string}",
                    "severity": "Low",
                    "explanation": "Phishing pages often use urgent or security-related titles."
                })
                score += 10

        # NEW 4: Favicon from external domain
        favicon = soup.find("link", rel=lambda x: x and "icon" in x.lower())
        if favicon and "href" in favicon.attrs:
            if domain not in favicon["href"]:
                findings.append({
                    "check": "External favicon source",
                    "detail": f"Favicon loaded from: {favicon['href']}",
                    "severity": "Low",
                    "explanation": "Phishing sites sometimes load assets from external sources to mimic brands."
                })
                score += 10

        # NEW 5: Excessive input fields (data harvesting)
        inputs = soup.find_all("input")
        if len(inputs) > 10:
            findings.append({
                "check": "Excessive input fields",
                "detail": f"{len(inputs)} input fields detected",
                "severity": "Medium",
                "explanation": "Phishing pages often request too much user information."
            })
            score += 20

    except requests.exceptions.ConnectionError:
        findings.append({
            "check": "Connection failed",
            "detail": "Could not connect to the website",
            "severity": "Info",
            "explanation": "The website may be down or the URL may be incorrect."
        })

    except Exception as e:
        findings.append({
            "check": "Analysis error",
            "detail": str(e),
            "severity": "Info",
            "explanation": "Could not fully analyse this page."
        })

    return {
        "findings": findings,
        "score": min(score, 100),
        "total_checks": 11,  # updated
        "flags_found": len(findings)
    }