import requests
from bs4 import BeautifulSoup
import urllib3
import re
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from config import REQUEST_TIMEOUT

# Extended brand list with official domains
BRAND_PROFILES = {
    "paypal":     ["paypal.com", "paypal.co.uk"],
    "google":     ["google.com", "google.co.uk", "gmail.com"],
    "apple":      ["apple.com", "icloud.com"],
    "microsoft":  ["microsoft.com", "live.com", "outlook.com", "office.com"],
    "facebook":   ["facebook.com", "fb.com", "meta.com"],
    "amazon":     ["amazon.com", "amazon.co.uk", "aws.amazon.com"],
    "netflix":    ["netflix.com"],
    "instagram":  ["instagram.com"],
    "twitter":    ["twitter.com", "x.com"],
    "linkedin":   ["linkedin.com"],
    "dropbox":    ["dropbox.com"],
    "yahoo":      ["yahoo.com", "yahoo.co.uk"],
    "ebay":       ["ebay.com", "ebay.co.uk"],
    "steam":      ["steampowered.com", "steamcommunity.com"],
    "netflix":    ["netflix.com"],
    "wellsfargo": ["wellsfargo.com"],
    "chase":      ["chase.com"],
    "barclays":   ["barclays.com", "barclays.co.uk"],
    "hsbc":       ["hsbc.com", "hsbc.co.uk"],
    "bankofamerica": ["bankofamerica.com"],
    "citibank":   ["citibank.com", "citi.com"],
    "dhl":        ["dhl.com", "dhl.co.uk"],
    "fedex":      ["fedex.com"],
    "ups":        ["ups.com"],
    "netflix":    ["netflix.com"],
    "spotify":    ["spotify.com"],
    "adobe":      ["adobe.com"],
    "docusign":   ["docusign.com"],
}

# Typosquatting patterns for top brands
TYPOSQUAT_PATTERNS = {
    "paypal":    ["paypa1", "paypai", "payp-al", "pay-pal", "paypall"],
    "google":    ["g00gle", "gooogle", "googie", "g0ogle"],
    "apple":     ["app1e", "appie", "aplle"],
    "microsoft": ["microsoift", "micros0ft", "microsoftt"],
    "facebook":  ["faceb00k", "facebok", "faceboок"],
    "amazon":    ["amaz0n", "amazoon", "arnazon"],
    "netflix":   ["netf1ix", "netlfix", "netfliix"],
}

def check_brand_impersonation(url):
    """Enhanced brand impersonation checker with proof-based scoring."""
    findings = []
    score = 0

    try:
        parsed_domain = url.lower().split('/')[2] if '//' in url else url.lower()
        full_url = url.lower()

        # ── CHECK 1: Brand keyword in URL but wrong domain ──
        for brand, official_domains in BRAND_PROFILES.items():
            if brand in full_url:
                is_official = any(
                    parsed_domain == od or parsed_domain.endswith('.' + od)
                    for od in official_domains
                )
                if not is_official:
                    points = 40
                    findings.append({
                        "check": f"Brand impersonation — {brand.capitalize()}",
                        "detail": f"URL contains '{brand}' but domain '{parsed_domain}' is not an official {brand.capitalize()} domain",
                        "severity": "High",
                        "points": points,
                        "explanation": f"[+{points} pts] The URL mentions '{brand.capitalize()}' but doesn't belong to their official domain ({', '.join(official_domains)}). This is a classic phishing technique."
                    })
                    score += points
                    break

        # ── CHECK 2: Typosquatting detection ──
        for brand, typos in TYPOSQUAT_PATTERNS.items():
            for typo in typos:
                if typo in parsed_domain:
                    points = 50
                    findings.append({
                        "check": f"Typosquatting detected — fake '{brand.capitalize()}'",
                        "detail": f"Domain '{parsed_domain}' uses '{typo}' to impersonate {brand.capitalize()}",
                        "severity": "High",
                        "points": points,
                        "explanation": f"[+{points} pts] The domain uses a deliberate misspelling of '{brand.capitalize()}' to trick users into thinking it's legitimate."
                    })
                    score += points
                    break

        # ── CHECK 3: Multiple brand names in one URL ──
        brands_found = [b for b in BRAND_PROFILES.keys() if b in full_url]
        if len(brands_found) >= 2:
            points = 35
            findings.append({
                "check": "Multiple brand names in URL",
                "detail": f"URL mentions these brands: {', '.join(brands_found)}",
                "severity": "High",
                "points": points,
                "explanation": f"[+{points} pts] Legitimate websites don't mention multiple competing brands in their URL. This is a strong phishing indicator."
            })
            score += points

        # ── NOW VISIT THE PAGE ───────────────────────────────
        headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"}
        response = requests.get(url, timeout=REQUEST_TIMEOUT, headers=headers, verify=False)
        soup = BeautifulSoup(response.text, 'html.parser')
        page_text = soup.get_text().lower()

        # ── CHECK 4: Page title brand mismatch ──
        title_tag = soup.find('title')
        if title_tag:
            title = title_tag.get_text().lower()
            for brand, official_domains in BRAND_PROFILES.items():
                if brand in title:
                    is_official = any(
                        parsed_domain == od or parsed_domain.endswith('.' + od)
                        for od in official_domains
                    )
                    if not is_official:
                        points = 45
                        findings.append({
                            "check": f"Page title impersonates {brand.capitalize()}",
                            "detail": f"Page title contains '{brand}' but domain is '{parsed_domain}'",
                            "severity": "High",
                            "points": points,
                            "explanation": f"[+{points} pts] The page title claims to be {brand.capitalize()} but the domain doesn't belong to them."
                        })
                        score += points
                        break

        # ── CHECK 5: Urgency language ──
        urgency_phrases = [
            "verify your account", "account suspended", "unusual activity",
            "confirm your identity", "immediate action required",
            "your account will be closed", "click here now",
            "limited time", "act now", "expires today",
            "unauthorized access", "security alert"
        ]
        found_urgency = [p for p in urgency_phrases if p in page_text]
        if found_urgency:
            points = 20 * min(len(found_urgency), 2)
            findings.append({
                "check": "Urgency language detected",
                "detail": f"Found phrases: {', '.join(found_urgency[:3])}",
                "severity": "Medium",
                "points": points,
                "explanation": f"[+{points} pts] Page uses urgency tactics to pressure victims into acting without thinking — a hallmark of phishing."
            })
            score += points

        # ── CHECK 6: Logo/image from official brand CDN ──
        images = soup.find_all('img', src=True)
        for img in images:
            src = img.get('src', '').lower()
            for brand in BRAND_PROFILES.keys():
                if brand in src and not any(
                    parsed_domain == od or parsed_domain.endswith('.' + od)
                    for od in BRAND_PROFILES.get(brand, [])
                ):
                    points = 30
                    findings.append({
                        "check": f"Stolen brand logo detected",
                        "detail": f"Page loads {brand.capitalize()} logo/image but isn't on their official domain",
                        "severity": "High",
                        "points": points,
                        "explanation": f"[+{points} pts] The page is using {brand.capitalize()}'s official images/logos to appear legitimate."
                    })
                    score += points
                    break

    except requests.exceptions.ConnectionError:
        findings.append({
            "check": "Page unreachable",
            "detail": "Could not connect to the website",
            "severity": "Info",
            "points": 0,
            "explanation": "[+0 pts] The website may be down or the URL is fake — URL-level analysis still applied."
        })

    except Exception as e:
        findings.append({
            "check": "Analysis error",
            "detail": str(e),
            "severity": "Info",
            "points": 0,
            "explanation": "[+0 pts] Could not fully analyse this page."
        })

    return {
        "findings": findings,
        "score": min(score, 100),
        "total_checks": 6,
        "flags_found": len(findings)
    }