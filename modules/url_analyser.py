import re
from urllib.parse import urlparse
from config import PROTECTED_BRANDS

def analyse_url(url):
    """Analyse a URL for phishing indicators."""
    findings = []
    score = 0

    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        full_url = url.lower()

        # Check 1: Is an IP address used instead of a domain name?
        # Phishers use IPs to avoid creating traceable domain names
        ip_pattern = re.compile(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
        if ip_pattern.match(domain):
            findings.append({
                "check": "IP address used as domain",
                "detail": f"URL uses IP address: {domain}",
                "severity": "High",
                "explanation": "Legitimate websites use domain names, not IP addresses."
            })
            score += 30

        # Check 2: Is the URL excessively long?
        # Phishers stuff URLs with extra text to hide the real domain
        if len(url) > 75:
            findings.append({
                "check": "Excessively long URL",
                "detail": f"URL length: {len(url)} characters",
                "severity": "Medium",
                "explanation": "Very long URLs are often used to confuse users about the real destination."
            })
            score += 15

        # Check 3: Too many hyphens in domain?
        # Phishers use hyphens to fake domains e.g. paypal-secure-login.com
        hyphen_count = domain.count('-')
        if hyphen_count >= 3:
            findings.append({
                "check": "Excessive hyphens in domain",
                "detail": f"Found {hyphen_count} hyphens in domain: {domain}",
                "severity": "Medium",
                "explanation": "Multiple hyphens are a common trick to make fake domains look legitimate."
            })
            score += 20

        # Check 4: Too many subdomains?
        # e.g. paypal.login.verify.evil.com — the real domain is evil.com
        subdomain_count = domain.count('.')
        if subdomain_count >= 4:
            findings.append({
                "check": "Too many subdomains",
                "detail": f"Domain has {subdomain_count} dots: {domain}",
                "severity": "High",
                "explanation": "Excessive subdomains are used to make malicious domains appear legitimate."
            })
            score += 25

        # Check 5: Is HTTPS used?
        # Not having HTTPS is a red flag (though having it doesn't mean safe)
        if parsed.scheme != "https":
            findings.append({
                "check": "No HTTPS",
                "detail": "Website does not use HTTPS encryption",
                "severity": "Medium",
                "explanation": "Legitimate sites almost always use HTTPS. HTTP sites can intercept your data."
            })
            score += 15

        # Check 6: Brand name in URL but domain doesn't belong to that brand?
        # e.g. paypal-login.com contains "paypal" but isn't paypal.com
        for brand in PROTECTED_BRANDS:
            if brand in full_url:
                # Check if the actual domain IS the brand's real domain
                if not domain.endswith(f"{brand}.com") and not domain.endswith(f"{brand}.co.uk"):
                    findings.append({
                        "check": "Brand name hijacking",
                        "detail": f"'{brand}' appears in URL but domain is: {domain}",
                        "severity": "High",
                        "explanation": f"The URL mentions '{brand}' but doesn't belong to their official domain."
                    })
                    score += 35
                    break

        # Check 7: Suspicious characters in URL
        # @ symbol in URL can be used to trick browsers
        if "@" in url:
            findings.append({
                "check": "@ symbol in URL",
                "detail": "URL contains @ symbol",
                "severity": "High",
                "explanation": "The @ symbol in URLs can redirect browsers to a completely different address."
            })
            score += 30

    except Exception as e:
        findings.append({
            "check": "Analysis error",
            "detail": str(e),
            "severity": "Info",
            "explanation": "Could not fully analyse this URL."
        })

    return {
        "findings": findings,
        "score": min(score, 100),
        "total_checks": 7,
        "flags_found": len(findings)
    }