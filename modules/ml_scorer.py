import re
from urllib.parse import urlparse

# Known legitimate domains — these get a clean pass
WHITELIST = [
    "google.com", "youtube.com", "facebook.com", "amazon.com",
    "microsoft.com", "apple.com", "twitter.com", "instagram.com",
    "linkedin.com", "github.com", "wikipedia.org", "reddit.com",
    "netflix.com", "spotify.com", "paypal.com", "ebay.com",
    "bbc.com", "bbc.co.uk", "cnn.com", "nytimes.com",
]

# Known phishing keywords — strong signals
PHISHING_KEYWORDS = [
    "login", "verify", "secure", "account", "update", "confirm",
    "banking", "password", "credential", "suspended", "unusual",
    "alert", "urgent", "immediately", "validate", "authenticate",
    "signin", "sign-in", "log-in", "logon", "webscr", "cmd=",
    "ebayisapi", "paypal", "phishing", "free", "lucky", "winner",
    "prize", "claim", "limited", "expire", "billing"
]

def extract_features(url):
    """Extract numerical features from URL for ML scoring."""
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()
    full_url = url.lower()

    features = {
        "url_length":        len(url),
        "domain_length":     len(domain),
        "hyphen_count":      url.count('-'),
        "dot_count":         url.count('.'),
        "slash_count":       url.count('/'),
        "at_symbol":         1 if '@' in url else 0,
        "has_https":         1 if parsed.scheme == 'https' else 0,
        "is_ip":             1 if re.match(r'^\d+\.\d+\.\d+\.\d+', domain) else 0,
        "path_length":       len(path),
        "subdomain_count":   domain.count('.'),
        "has_login":         1 if 'login' in full_url else 0,
        "has_verify":        1 if 'verify' in full_url else 0,
        "has_secure":        1 if 'secure' in full_url else 0,
        "has_account":       1 if 'account' in full_url else 0,
        "has_update":        1 if 'update' in full_url else 0,
        "has_bank":          1 if 'bank' in full_url else 0,
        "has_paypal":        1 if 'paypal' in full_url else 0,
        "has_free":          1 if 'free' in full_url else 0,
        "has_confirm":       1 if 'confirm' in full_url else 0,
        "domain_hyphens":    domain.count('-'),
        "query_params":      len(parsed.query.split('&')) if parsed.query else 0,
        "has_double_slash":  1 if '//' in path else 0,
        "keyword_count":     sum(1 for kw in PHISHING_KEYWORDS if kw in full_url),
    }
    return features

def get_ml_score(url, model=None, scaler=None):
    """Get ML-based phishing probability with proof."""

    parsed = urlparse(url)
    domain = parsed.netloc.lower()

    # Whitelist check — known safe domains
    for safe in WHITELIST:
        if domain == safe or domain.endswith('.' + safe):
            return {
                "score": 0,
                "method": "Whitelist — verified safe domain",
                "confidence": "High",
                "proof": f"[+0 pts] Domain '{domain}' is a verified legitimate domain"
            }

    features = extract_features(url)
    score = 0
    proof_points = []

    # URL length scoring
    if features["url_length"] > 100:
        pts = 20
        score += pts
        proof_points.append(f"[+{pts}] URL is very long ({features['url_length']} chars — typically phishing)")
    elif features["url_length"] > 75:
        pts = 10
        score += pts
        proof_points.append(f"[+{pts}] URL is suspiciously long ({features['url_length']} chars)")

    # IP address
    if features["is_ip"]:
        pts = 35
        score += pts
        proof_points.append(f"[+{pts}] IP address used instead of domain name")

    # No HTTPS
    if not features["has_https"]:
        pts = 20
        score += pts
        proof_points.append(f"[+{pts}] No HTTPS encryption")

    # @ symbol
    if features["at_symbol"]:
        pts = 30
        score += pts
        proof_points.append(f"[+{pts}] @ symbol in URL — can redirect to malicious site")

    # Excessive hyphens
    if features["hyphen_count"] >= 4:
        pts = 15
        score += pts
        proof_points.append(f"[+{pts}] {features['hyphen_count']} hyphens in URL — common phishing pattern")
    elif features["hyphen_count"] >= 2:
        pts = 8
        score += pts
        proof_points.append(f"[+{pts}] Multiple hyphens in URL")

    # Excessive subdomains
    if features["subdomain_count"] >= 4:
        pts = 20
        score += pts
        proof_points.append(f"[+{pts}] {features['subdomain_count']} subdomains — used to hide real domain")
    elif features["subdomain_count"] >= 3:
        pts = 10
        score += pts
        proof_points.append(f"[+{pts}] Multiple subdomains detected")

    # Phishing keywords
    kw_count = features["keyword_count"]
    if kw_count >= 3:
        pts = 25
        score += pts
        proof_points.append(f"[+{pts}] {kw_count} phishing keywords found in URL")
    elif kw_count >= 1:
        pts = kw_count * 8
        score += pts
        proof_points.append(f"[+{pts}] {kw_count} suspicious keyword(s) in URL")

    # Double slash in path
    if features["has_double_slash"]:
        pts = 15
        score += pts
        proof_points.append(f"[+{pts}] Double slash in URL path — redirection trick")

    # High query params
    if features["query_params"] > 5:
        pts = 10
        score += pts
        proof_points.append(f"[+{pts}] {features['query_params']} query parameters — hiding destination")

    final_score = min(score, 100)
    proof_summary = " | ".join(proof_points) if proof_points else "No suspicious patterns detected"

    return {
        "score": final_score,
        "method": "Rule-based ML scoring",
        "confidence": "High" if final_score > 50 else "Medium",
        "proof": proof_summary
    }