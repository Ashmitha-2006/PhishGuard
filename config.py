import os
from dotenv import load_dotenv

load_dotenv()

REQUEST_TIMEOUT = 10

PROTECTED_BRANDS = [
    "google", "paypal", "apple", "microsoft", "facebook",
    "amazon", "netflix", "instagram", "twitter", "bank",
    "wellsfargo", "chase", "barclays", "hsbc", "ebay",
    "linkedin", "dropbox", "yahoo", "outlook", "steam"
]

SUSPICIOUS_KEYWORDS = [
    "login", "verify", "update", "secure", "account",
    "banking", "confirm", "password", "credential", "suspended",
    "unusual", "alert", "urgent", "immediately", "click here"
]