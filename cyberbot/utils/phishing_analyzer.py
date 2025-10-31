def analyze_message(text):
    suspicious_keywords = [
        "urgent", "verify", "password", "bank", "account locked",
        "click here", "update now", "win", "lottery", "otp"
    ]

    found = [w for w in suspicious_keywords if w in text.lower()]
    
    result = {
        "keywords": found,
        "is_suspicious": len(found) > 0
    }

    return result
