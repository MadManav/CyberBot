import re
import pickle
import os
import logging
import difflib
from urllib.parse import urlparse
import numpy as np
import tldextract
from functools import lru_cache
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from .url_check import check_domain_age

# -----------------------------------------------------
# Setup logging
# -----------------------------------------------------
logging.basicConfig(filename="phishing_analysis.log", level=logging.WARNING)

MODEL_PATH = os.path.join(os.path.dirname(__file__), 'phishing_model.pkl')
VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), 'vectorizer.pkl')


# -----------------------------------------------------
# Safe domain lookup
# -----------------------------------------------------
def safe_domain_lookup(url):
    try:
        extracted = tldextract.extract(url)
        domain = f"{extracted.domain}.{extracted.suffix}" if extracted.suffix else extracted.domain
        if not domain:
            return {"is_new": True, "age_days": 0}
        info = check_domain_age(domain)
        if info.get("error"):
            info["is_new"] = True
            info["age_days"] = 0
        return info
    except Exception as e:
        return {"is_new": True, "age_days": 0, "error": str(e)}


# -----------------------------------------------------
# Model load or train
# -----------------------------------------------------
def load_or_train_model():
    if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
        with open(MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
        with open(VECTORIZER_PATH, 'rb') as f:
            vectorizer = pickle.load(f)
        print("✅ Loaded existing phishing model")
        return model, vectorizer

    # Training samples
    training_data = [
        ("Click here to verify your account urgently", 1),
        ("Confirm your password immediately", 1),
        ("You've won a prize! Claim now", 1),
        ("Suspicious activity detected. Update payment info", 1),
        ("URGENT: Act now or account will be closed", 1),
        ("Verify your identity by clicking this link", 1),
        ("Welcome to our newsletter", 0),
        ("Here's your order confirmation", 0),
        ("Check out our latest products", 0),
        ("Thank you for subscribing", 0),
        ("Your account has been limited, verify immediately", 1),
        ("Login to view your invoice", 1),
        ("Payment failed, update details", 1),
        ("Download your secure file here", 1),
        ("Meeting tomorrow at 10AM", 0),
        ("Reminder: complete project submission", 0),
        ("Your OTP for login is 123456", 0),
        ("Hi, let's schedule a call", 0),
    ]

    texts = [t for t, _ in training_data]
    labels = [l for _, l in training_data]
    vectorizer = TfidfVectorizer(max_features=100, lowercase=True)
    X = vectorizer.fit_transform(texts)
    model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
    model.fit(X, labels)

    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    with open(VECTORIZER_PATH, 'wb') as f:
        pickle.dump(vectorizer, f)
    print("✅ Trained and saved new phishing model")
    return model, vectorizer


rf_model, tfidf_vectorizer = load_or_train_model()


# -----------------------------------------------------
# Phishing-related keyword list
# -----------------------------------------------------
PHISHING_KEYWORDS = list(set([
    'verify', 'confirm', 'urgent', 'act now', 'claim', 'update', 'suspended', 'locked',
    'click here', 'reset password', 'win', 'prize', 'congratulations', 'limited time',
    'expire', 'alert', 'payment', 'invoice', 'transaction', 'bank', 'security', 'blocked',
    'lottery', 'verify identity', 'free', 'credit card', 'paypal'
]))


# -----------------------------------------------------
# Domain feature extraction
# -----------------------------------------------------
@lru_cache(maxsize=200)
def cached_check_domain_age(domain):
    return check_domain_age(domain)


def extract_url_features(url):
    features = {}
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        extracted = tldextract.extract(domain)
        domain_base = extracted.domain
        domain_info = safe_domain_lookup(domain)

        features['has_ip'] = bool(re.match(r'^(\d+\.){3}\d+', domain))
        features['has_https'] = url.startswith('https://')
        features['domain_length'] = len(domain)
        features['has_suspicious_chars'] = bool(re.search(r'[@!#$%^&*]', domain))
        features['is_shortened'] = any(x in domain for x in ['bit.ly', 'tinyurl', 'short', 'ow.ly'])

        suspicious_patterns = [r'secure', r'login', r'auth', r'verify', r'account', r'bank', r'confirm']
        suspicious_tlds = ['.co', '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.info', '.top', '.cc']

        features['has_hyphens'] = '-' in domain
        features['has_multiple_hyphens'] = domain.count('-') > 1
        features['has_suspicious_keywords'] = any(re.search(p, domain) for p in suspicious_patterns)
        features['has_suspicious_tld'] = any(domain.endswith(t) for t in suspicious_tlds)
        features['has_numbers_in_domain'] = bool(re.search(r'\d', domain))

        # ✅ Typosquat / Brand Similarity Detection
        known_brands = ['google', 'amazon', 'facebook', 'microsoft', 'apple', 'paypal', 'bank', 'instagram', 'twitter']
        similarity_scores = [difflib.SequenceMatcher(None, domain_base, brand).ratio() for brand in known_brands]
        features['typosquatted'] = any(score > 0.75 for score in similarity_scores)

        features['is_new_domain'] = domain_info.get('is_new', False)
        features['domain_age_days'] = domain_info.get('age_days', 0)

    except Exception as e:
        logging.warning(f"Error extracting URL features: {e}")
        features = {k: False for k in [
            'has_ip', 'has_https', 'has_suspicious_chars', 'is_shortened', 'typosquatted',
            'is_new_domain', 'has_hyphens', 'has_multiple_hyphens', 'has_suspicious_keywords',
            'has_suspicious_tld', 'has_numbers_in_domain'
        ]}
        features['domain_length'] = 0
        features['domain_age_days'] = 0
    return features


# -----------------------------------------------------
# Input classification helper
# -----------------------------------------------------
def classify_input_type(text):
    text = text.lower().strip()
    if re.search(r'https?://', text):
        return "url"
    elif any(w in text for w in ["how to", "steps to", "what is", "generate", "make me", "create"]):
        return "instruction"
    elif any(w in text for w in ["hi", "hello", "thanks", "ok", "bye"]):
        return "simple_response"
    else:
        return "message"


# -----------------------------------------------------
# Main analyzer
# -----------------------------------------------------
def analyze_message(user_input):
    try:
        if not user_input or not isinstance(user_input, str):
            return {"error": "Invalid input", "is_suspicious": False}

        analysis = {
            "message": user_input[:100],
            "keywords": [],
            "is_suspicious": False,
            "confidence": 0.0,
            "url_domain": None,
            "is_shortened": False,
            "reputation_score": 0.5,
            "ml_score": 0.0,
            "method": "keyword_analysis"
        }
        analysis["input_type"] = classify_input_type(user_input)

        # Extract URL (if present)
        url_match = re.search(r'https?://[^\s]+', user_input)
        if url_match:
            url = url_match.group(0)
            analysis["url_domain"] = str(urlparse(url).netloc)
            url_features = extract_url_features(url)
            url_score = 0.0
            if url_features['has_ip']: url_score += 0.3
            if not url_features['has_https']: url_score += 0.2
            if url_features['is_shortened']: url_score += 0.25
            if url_features['has_suspicious_chars']: url_score += 0.15
            if url_features['typosquatted']: url_score += 0.45
            if url_features['has_hyphens']: url_score += 0.1
            if url_features['has_multiple_hyphens']: url_score += 0.15
            if url_features['has_suspicious_keywords']: url_score += 0.35
            if url_features['has_suspicious_tld']: url_score += 0.25
            if url_features['has_numbers_in_domain']: url_score += 0.15
            if url_features['is_new_domain']: url_score += 0.35
            analysis["reputation_score"] = max(0, 1 - url_score)

        # ML prediction
        ml_prediction = 0.0
        if rf_model and tfidf_vectorizer:
            X_text = tfidf_vectorizer.transform([user_input])
            ml_prediction = float(rf_model.predict_proba(X_text)[0][1])
            analysis["ml_score"] = ml_prediction
            analysis["method"] = "random_forest"

        # Keyword scoring
        detected_keywords = [kw for kw in PHISHING_KEYWORDS if kw in user_input.lower()]
        keyword_score = min(len(detected_keywords) * 0.15, 0.6)
        url_score = 1.0 - analysis["reputation_score"]
        combined_score = np.clip((ml_prediction * 0.5) + (keyword_score * 0.25) + (url_score * 0.25), 0, 1)
        analysis["confidence"] = round(float(combined_score), 2)
        analysis["is_suspicious"] = combined_score > 0.6
        analysis["keywords"] = detected_keywords

        return {
            "input": user_input,
            "type": analysis["input_type"],
            "is_suspicious": analysis["is_suspicious"],
            "confidence": analysis["confidence"],
            "keywords": analysis["keywords"],
            "url_info": {
                "domain": analysis["url_domain"],
                "reputation_score": analysis["reputation_score"]
            },
            "ml_score": analysis["ml_score"]
        }

    except Exception as e:
        logging.warning(f"Error in analyze_message: {e}")
        return {"error": str(e), "is_suspicious": False}
