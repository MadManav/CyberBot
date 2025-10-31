import re
import pickle
import os
from urllib.parse import urlparse
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from .url_check import extract_domain, check_domain_age

# Path to save the model
MODEL_PATH = os.path.join(os.path.dirname(__file__), 'phishing_model.pkl')
VECTORIZER_PATH = os.path.join(os.path.dirname(__file__), 'vectorizer.pkl')

# Initialize or load model
def load_or_train_model():
    """Load existing model or train a new one"""
    if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
        with open(MODEL_PATH, 'rb') as f:
            model = pickle.load(f)
        with open(VECTORIZER_PATH, 'rb') as f:
            vectorizer = pickle.load(f)
        print("✅ Loaded existing model")
        return model, vectorizer
    
    # Training data: (text, label) - 1 = phishing, 0 = legitimate
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
    ]
    
    texts = [item[0] for item in training_data]
    labels = [item[1] for item in training_data]
    
    # Vectorize text
    vectorizer = TfidfVectorizer(max_features=100, lowercase=True)
    X = vectorizer.fit_transform(texts)
    
    # Train Random Forest
    model = RandomForestClassifier(n_estimators=100, random_state=42, max_depth=10)
    model.fit(X, labels)
    
    # Save model and vectorizer
    with open(MODEL_PATH, 'wb') as f:
        pickle.dump(model, f)
    with open(VECTORIZER_PATH, 'wb') as f:
        pickle.dump(vectorizer, f)
    
    print("✅ Trained and saved new model")
    return model, vectorizer

# Load model globally
try:
    rf_model, tfidf_vectorizer = load_or_train_model()
except Exception as e:
    print(f"⚠️ Error loading model: {str(e)}")
    rf_model, tfidf_vectorizer = None, None

# Keyword patterns for feature extraction
PHISHING_KEYWORDS = [
    'verify', 'confirm', 'urgent', 'act now', 'claim', 'update',
    'suspended', 'locked', 'click here', 'reset password', 'win',
    'prize', 'congratulations', 'limited time', 'expire', 'alert'
]

def extract_url_features(url):
    """Extract features from URL"""
    features = {}
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        
        features['has_ip'] = bool(re.match(r'^(\d+\.){3}\d+', domain))
        features['has_https'] = url.startswith('https://')
        features['domain_length'] = len(domain)
        features['has_suspicious_chars'] = bool(re.search(r'[@!#$%^&*]', domain))
        features['is_shortened'] = any(x in domain for x in ['bit.ly', 'tinyurl', 'short', 'ow.ly'])
        
        # Check for suspicious domain patterns
        suspicious_patterns = [
            r'secure', r'login', r'auth', r'verify', r'account', r'bank', r'confirm',
            r'update', r'verify', r'status', r'track', r'delivery', r'package'
        ]
        
        # Check for suspicious TLDs
        suspicious_tlds = ['.co', '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.info', '.top', '.cc']
        
        # Check for hyphens in domain (common in phishing)
        features['has_hyphens'] = '-' in domain
        
        # Check for multiple hyphens (very suspicious)
        features['has_multiple_hyphens'] = domain.count('-') > 1
        
        # Check for suspicious domain patterns
        features['has_suspicious_keywords'] = any(re.search(pattern, domain) for pattern in suspicious_patterns)
        
        # Check for suspicious TLDs
        features['has_suspicious_tld'] = any(domain.endswith(tld) for tld in suspicious_tlds)
        
        # Check for numbers in domain (often suspicious)
        features['has_numbers_in_domain'] = bool(re.search(r'\d', domain))
        
        # Check for typosquatting (similar to known domains)
        known_domains = ['google', 'amazon', 'facebook', 'microsoft', 'apple', 'paypal', 'bank']
        features['typosquatted'] = any(
            sim in domain.lower() and sim != domain.split('.')[0].lower() 
            for sim in known_domains
        )
        
        # Check domain age
        domain_info = check_domain_age(domain)
        features['is_new_domain'] = domain_info.get('is_new', False)
        features['domain_age_days'] = domain_info.get('age_days', 0)
        
    except Exception as e:
        print(f"Error extracting URL features: {str(e)}")
        features = {k: False for k in ['has_ip', 'has_https', 'has_suspicious_chars', 'is_shortened', 
                                      'typosquatted', 'is_new_domain', 'has_hyphens', 
                                      'has_multiple_hyphens', 'has_suspicious_keywords',
                                      'has_suspicious_tld', 'has_numbers_in_domain']}
        features['domain_length'] = 0
        features['domain_age_days'] = 0
    
    return features

def analyze_message(user_input):
    """
    Analyze message using Random Forest + keyword analysis
    
    Returns:
        dict: Analysis results with phishing probability (all JSON serializable)
    """
    if not user_input or not isinstance(user_input, str):
        return {"error": "Invalid input", "is_suspicious": False}
    
    analysis = {
        "message": user_input[:100],
        "keywords": [],
        "is_suspicious": False,  # Will be converted to bool for JSON
        "confidence": 0.0,
        "url_domain": None,
        "is_shortened": False,
        "reputation_score": 0.5,
        "ml_score": 0.0,
        "method": "keyword_analysis"
    }
    
    # Extract URL if present
    url_match = re.search(r'https?://[^\s]+', user_input)
    if url_match:
        url = url_match.group(0)
        analysis["url_domain"] = str(urlparse(url).netloc)
        url_features = extract_url_features(url)
        
        # URL-based scoring
        url_score = 0.0
        
        # Basic security features
        if url_features['has_ip']: 
            url_score += 0.3
            analysis["keywords"].append("IP address in URL")
        if not url_features['has_https']: 
            url_score += 0.2
            analysis["keywords"].append("No HTTPS")
        if url_features['is_shortened']: 
            url_score += 0.25
            analysis["keywords"].append("URL shortener")
        if url_features['has_suspicious_chars']: 
            url_score += 0.15
            analysis["keywords"].append("Suspicious characters")
        if url_features['typosquatted']: 
            url_score += 0.4
            analysis["keywords"].append("Typosquatting attempt")
            
        # Enhanced detection features
        if url_features.get('has_hyphens', False):
            url_score += 0.15
            if url_features.get('has_multiple_hyphens', False):
                url_score += 0.15
                analysis["keywords"].append("Multiple hyphens in domain")
        
        if url_features.get('has_suspicious_keywords', False):
            url_score += 0.35
            analysis["keywords"].append("Suspicious keywords in domain")
            
        if url_features.get('has_suspicious_tld', False):
            url_score += 0.25
            analysis["keywords"].append("Suspicious TLD")
            
        if url_features.get('has_numbers_in_domain', False):
            url_score += 0.15
            
        if url_features.get('is_new_domain', False):
            url_score += 0.35
            analysis["keywords"].append("Newly registered domain")
        
        # Store feature results in analysis
        analysis["is_shortened"] = bool(url_features['is_shortened'])
        analysis["is_new_domain"] = bool(url_features.get('is_new_domain', False))
        domain_age = url_features.get('domain_age_days')
        analysis["domain_age_days"] = int(domain_age) if domain_age is not None else 0
        
        # Calculate reputation score (inverse of suspicion score)
        analysis["reputation_score"] = float(max(0, 1 - url_score))
    
    # Machine Learning prediction (if model loaded)
    ml_prediction = 0.0
    if rf_model is not None and tfidf_vectorizer is not None:
        try:
            X_text = tfidf_vectorizer.transform([user_input])
            ml_prediction = float(rf_model.predict_proba(X_text)[0][1])  # Probability of phishing
            analysis["ml_score"] = ml_prediction
            analysis["method"] = "random_forest"
        except Exception as e:
            print(f"ML prediction error: {str(e)}")
            ml_prediction = 0.0
    
    # Extract keywords
    lower_input = user_input.lower()
    detected_keywords = [str(kw) for kw in PHISHING_KEYWORDS if kw in lower_input]
    
    # Add URL-based keywords to the main keywords list
    if "keywords" in analysis and isinstance(analysis["keywords"], list):
        detected_keywords.extend([kw for kw in analysis["keywords"] if kw not in detected_keywords])
    
    analysis["keywords"] = detected_keywords
    
    # Keyword-based scoring
    keyword_score = float(min(len(detected_keywords) * 0.15, 0.6))
    
    # Get URL score from reputation_score (which is inverse of url_score)
    url_score = 0.0
    if "reputation_score" in analysis:
        url_score = float(1.0 - analysis["reputation_score"])
    
    # Combine scores: 40% ML, 30% keyword, 30% URL
    combined_score = float((ml_prediction * 0.4) + (keyword_score * 0.3) + (url_score * 0.3))
    
    # Decision threshold
    analysis["confidence"] = combined_score
    analysis["is_suspicious"] = bool(combined_score > 0.5 or url_score > 0.7)  # Ensure it's a Python bool
    
    # Ensure all values are JSON serializable
    analysis["message"] = str(analysis["message"])
    analysis["url_domain"] = str(analysis["url_domain"]) if analysis["url_domain"] else None
    analysis["method"] = str(analysis["method"])
    
    return analysis