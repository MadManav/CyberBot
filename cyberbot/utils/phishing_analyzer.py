import re
import os
from urllib.parse import urlparse
import numpy as np

# Import our new modules
from .ensemble_model import predict_phishing
from .virustotal_check import get_comprehensive_check, extract_url_from_text
from .url_check import check_domain_age, extract_domain

# Phishing keyword patterns (keep existing)
PHISHING_KEYWORDS = [
    'verify', 'confirm', 'urgent', 'act now', 'claim', 'update',
    'suspended', 'locked', 'click here', 'reset password', 'win',
    'prize', 'congratulations', 'limited time', 'expire', 'alert',
    'account suspended', 'unusual activity', 'security alert'
]


def extract_url_features(url):
    """
    Extract features from URL (KEEP YOUR EXISTING FUNCTION)
    This stays exactly as you have it - WHOIS domain age check included
    """
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
        
        # Suspicious patterns
        suspicious_patterns = [
            r'secure', r'login', r'auth', r'verify', r'account', r'bank', r'confirm',
            r'update', r'status', r'track', r'delivery', r'package'
        ]
        
        suspicious_tlds = ['.co', '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.info', '.top', '.cc']
        
        features['has_hyphens'] = '-' in domain
        features['has_multiple_hyphens'] = domain.count('-') > 1
        features['has_suspicious_keywords'] = any(re.search(pattern, domain) for pattern in suspicious_patterns)
        features['has_suspicious_tld'] = any(domain.endswith(tld) for tld in suspicious_tlds)
        features['has_numbers_in_domain'] = bool(re.search(r'\d', domain))
        
        # Typosquatting check
        known_domains = ['google', 'amazon', 'facebook', 'microsoft', 'apple', 'paypal', 'bank']
        features['typosquatted'] = any(
            sim in domain.lower() and sim != domain.split('.')[0].lower() 
            for sim in known_domains
        )
        
        # ✅ KEEP YOUR EXISTING WHOIS CHECK - This stays!
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
    🚀 NEW 3-LAYER ANALYSIS: ML Ensemble + VirusTotal + URL Features
    
    Returns:
        dict: Complete analysis with all scores (JSON serializable)
    """
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
        
        # NEW: 3-Layer Detection Scores
        "ml_ensemble_score": 0.0,      # XGBoost + RF + LR
        "virustotal_score": 0.0,        # VT score (0-10)
        "url_feature_score": 0.0,       # Your existing URL analysis
        "final_score": 0.0,             # Combined weighted score
        
        # Detection method used
        "detection_layers": [],
        "vt_details": None,
        "is_new_domain": False,
        "domain_age_days": 0
    }
    
    # ==========================================
    # LAYER 1: ML ENSEMBLE PREDICTION
    # ==========================================
    try:
        ml_score = predict_phishing(user_input)
        analysis["ml_ensemble_score"] = float(ml_score)
        analysis["detection_layers"].append("ML_Ensemble")
        print(f"🤖 ML Ensemble Score: {ml_score:.2%}")
    except Exception as e:
        print(f"⚠️  ML Ensemble error: {str(e)}")
        analysis["ml_ensemble_score"] = 0.0
    
    
    # ==========================================
    # LAYER 2: VIRUSTOTAL CHECK (if URL found)
    # ==========================================
    url_match = re.search(r'https?://[^\s]+', user_input)
    if url_match:
        url = url_match.group(0)
        analysis["url_domain"] = str(urlparse(url).netloc)
        
        try:
            # Get VirusTotal analysis
            vt_result = get_comprehensive_check(user_input)
            
            if vt_result['detected'] and not vt_result.get('error'):
                vt_score_normalized = vt_result['vt_score'] / 10.0  # Convert 0-10 to 0-1
                analysis["virustotal_score"] = float(vt_score_normalized)
                analysis["detection_layers"].append("VirusTotal")
                
                # Store VT details
                analysis["vt_details"] = {
                    "malicious": int(vt_result.get('malicious', 0)),
                    "suspicious": int(vt_result.get('suspicious', 0)),
                    "harmless": int(vt_result.get('harmless', 0)),
                    "reputation": str(vt_result.get('reputation', 'unknown'))
                }
                
                print(f"🛡️  VirusTotal Score: {vt_result['vt_score']}/10 ({vt_result['reputation']})")
                
                # Add to keywords if malicious
                if vt_result['malicious'] > 0:
                    analysis["keywords"].append(f"Flagged by {vt_result['malicious']} security engines")
            else:
                print(f"⚠️  VirusTotal: {vt_result.get('error', 'No detection')}")
                
        except Exception as e:
            print(f"⚠️  VirusTotal check failed: {str(e)}")
    
    
    # ==========================================
    # LAYER 3: URL FEATURE ANALYSIS (Your existing code + WHOIS)
    # ==========================================
    if url_match:
        url = url_match.group(0)
        url_features = extract_url_features(url)
        analysis["detection_layers"].append("URL_Features")
        
        # Calculate URL-based score
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
            analysis["is_shortened"] = True
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
        
        # ✅ WHOIS Domain Age Check (Your existing code)
        if url_features.get('is_new_domain', False):
            url_score += 0.35
            analysis["keywords"].append("Newly registered domain")
            analysis["is_new_domain"] = True
        
        domain_age = url_features.get('domain_age_days')
        analysis["domain_age_days"] = int(domain_age) if domain_age is not None else 0
        analysis["url_feature_score"] = float(min(url_score, 1.0))
        
        print(f"🔗 URL Feature Score: {url_score:.2%}")
    
    
    # ==========================================
    # KEYWORD DETECTION (Your existing code)
    # ==========================================
    lower_input = user_input.lower()
    detected_keywords = [str(kw) for kw in PHISHING_KEYWORDS if kw in lower_input]
    
    # Merge with URL keywords
    if "keywords" in analysis:
        detected_keywords.extend([kw for kw in analysis["keywords"] if kw not in detected_keywords])
    
    analysis["keywords"] = detected_keywords
    keyword_score = float(min(len(detected_keywords) * 0.15, 0.6))
    
    
    # ==========================================
    # 🎯 FINAL WEIGHTED DECISION
    # ==========================================
    # Weight distribution:
    # - VirusTotal: 50% (most reliable - real-time threat intel)
    # - ML Ensemble: 30% (trained on large dataset)
    # - URL Features: 15% (structural analysis + WHOIS)
    # - Keywords: 5% (basic pattern matching)
    
    vt_weight = 0.50
    ml_weight = 0.30
    url_weight = 0.15
    keyword_weight = 0.05
    
    # If VirusTotal detected something, prioritize it
    if analysis["virustotal_score"] > 0:
        final_score = (
            analysis["virustotal_score"] * vt_weight +
            analysis["ml_ensemble_score"] * ml_weight +
            analysis["url_feature_score"] * url_weight +
            keyword_score * keyword_weight
        )
    else:
        # No VT data, redistribute weights
        final_score = (
            analysis["ml_ensemble_score"] * 0.50 +
            analysis["url_feature_score"] * 0.35 +
            keyword_score * 0.15
        )
    
    analysis["final_score"] = float(final_score)
    analysis["confidence"] = float(final_score)  # For backward compatibility
    
    # ==========================================
    # DECISION LOGIC (as per architecture)
    # ==========================================
    # Priority 1: VirusTotal says malicious (VT score >= 5/10 = 0.5)
    if analysis["virustotal_score"] >= 0.5:
        analysis["is_suspicious"] = True
        analysis["risk_level"] = "HIGH"
        
    # Priority 2: ML Ensemble high confidence (>0.75)
    elif analysis["ml_ensemble_score"] > 0.75:
        analysis["is_suspicious"] = True
        analysis["risk_level"] = "HIGH"
        
    # Priority 3: Combined score moderate-high (>0.5)
    elif final_score > 0.5:
        analysis["is_suspicious"] = True
        analysis["risk_level"] = "MEDIUM"
        
    # Safe
    else:
        analysis["is_suspicious"] = False
        analysis["risk_level"] = "LOW"
    
    
    # ==========================================
    # LOGGING & RETURN
    # ==========================================
    print(f"\n📊 FINAL ANALYSIS:")
    print(f"   Detection Layers: {', '.join(analysis['detection_layers'])}")
    print(f"   ML Score: {analysis['ml_ensemble_score']:.2%}")
    print(f"   VT Score: {analysis['virustotal_score']:.2%}")
    print(f"   URL Score: {analysis['url_feature_score']:.2%}")
    print(f"   Final Score: {analysis['final_score']:.2%}")
    print(f"   Decision: {'⚠️  PHISHING' if analysis['is_suspicious'] else '✅ SAFE'}")
    print(f"   Risk Level: {analysis['risk_level']}\n")
    
    # Ensure JSON serializable
    analysis["message"] = str(analysis["message"])
    analysis["url_domain"] = str(analysis["url_domain"]) if analysis["url_domain"] else None
    analysis["detection_layers"] = [str(layer) for layer in analysis["detection_layers"]]
    
    return analysis