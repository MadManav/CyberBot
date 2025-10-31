import os
import re
import time
import requests
from urllib.parse import urlparse
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# VirusTotal API Configuration
VT_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
VT_API_BASE = "https://www.virustotal.com/api/v3"

# Cache to avoid duplicate API calls
_vt_cache = {}


def extract_url_from_text(text):
    """
    Extract URL from user message
    Returns: URL string or None
    """
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    match = re.search(url_pattern, text)
    return match.group(0) if match else None


def check_url_virustotal(url):
    """
    Check URL against VirusTotal database
    
    Args:
        url (str): URL to check
        
    Returns:
        dict: {
            'vt_score': int (0-10),
            'malicious': int,
            'suspicious': int,
            'harmless': int,
            'undetected': int,
            'total_engines': int,
            'detected': bool,
            'reputation': str ('safe', 'suspicious', 'malicious'),
            'error': str or None
        }
    """
    
    if not VT_API_KEY or VT_API_KEY == "your_virustotal_api_key_here":
        return {
            'vt_score': 0,
            'malicious': 0,
            'suspicious': 0,
            'harmless': 0,
            'undetected': 0,
            'total_engines': 0,
            'detected': False,
            'reputation': 'unknown',
            'error': 'VirusTotal API key not configured'
        }
    
    # Check cache first
    if url in _vt_cache:
        print(f"✅ Using cached VT result for {url}")
        return _vt_cache[url]
    
    result = {
        'vt_score': 0,
        'malicious': 0,
        'suspicious': 0,
        'harmless': 0,
        'undetected': 0,
        'total_engines': 0,
        'detected': False,
        'reputation': 'unknown',
        'error': None
    }
    
    try:
        # Step 1: Submit URL for scanning
        print(f"🔍 Checking URL with VirusTotal: {url}")
        
        headers = {
            "x-apikey": VT_API_KEY,
            "Content-Type": "application/x-www-form-urlencoded"
        }
        
        # Submit URL
        submit_url = f"{VT_API_BASE}/urls"
        response = requests.post(
            submit_url,
            headers=headers,
            data={"url": url},
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            url_id = data['data']['id']
            
            # Step 2: Get analysis results
            # Wait a bit for analysis
            time.sleep(2)
            
            analysis_url = f"{VT_API_BASE}/analyses/{url_id}"
            analysis_response = requests.get(
                analysis_url,
                headers=headers,
                timeout=10
            )
            
            if analysis_response.status_code == 200:
                analysis_data = analysis_response.json()
                stats = analysis_data['data']['attributes']['stats']
                
                # Extract statistics
                result['malicious'] = stats.get('malicious', 0)
                result['suspicious'] = stats.get('suspicious', 0)
                result['harmless'] = stats.get('harmless', 0)
                result['undetected'] = stats.get('undetected', 0)
                result['total_engines'] = sum(stats.values())
                result['detected'] = True
                
                # Calculate VT Score (0-10)
                # Formula: (malicious * 2 + suspicious * 1) / total_engines * 10
                if result['total_engines'] > 0:
                    threat_score = (
                        result['malicious'] * 2 + result['suspicious']
                    ) / result['total_engines']
                    result['vt_score'] = min(10, int(threat_score * 10))
                
                # Determine reputation
                if result['malicious'] >= 5:
                    result['reputation'] = 'malicious'
                elif result['malicious'] >= 2 or result['suspicious'] >= 5:
                    result['reputation'] = 'suspicious'
                elif result['harmless'] > result['malicious'] + result['suspicious']:
                    result['reputation'] = 'safe'
                else:
                    result['reputation'] = 'unknown'
                
                print(f"✅ VT Check Complete: {result['reputation'].upper()}")
                print(f"   Malicious: {result['malicious']}, Suspicious: {result['suspicious']}")
                print(f"   VT Score: {result['vt_score']}/10")
                
        elif response.status_code == 429:
            result['error'] = 'Rate limit exceeded (4 requests/min)'
            print(f"⚠️  {result['error']}")
            
        elif response.status_code == 204:
            result['error'] = 'Daily quota exceeded (500/day)'
            print(f"⚠️  {result['error']}")
            
        else:
            result['error'] = f'VT API error: {response.status_code}'
            print(f"❌ {result['error']}")
            
    except requests.exceptions.Timeout:
        result['error'] = 'VirusTotal request timeout'
        print(f"⏱️  {result['error']}")
        
    except requests.exceptions.RequestException as e:
        result['error'] = f'Network error: {str(e)}'
        print(f"❌ {result['error']}")
        
    except Exception as e:
        result['error'] = f'Unexpected error: {str(e)}'
        print(f"❌ {result['error']}")
    
    # Cache result (even errors, to avoid repeated failed calls)
    _vt_cache[url] = result
    
    return result


def check_domain_virustotal(domain):
    """
    Check domain reputation on VirusTotal
    More comprehensive than URL check
    
    Args:
        domain (str): Domain to check (e.g., 'google.com')
        
    Returns:
        dict: Similar to check_url_virustotal()
    """
    
    if not VT_API_KEY or VT_API_KEY == "your_virustotal_api_key_here":
        return {
            'vt_score': 0,
            'detected': False,
            'reputation': 'unknown',
            'error': 'API key not configured'
        }
    
    result = {
        'vt_score': 0,
        'malicious': 0,
        'suspicious': 0,
        'harmless': 0,
        'categories': [],
        'detected': False,
        'reputation': 'unknown',
        'error': None
    }
    
    try:
        headers = {"x-apikey": VT_API_KEY}
        domain_url = f"{VT_API_BASE}/domains/{domain}"
        
        response = requests.get(domain_url, headers=headers, timeout=10)
        
        if response.status_code == 200:
            data = response.json()
            attributes = data['data']['attributes']
            
            # Get last analysis stats
            if 'last_analysis_stats' in attributes:
                stats = attributes['last_analysis_stats']
                result['malicious'] = stats.get('malicious', 0)
                result['suspicious'] = stats.get('suspicious', 0)
                result['harmless'] = stats.get('harmless', 0)
                result['detected'] = True
                
                total = sum(stats.values())
                if total > 0:
                    threat_score = (result['malicious'] * 2 + result['suspicious']) / total
                    result['vt_score'] = min(10, int(threat_score * 10))
            
            # Get categories
            if 'categories' in attributes:
                result['categories'] = list(attributes['categories'].values())
            
            # Determine reputation
            if result['malicious'] >= 3:
                result['reputation'] = 'malicious'
            elif result['suspicious'] >= 3:
                result['reputation'] = 'suspicious'
            else:
                result['reputation'] = 'safe'
                
            print(f"✅ Domain Check: {domain} - {result['reputation'].upper()}")
            
        elif response.status_code == 404:
            result['error'] = 'Domain not found in VT database'
            result['reputation'] = 'unknown'
            
        else:
            result['error'] = f'API error: {response.status_code}'
            
    except Exception as e:
        result['error'] = str(e)
    
    return result


def get_comprehensive_check(text):
    """
    Comprehensive check that combines URL and domain analysis
    
    Args:
        text (str): Message containing URL
        
    Returns:
        dict: Combined VT analysis results
    """
    # Extract URL
    url = extract_url_from_text(text)
    
    if not url:
        return {
            'vt_score': 0,
            'detected': False,
            'reputation': 'no_url',
            'error': 'No URL found in message'
        }
    
    # Check URL
    url_result = check_url_virustotal(url)
    
    # Also check domain separately for more data
    try:
        parsed = urlparse(url)
        domain = parsed.netloc
        if domain:
            domain_result = check_domain_virustotal(domain)
            
            # Combine scores (prioritize URL check, but use domain as backup)
            if url_result['detected']:
                return url_result
            elif domain_result['detected']:
                return domain_result
    except:
        pass
    
    return url_result


def clear_cache():
    """Clear the VT results cache"""
    global _vt_cache
    _vt_cache = {}
    print("🗑️  VirusTotal cache cleared")


# Testing function
if __name__ == "__main__":
    print("🧪 Testing VirusTotal Integration\n")
    
    # Test URLs
    test_cases = [
        "Check this link: https://www.google.com",
        "Suspicious: http://bit.ly/suspicious123",
        "Phishing: https://secure-login-verification.tk/verify",
    ]
    
    for test in test_cases:
        print(f"\n{'='*60}")
        print(f"Testing: {test}")
        print('='*60)
        
        result = get_comprehensive_check(test)
        
        print(f"\n📊 Results:")
        print(f"   VT Score: {result['vt_score']}/10")
        print(f"   Reputation: {result['reputation']}")
        print(f"   Malicious: {result.get('malicious', 0)}")
        print(f"   Suspicious: {result.get('suspicious', 0)}")
        if result['error']:
            print(f"   Error: {result['error']}")
        
        time.sleep(15)  # Rate limit: 4 req/min