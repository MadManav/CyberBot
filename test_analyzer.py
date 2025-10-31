from cyberbot.utils.phishing_analyzer import analyze_message

# Test cases
tests = [
    "Check this link: https://www.google.com",
    "URGENT! Verify your account: http://secure-bank-login.tk/verify",
    "Meeting tomorrow at 3pm",
    "You won $1M! Click: http://bit.ly/claim-prize",
]

for test in tests:
    print(f"\n{'='*70}")
    print(f"Testing: {test}")
    print('='*70)
    
    result = analyze_message(test)
    
    print(f"\n✅ Result: {result['risk_level']}")
    print(f"   Phishing: {result['is_suspicious']}")
    print(f"   Confidence: {result['final_score']:.1%}")
    print(f"   Keywords: {', '.join(result['keywords'][:3])}")