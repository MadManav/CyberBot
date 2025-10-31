import os
import google.generativeai as genai
from dotenv import load_dotenv
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, 
                    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                    filename='llm_service.log')
logger = logging.getLogger('llm_service')

# Load environment variables
load_dotenv()

# Configure Gemini API
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    logger.warning("GEMINI_API_KEY not found in environment variables. Using fallback responses.")
    print("⚠️ Warning: GEMINI_API_KEY not found in environment variables. Using fallback responses.")
    GEMINI_API_KEY = None

# Global flag to track if Gemini is working
GEMINI_AVAILABLE = False
model = None

try:
    if GEMINI_API_KEY:
        logger.info(f"Found API key: {GEMINI_API_KEY[:5]}...{GEMINI_API_KEY[-5:] if len(GEMINI_API_KEY) > 10 else ''}")
        genai.configure(api_key=GEMINI_API_KEY)
        
        # Try different model names in order of preference
        model_names = [
            "gemini-1.5-flash",
            "gemini-pro",
            "gemini-1.0-pro",
            "models/gemini-pro"
        ]
        
        model_initialized = False
        for model_name in model_names:
            try:
                logger.info(f"Trying model: {model_name}")
                print(f"🔄 Trying model: {model_name}")
                model = genai.GenerativeModel(model_name)
                
                # Test the model
                test_response = model.generate_content("Hello")
                if test_response and hasattr(test_response, 'text'):
                    GEMINI_AVAILABLE = True
                    model_initialized = True
                    logger.info(f"✅ Successfully initialized Gemini model: {model_name}")
                    print(f"✅ Successfully initialized Gemini model: {model_name}")
                    break
            except Exception as model_error:
                logger.warning(f"⚠️ Model {model_name} failed: {str(model_error)}")
                print(f"⚠️ Model {model_name} not available")
                continue
        
        if not model_initialized:
            logger.warning("⚠️ No Gemini models available")
            print("⚠️ No Gemini models available, using fallback responses")
            
except Exception as e:
    logger.error(f"❌ Error initializing Gemini: {str(e)}")
    print(f"❌ Error initializing Gemini: {str(e)}")
    print("💡 Using fallback responses instead")

def classify_intent(user_input):
    """Classify user's intent"""
    user_lower = user_input.lower()
    
    # Check for common phishing patterns
    phishing_indicators = [
        'click', 'http://', 'https://', 'www.', '.com', '.org', '.net', '.in',
        'prize', 'won', 'winner', 'claim', 'reward', 'money', 'cash', 'bank',
        'account', 'verify', 'password', 'login', 'urgent', 'alert', 'update',
        'security', 'suspicious', 'unusual', 'activity', 'limited', 'time',
        'offer', 'free', 'gift', 'congratulations', 'lucky', 'selected',
        'payment', 'credit', 'debit', 'card', 'expire', 'kyc', 'verify',
        'bit.ly', 'tinyurl', 'goo.gl', 'is this safe', 'is this legit'
    ]
    
    if any(indicator in user_lower for indicator in phishing_indicators):
        return 'check'
    
    # Fallback keyword detection
    if any(word in user_lower for word in ['check', 'analyze', 'safe', 'suspicious', 'phishing', 'scam', 'link']):
        return 'check'
    elif any(word in user_lower for word in ['learn', 'what is', 'how to', 'explain', 'tell me about']):
        return 'learn'
    elif any(word in user_lower for word in ['help', 'clicked', 'hacked', 'compromised', 'victim']):
        return 'incident'
    return 'casual'

def get_llm_response(user_input, analysis=None, incident=None):
    """Smart routing with LLM as EXPLAINER"""
    if not user_input or not isinstance(user_input, str):
        return "Please provide a valid message to analyze."
    
    try:
        if incident:
            return handle_incident_response(user_input, incident)
        
        intent = classify_intent(user_input)
        print(f"🎯 Detected intent: {intent}")
        
        if intent == 'casual':
            return handle_casual_mode(user_input)
        elif intent == 'learn':
            return handle_learn_mode(user_input)
        elif intent == 'check':
            if not analysis or not isinstance(analysis, dict):
                from ..utils.phishing_analyzer import analyze_message
                try:
                    analysis = analyze_message(user_input)
                except Exception as e:
                    print(f"Error in analysis: {str(e)}")
                    return "I encountered an error while analyzing your request. Please try again."
            return handle_check_mode(user_input, analysis)
        elif intent == 'incident':
            return "🚨 It sounds like you might be experiencing a security incident. Could you provide more details?"
        
        return handle_casual_mode(user_input)
    except Exception as e:
        print(f"Error in get_llm_response: {str(e)}")
        return "I encountered an error. Please try again."

def handle_casual_mode(user_input):
    """Handle casual conversations"""
    user_lower = user_input.lower().strip()
    
    greetings = {
        'hi': "👋 Hi there! I'm CyberGuard AI, your cybersecurity assistant. I can help you:\n• Learn about online safety\n• Check if messages/links are safe\n• Guide you if you've experienced a security incident\n\nHow can I help you today?",
        'hello': "👋 Hello! I'm here to help keep you safe online. You can ask me about phishing, passwords, suspicious links, or get help if something went wrong. What would you like to know?",
        'hey': "👋 Hey! I'm CyberGuard AI. I protect people from cyber threats. Feel free to ask me anything about online safety or share suspicious messages!",
        'thank you': "😊 You're welcome! Stay safe online, and feel free to come back anytime!",
        'thanks': "😊 Happy to help! Remember, staying cautious online is the best defense. Come back anytime!",
        'bye': "👋 Goodbye! Stay safe online and remember: never share OTPs, always verify links, and trust your instincts!",
        'goodbye': "👋 Take care! Keep your devices secure and stay alert for phishing attempts!"
    }
    
    for key, response in greetings.items():
        if user_lower == key or user_lower == key + '!':
            return response
    
    if GEMINI_AVAILABLE and model:
        try:
            prompt = f"""You are CyberGuard AI, a friendly cybersecurity chatbot. A user is having a casual conversation.

User's message: "{user_input}"

Respond warmly and briefly (2-3 sentences). If they're asking what you can do, mention: detecting phishing, educating about online safety, and providing incident guidance.

Keep it conversational and helpful. Use max 1 emoji."""

            response = model.generate_content(
                prompt,
                generation_config={"temperature": 0.7, "max_output_tokens": 300}
            )
            
            if response and hasattr(response, 'text') and response.text.strip():
                return response.text.strip()
        except Exception as e:
            print(f"Casual mode error: {str(e)}")
    
    # Contextual fallback
    if "what" in user_lower and "do" in user_lower:
        return "I'm CyberGuard AI, your cybersecurity assistant. I can analyze suspicious messages, educate you about online threats, and help if you've experienced a security incident. What would you like help with today?"
    
    return "👋 Hi! I'm CyberGuard AI. I can help you:\n• Learn about online threats\n• Check if links or messages are safe\n• Guide you through security incidents\n\nWhat would you like help with?"

def handle_learn_mode(user_input):
    """Educational responses"""
    if not GEMINI_AVAILABLE or not model:
        # Better fallback for common questions
        user_lower = user_input.lower()
        if 'phishing' in user_lower:
            return """📚 **What is Phishing?**

Phishing is a cybercrime where attackers pretend to be legitimate organizations to steal your personal information (passwords, credit cards, OTPs).

**Common signs:**
• Urgent language ("Act now!", "Account suspended")
• Suspicious links or email addresses
• Requests for passwords/OTPs
• Too-good-to-be-true offers

**Stay safe:** Always verify sender identity, never share OTPs, and check URLs before clicking!"""
        
        return "📚 I'd be happy to explain that! However, I'm having trouble generating a detailed response. Could you try rephrasing your question?"
    
    try:
        prompt = f"""You are a friendly cybersecurity educator. Answer this question clearly:

Question: "{user_input}"

Provide a clear, simple explanation (3-4 sentences):
1. Directly answer their question
2. Use simple language (explain jargon)
3. Include ONE practical example or tip
4. Encourage safe practices

Be conversational. Use max 1 emoji."""

        response = model.generate_content(
            prompt,
            generation_config={"temperature": 0.6, "max_output_tokens": 400}
        )
        
        if response and hasattr(response, 'text') and response.text.strip():
            return "📚 " + response.text.strip()
        else:
            return "📚 I'd be happy to explain that! Could you try rephrasing your question?"
            
    except Exception as e:
        print(f"Learn mode error: {str(e)}")
        return "📚 I'd love to help you learn! Please try again."

def handle_check_mode(user_input, analysis):
    """Analysis mode - LLM EXPLAINS the detection results"""
    
    is_suspicious = analysis.get('is_suspicious', False)
    final_score = analysis.get('final_score', 0)
    ml_score = analysis.get('ml_ensemble_score', 0)
    vt_score = analysis.get('virustotal_score', 0)
    risk_level = analysis.get('risk_level', 'UNKNOWN')
    keywords = analysis.get('keywords', [])
    vt_details = analysis.get('vt_details', {})
    
    # Critical threat - immediate warning
    if vt_score >= 0.5:
        return f"""⚠️ **CRITICAL THREAT DETECTED!**

This has been flagged as MALICIOUS by {vt_details.get('malicious', 'multiple')} security engines on VirusTotal.

**🛡️ Detection Results:**
- VirusTotal: {vt_score*10:.0f}/10 (Malicious)
- ML Analysis: {ml_score*100:.0f}% phishing probability
- Risk Level: {risk_level}

**🚨 IMMEDIATE ACTIONS:**
- Do NOT click any links
- Do NOT enter personal information
- DELETE this message immediately
- If from someone you know, contact them directly

**Why it's dangerous:** This URL/domain is known to security databases as a threat."""
    
    # Use LLM to explain findings
    if not GEMINI_AVAILABLE or not model:
        return get_fallback_check_response(is_suspicious, keywords, risk_level, ml_score, vt_score)
    
    try:
        vt_info = f"\n- VirusTotal flagged this by {vt_details.get('malicious', 0)} security engines" if vt_score > 0 else ""
        
        prompt = f"""You are a cybersecurity analyst explaining detection results.

User asked about: "{user_input}"

**DETECTION RESULTS:**
- Overall Risk: {risk_level}
- Final Confidence: {final_score*100:.0f}%
- ML Score: {ml_score*100:.0f}% (phishing probability)
- VirusTotal: {vt_score*10:.0f}/10{vt_info}
- Warning signs: {', '.join(keywords[:5]) if keywords else 'none'}

Explain in plain language (3-4 sentences):
1. Clear verdict: Is it SAFE or SUSPICIOUS/DANGEROUS?
2. Explain WHY based on scores
3. Give ONE specific actionable advice
4. Keep tone helpful

Be direct. Use max 1 emoji."""

        response = model.generate_content(
            prompt,
            generation_config={"temperature": 0.4, "max_output_tokens": 400}
        )
        
        if response and hasattr(response, 'text') and response.text.strip():
            return response.text.strip()
        else:
            return get_fallback_check_response(is_suspicious, keywords, risk_level, ml_score, vt_score)
            
    except Exception as e:
        print(f"Check mode error: {str(e)}")
        return get_fallback_check_response(is_suspicious, keywords, risk_level, ml_score, vt_score)

def get_fallback_check_response(is_suspicious, keywords, risk_level, ml_score, vt_score):
    """Fallback for check mode"""
    if is_suspicious:
        issues = ', '.join(keywords[:3]) if keywords else 'suspicious patterns'
        vt_msg = f" VirusTotal flagged this ({vt_score*10:.0f}/10)." if vt_score > 0 else ""
        return f"""⚠️ **{risk_level} RISK DETECTED**

Our analysis found: {issues}.{vt_msg}

**Detection Confidence:** {ml_score*100:.0f}%

**Recommendation:** Be cautious. Avoid clicking links or sharing information."""
    else:
        return f"""✅ **Appears Safe**

Our 3-layer analysis shows low risk:
- ML Score: {ml_score*100:.0f}%
- VirusTotal: Clean
- Risk Level: {risk_level}

However, always stay vigilant online and verify sender identity."""

def handle_incident_response(user_input, incident):
    """Handle incident with empathy"""
    severity = incident.get('severity', 'medium')
    
    if not GEMINI_AVAILABLE or not model:
        return get_fallback_empathy(severity)
    
    try:
        prompt = f"""You are a calm cybersecurity counselor. A user experienced: {incident.get('description', 'cybersecurity incident')}.

Their message: "{user_input}"
Severity: {severity}

Respond (3-4 sentences):
1. Calm reassurance
2. Acknowledge empathetically
3. Mention this is common
4. Note they'll see action steps below

Be warm and supportive. Use max 1 emoji."""

        response = model.generate_content(
            prompt,
            generation_config={"temperature": 0.7, "max_output_tokens": 300}
        )
        
        if response and hasattr(response, 'text') and response.text.strip():
            return response.text.strip()
        else:
            return get_fallback_empathy(severity)
            
    except Exception as e:
        print(f"Error in incident response: {str(e)}")
        return get_fallback_empathy(severity)

def get_fallback_empathy(severity):
    """Fallback empathetic responses"""
    if severity == "critical":
        return "🫂 I understand this is stressful. Take a deep breath - you did the right thing by reaching out. Let's handle this together."
    elif severity == "high":
        return "🫂 Don't worry, you've taken the right step by seeking help. Follow the action steps below carefully."
    else:
        return "🫂 Thank you for being cautious. Let's review what you can do to stay safe."

def analyze_code_with_ai(source_code: str, language: str, rule_based_issues: list) -> dict:
    """
    Use Gemini AI to analyze code for security vulnerabilities and suggest fixes.
    Combines AI insights with rule-based detection.
    
    Args:
        source_code: The code snippet to analyze
        language: Programming language (python, javascript, etc.)
        rule_based_issues: List of issues found by rule-based analysis
        
    Returns:
        dict with keys: ai_issues, ai_fixes, best_practices, ai_fixed_code, explanations
    """
    try:
        # Check if AI is available
        if not GEMINI_AVAILABLE or not model:
            return {
                "ai_issues": [],
                "ai_fixes": source_code,
                "best_practices": [],
                "explanations": {},
                "summary": "AI analysis unavailable - Gemini API not configured",
                "error": "Gemini API not available"
            }
            
        # Build prompt for Gemini
        rule_based_summary = ""
        if rule_based_issues:
            issues_text = "\n".join([
                f"- Line {iss.get('line', '?')}: [{iss.get('severity', 'unknown')}] {iss.get('message', '')}"
                for iss in rule_based_issues[:10]  # Limit to first 10
            ])
            rule_based_summary = f"Rule-based analysis found {len(rule_based_issues)} issue(s):\n{issues_text}\n\n"
        
        prompt = f"""You are a secure coding expert. Analyze this {language} code snippet for security vulnerabilities.

CODE:
```{language}
{source_code}
```

{rule_based_summary}Perform a comprehensive security analysis:

1. **Security Issues**: Identify ALL security vulnerabilities (even ones not caught by rules):
   - Injection attacks (SQL, command, code)
   - Authentication/Authorization flaws
   - Sensitive data exposure (secrets, passwords, API keys)
   - Insecure deserialization
   - XXE, XSS, CSRF vulnerabilities
   - Weak cryptography
   - Insecure dependencies
   - Security misconfigurations
   - Any other OWASP Top 10 issues

2. **Provide detailed explanations** for each issue found (why it's dangerous)

3. **Suggest specific fixes** with corrected code snippets

4. **Best Practices**: Recommend secure coding guidelines relevant to this code

5. **Fixed Code**: Provide a corrected version of the entire code snippet

Format your response as JSON:
{{
    "ai_issues": [
        {{
            "line": <line_number>,
            "severity": "critical|high|medium|low",
            "vulnerability": "<OWASP category or type>",
            "description": "<what the issue is>",
            "explanation": "<why it's dangerous, with examples>",
            "fix_suggestion": "<specific fix with code example>"
        }}
    ],
    "ai_fixes": "<complete fixed code>",
    "best_practices": [
        "<relevant secure coding guideline 1>",
        "<relevant secure coding guideline 2>"
    ],
    "summary": "<brief overview of security posture>"
}}

Focus on actionable, specific issues. Be concise but thorough."""

        response = model.generate_content(
            prompt,
            generation_config={
                "temperature": 0.3,  # Lower temperature for more consistent analysis
                "max_output_tokens": 4000,
            }
        )
        
        if not response or not hasattr(response, 'text'):
            return {
                "ai_issues": [],
                "ai_fixes": source_code,
                "best_practices": [],
                "explanations": {},
                "summary": "AI analysis unavailable",
                "error": "No response from AI model"
            }
        
        response_text = response.text.strip()
        
        # Try to parse JSON from response
        import json
        try:
            # Extract JSON from response (handle markdown code blocks)
            json_text = response_text
            if "```json" in response_text:
                json_text = response_text.split("```json")[1].split("```")[0].strip()
            elif "```" in response_text:
                json_text = response_text.split("```")[1].split("```")[0].strip()
            
            ai_result = json.loads(json_text)
            
            return {
                "ai_issues": ai_result.get("ai_issues", []),
                "ai_fixes": ai_result.get("ai_fixes", source_code),
                "best_practices": ai_result.get("best_practices", []),
                "summary": ai_result.get("summary", ""),
                "explanations": {iss.get("vulnerability", ""): iss.get("explanation", "")
                                for iss in ai_result.get("ai_issues", [])}
            }
        except (json.JSONDecodeError, KeyError) as e:
            # Fallback: return structured text response
            return {
                "ai_issues": [],
                "ai_fixes": source_code,
                "best_practices": [],
                "explanations": {},
                "summary": response_text[:500],  # First 500 chars as summary
                "raw_response": response_text,
                "error": f"Could not parse AI response: {str(e)}"
            }
            
    except Exception as e:
        print(f"Error in AI code analysis: {str(e)}")
        return {
            "ai_issues": [],
            "ai_fixes": source_code,
            "best_practices": [],
            "explanations": {},
            "summary": f"AI analysis failed: {str(e)}",
            "error": str(e)
        }

def get_quiz_feedback(question, selected_answer, correct_answer, is_correct, category, user_score, total_answered):
    """Generate personalized quiz feedback"""
    
    # If Gemini not available, use better fallbacks
    if not GEMINI_AVAILABLE or not model:
        return get_fallback_quiz_feedback(is_correct, category, selected_answer, correct_answer)
    
    try:
        performance = "excellent" if user_score / total_answered > 0.8 else \
                     "good" if user_score / total_answered > 0.6 else "progressing"
        
        if is_correct:
            prompt = f"""You are an encouraging cybersecurity tutor. Student answered correctly!

Question: {question}
Category: {category}
Their answer: {selected_answer}
Performance: {performance} ({user_score}/{total_answered})

Brief feedback (2-3 sentences):
1. Congratulate warmly
2. Add ONE real-world insight about {category}
3. Encourage continued learning

Conversational and enthusiastic. Max 1 emoji."""
        else:
            prompt = f"""You are a supportive cybersecurity tutor. Student answered incorrectly.

Question: {question}
Category: {category}
They chose: {selected_answer}
Correct: {correct_answer}
Performance: {performance} ({user_score}/{total_answered})

Brief feedback (3-4 sentences):
1. Gently explain WHY their answer was wrong
2. Clarify correct answer with memorable tip
3. Share ONE real-world scenario
4. Encourage positively

Empathetic and clear. Max 1 emoji."""

        response = model.generate_content(
            prompt,
            generation_config={"temperature": 0.7, "max_output_tokens": 400}
        )
        
        if response and hasattr(response, 'text') and response.text.strip():
            return response.text.strip()
        else:
            return get_fallback_quiz_feedback(is_correct, category, selected_answer, correct_answer)
            
    except Exception as e:
        print(f"Quiz feedback error: {str(e)}")
        return get_fallback_quiz_feedback(is_correct, category, selected_answer, correct_answer)

def get_fallback_quiz_feedback(is_correct, category, selected_answer, correct_answer):
    """Better fallback feedback"""
    if is_correct:
        tips = {
            "Phishing": "Spotting phishing emails can prevent 90% of cyberattacks!",
            "Password Security": "Strong passwords are your first line of defense online.",
            "Social Engineering": "Awareness of manipulation tactics keeps you safe.",
            "Malware": "Understanding malware helps you avoid dangerous downloads.",
            "Data Privacy": "Protecting your data protects your identity."
        }
        tip = tips.get(category, "This knowledge is crucial for staying safe online!")
        return f"✅ Excellent! You're right. {tip} Keep up the great work!"
    else:
        return f"""📚 Not quite! The correct answer was: {correct_answer}

Here's why: {selected_answer} isn't the best choice because it doesn't address the core security principle. In {category}, it's important to understand the underlying threats and how to protect yourself.

**Remember:** Always verify before trusting, especially online! You're learning - keep going! 💪"""