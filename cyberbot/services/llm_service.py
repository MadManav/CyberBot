import os
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure Gemini API
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_API_KEY:
    raise ValueError("GEMINI_API_KEY not found in environment variables")

try:
    genai.configure(api_key=GEMINI_API_KEY)
    model = genai.GenerativeModel("gemini-2.5-flash")
    print("✅ Successfully initialized Gemini model")
except Exception as e:
    print(f"❌ Error initializing Gemini: {str(e)}")
    raise

def get_llm_response(user_input, analysis, incident=None):
    """
    Get a response from Gemini based on user input, analysis, and incident
    
    Args:
        user_input (str): The user's message
        analysis (dict): The phishing analysis results
        incident (dict): Incident details if detected (optional)
        
    Returns:
        str: The generated response or error message
    """
    if not user_input or not isinstance(user_input, str):
        return "Please provide a valid message to analyze."
    
    # If this is an incident response scenario
    if incident:
        return handle_incident_response(user_input, incident)
    
    is_suspicious = analysis.get('is_suspicious', False)
    keywords = analysis.get('keywords', [])
    
    # If highly suspicious, provide direct response
    if is_suspicious and keywords:
        warning_signs = ', '.join(keywords[:3])
        return f"⚠️ This looks like a phishing attempt. Warning signs detected: {warning_signs}. Never click links or download files from suspicious messages. When in doubt, go directly to the official website by typing the URL yourself."
    
    if is_suspicious:
        return "⚠️ This message appears suspicious. Be cautious about clicking links or sharing personal information. Visit official websites directly instead of through links."
        
    try:
        keywords_str = ', '.join(keywords) or 'None'
        
        prompt = f"""You are a helpful cybersecurity guide. A user asked: "{user_input}"

Analysis: This message appears safe and legitimate.
Background info: {keywords_str if keywords_str != 'None' else 'Standard analysis performed'}

Provide a brief, reassuring response (2-3 sentences) that:
1. Confirms the message/URL appears safe
2. Explains why briefly
3. Gives one general online safety tip
4. Use empathetic and friendly tone

Keep it friendly and conversational."""
        
        response = model.generate_content(
            prompt,
            generation_config={
                "temperature": 0.3,
                "max_output_tokens": 500,
            }
        )
        
        if not response.candidates or not response.candidates[0].content.parts:
            return "⚠️ I couldn't generate a response for this query. Please try rephrasing your question."
        
        return response.text.strip()
        
    except ValueError as e:
        error_msg = str(e).lower()
        if "finish_reason" in error_msg or "part" in error_msg:
            return "⚠️ The content was blocked by safety filters. Please try rephrasing your question."
        return f"⚠️ Sorry, I'm having trouble generating a response. Please try again later.\n(Error: {str(e)})"
        
    except Exception as e:
        error_msg = str(e).lower()
        
        if "api key" in error_msg:
            return "🔑 Error: Invalid API key. Please check your GEMINI_API_KEY in the .env file."
        elif "quota" in error_msg:
            return "⚠️ Error: API quota exceeded. Please check your Google Cloud account."
        elif "model" in error_msg:
            return "❌ Error: Invalid model configuration. Please contact support."
        else:
            return f"⚠️ Sorry, I'm having trouble generating a response. Please try again later.\n(Error: {str(e)})"


def handle_incident_response(user_input, incident):
    """
    Handle incident response with empathy and actionable steps
    
    Args:
        user_input (str): User's message
        incident (dict): Detected incident details
        
    Returns:
        str: Empathetic response with action steps
    """
    try:
        incident_type = incident.get('type', 'unknown')
        severity = incident.get('severity', 'medium')
        
        # Create empathetic prompt for Gemini
        prompt = f"""You are a calm, supportive cybersecurity counselor. A user is stressed because they experienced this incident: {incident.get('description', 'cybersecurity incident')}.

Their message: "{user_input}"

Severity: {severity}

Respond with:
1. Calm reassurance (don't panic them further)
2. Acknowledge their situation empathetically
3. Tell them this is common and help is available
4. Briefly mention they'll see action steps below

Keep response to 3-4 sentences. Be warm, supportive, and professional. Don't give technical steps (those will be shown separately)."""

        response = model.generate_content(
            prompt,
            generation_config={
                "temperature": 0.7,  # More empathetic
                "max_output_tokens": 300,
            }
        )
        
        if response.candidates and response.candidates[0].content.parts:
            return response.text.strip()
        else:
            # Fallback empathetic response
            return get_fallback_empathy(severity)
            
    except Exception as e:
        print(f"Error in incident response: {str(e)}")
        return get_fallback_empathy(incident.get('severity', 'medium'))


def get_fallback_empathy(severity):
    """
    Fallback empathetic responses if LLM fails
    
    Args:
        severity (str): Incident severity level
        
    Returns:
        str: Pre-written empathetic response
    """
    if severity == "critical":
        return "🫂 I understand this is stressful. Take a deep breath - you did the right thing by reaching out. Many people face similar situations, and there are clear steps to protect yourself. Let's handle this together."
    elif severity == "high":
        return "🫂 Don't worry, you've taken the right step by seeking help. This is a common issue and we can resolve it. Follow the action steps below carefully, and you'll be secure again."
    else:
        return "🫂 Thank you for being cautious and reaching out. This shows good security awareness. Let's review what you can do to stay safe."