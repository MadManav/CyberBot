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
    # Initialize with the latest stable model
    model = genai.GenerativeModel("gemini-2.5-flash")  # Using the latest stable model
    print("✅ Successfully initialized Gemini model")
except Exception as e:
    print(f"❌ Error initializing Gemini: {str(e)}")
    raise

def get_llm_response(user_input, analysis):
    """
    Get a response from Gemini based on user input and analysis.
    
    Args:
        user_input (str): The user's message
        analysis (dict): The phishing analysis results
        
    Returns:
        str: The generated response or error message
    """
    if not user_input or not isinstance(user_input, str):
        return "Please provide a valid message to analyze."
        
    try:
        # Format the prompt for Gemini
        prompt = f"""
        You are a cybersecurity assistant. Analyze the following message and provide a helpful response.
        
        USER MESSAGE: {user_input}
        
        PHISHING ANALYSIS:
        - Suspicious Keywords: {analysis.get('keywords', [])}
        - Is Suspicious: {analysis.get('is_suspicious', False)}
        
        Based on the above information:
        1. Analyze the potential risks in simple language
        2. Provide recommended actions
        3. Warn if anything looks unsafe
        4. Keep the response friendly, helpful, and clear (2-3 sentences max)
        """
        
        # Generate response
        response = model.generate_content(
            prompt,
            generation_config={
                "temperature": 0.3,
                "max_output_tokens": 500,
            }
        )
        
        # Return the generated text
        return response.text.strip()
        
    except Exception as e:
        error_msg = str(e).lower()
        
        if "api key" in error_msg:
            return "🔑 Error: Invalid API key. Please check your GEMINI_API_KEY in the .env file."
        elif "quota" in error_msg:
            return "⚠️  Error: API quota exceeded. Please check your Google Cloud account."
        elif "model" in error_msg:
            return "❌ Error: Invalid model configuration. Please contact support."
        else:
            return f"⚠️  Sorry, I'm having trouble generating a response. Please try again later.\n(Error: {str(e)})"
