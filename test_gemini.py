import os
import google.generativeai as genai
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get API key
api_key = os.getenv("GEMINI_API_KEY")
print(f"API Key: {'*' * 10 + api_key[-4:] if api_key else 'Not set'}")

if not api_key:
    print("Error: GEMINI_API_KEY not found in .env file")
    exit(1)

try:
    # Configure Gemini
    genai.configure(api_key=api_key)
    
    # Using the latest stable model
    model = genai.GenerativeModel("gemini-pro")
    
    # Test prompt
    prompt = "Give me a short cybersecurity tip."
    print(f"\nSending test prompt: {prompt}")
    
    # Get response
    response = model.generate_content(prompt)
    
    print("\n=== Response from Gemini ===")
    print(response.text)
    print("\n✅ Test completed successfully!")
    
except Exception as e:
    print("\n=== Error Details ===")
    print(f"Error type: {type(e).__name__}")
    print(f"Error message: {str(e)}")
    import traceback
    traceback.print_exc()
