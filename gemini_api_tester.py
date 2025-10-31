"""
Complete Gemini API Diagnostic Tool
Tests API key, lists models, and tests connection
"""

import os
from dotenv import load_dotenv

print("="*70)
print("🔍 GEMINI API DIAGNOSTIC TOOL")
print("="*70)

# Step 1: Check if package is installed
print("\n📦 Step 1: Checking package installation...")
try:
    import google.generativeai as genai
    print(f"   ✅ google-generativeai installed")
    
    # Check version
    try:
        import google.generativeai as genai_pkg
        version = genai_pkg.__version__ if hasattr(genai_pkg, '__version__') else 'unknown'
        print(f"   📌 Version: {version}")
    except:
        print(f"   ⚠️ Could not determine version")
except ImportError as e:
    print(f"   ❌ google-generativeai NOT installed")
    print(f"   Fix: pip install google-generativeai")
    exit(1)

# Step 2: Check for API key
print("\n🔑 Step 2: Checking API key...")
load_dotenv()
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")

if not GEMINI_API_KEY:
    print("   ❌ GEMINI_API_KEY not found in .env file")
    print("\n   Fix:")
    print("   1. Go to https://aistudio.google.com/app/apikey")
    print("   2. Create a new API key")
    print("   3. Add to .env file: GEMINI_API_KEY=your_key_here")
    exit(1)
else:
    print(f"   ✅ API key found: {GEMINI_API_KEY[:8]}...{GEMINI_API_KEY[-8:]}")
    print(f"   📏 Key length: {len(GEMINI_API_KEY)} characters")

# Step 3: Configure API
print("\n⚙️ Step 3: Configuring Gemini API...")
try:
    genai.configure(api_key=GEMINI_API_KEY)
    print("   ✅ API configured successfully")
except Exception as e:
    print(f"   ❌ Configuration failed: {str(e)}")
    exit(1)

# Step 4: List available models
print("\n📋 Step 4: Listing available models...")
try:
    models = list(genai.list_models())
    
    if not models:
        print("   ⚠️ No models returned")
        print("\n   Possible issues:")
        print("   1. Invalid API key")
        print("   2. API key not enabled for Gemini API")
        print("   3. Network/firewall blocking access")
        print("\n   💡 Try:")
        print("   - Generate a NEW API key at https://aistudio.google.com/app/apikey")
        print("   - Make sure you accept terms of service")
        print("   - Check if you're in a supported region")
    else:
        print(f"   ✅ Found {len(models)} models total")
        
        # Filter for generateContent models
        content_models = [m for m in models if 'generateContent' in m.supported_generation_methods]
        
        if content_models:
            print(f"   ✅ Found {len(content_models)} models supporting generateContent:\n")
            for model in content_models:
                print(f"      • {model.name}")
                print(f"        Display: {model.display_name}")
                print(f"        Methods: {', '.join(model.supported_generation_methods)}")
                print()
        else:
            print("   ⚠️ No models support generateContent")
            
except Exception as e:
    print(f"   ❌ Error listing models: {str(e)}")
    print(f"\n   Full error: {repr(e)}")
    
    # Check if it's an authentication error
    if "401" in str(e) or "403" in str(e) or "authentication" in str(e).lower():
        print("\n   🔴 AUTHENTICATION ERROR!")
        print("   Your API key is invalid or expired.")
        print("\n   Fix:")
        print("   1. Go to https://aistudio.google.com/app/apikey")
        print("   2. Delete old key and create a NEW one")
        print("   3. Update .env file with new key")
    elif "404" in str(e):
        print("\n   🔴 API NOT FOUND ERROR!")
        print("   The Gemini API might not be enabled for your account.")
        print("\n   Fix:")
        print("   1. Go to https://aistudio.google.com")
        print("   2. Accept terms of service")
        print("   3. Make sure Gemini API is enabled")
    else:
        print("\n   Unknown error. Try generating a new API key.")
    
    exit(1)

# Step 5: Test a model
print("\n🧪 Step 5: Testing model generation...")
try:
    models = list(genai.list_models())
    content_models = [m for m in models if 'generateContent' in m.supported_generation_methods]
    
    if content_models:
        test_model_name = content_models[0].name
        print(f"   Testing: {test_model_name}")
        
        model = genai.GenerativeModel(test_model_name)
        response = model.generate_content("Say 'Hello, I am working!'")
        
        if response and hasattr(response, 'text'):
            print(f"   ✅ SUCCESS! Model is working!")
            print(f"   📝 Response: {response.text[:100]}")
            
            print("\n" + "="*70)
            print("✅ DIAGNOSIS COMPLETE - EVERYTHING WORKS!")
            print("="*70)
            print(f"\n💡 Use this model in your code:")
            print(f"   model = genai.GenerativeModel('{test_model_name}')")
        else:
            print(f"   ⚠️ Model responded but format unexpected")
            print(f"   Response: {response}")
    else:
        print("   ⚠️ No models available to test")
        
except Exception as e:
    print(f"   ❌ Test failed: {str(e)}")
    print(f"\n   Full error: {repr(e)}")

print("\n" + "="*70)
print("🏁 DIAGNOSTIC COMPLETE")
print("="*70)

# Final recommendations
print("\n📌 TROUBLESHOOTING CHECKLIST:")
print("   [ ] API key is valid and not expired")
print("   [ ] API key has Gemini API enabled")
print("   [ ] Terms of service accepted on Google AI Studio")
print("   [ ] Not behind a restrictive firewall/proxy")
print("   [ ] Using latest version: pip install --upgrade google-generativeai")
print("\n💡 If all else fails:")
print("   1. Delete old API key")
print("   2. Create fresh key at: https://aistudio.google.com/app/apikey")
print("   3. Update .env file")
print("   4. Restart your application")