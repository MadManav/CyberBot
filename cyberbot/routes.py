import os
from flask import jsonify, request, render_template, send_from_directory
from .utils.phishing_analyzer import analyze_message
from .services.llm_service import get_llm_response

def init_routes(app):
    @app.route('/')
    def home():
        return render_template('home.html')

    @app.route('/chat', methods=['POST'])
    def chat():
        try:
            # Get and validate input
            if not request.is_json:
                return jsonify({"error": "Request must be JSON"}), 400
                
            data = request.get_json()
            user_input = data.get("message", "")
            
            if not user_input:
                return jsonify({"error": "Message is required"}), 400

            print(f"Received message: {user_input}")  # Debug log
            
            # Step 1 — Basic phishing analysis
            try:
                analysis = analyze_message(user_input)
                print(f"Analysis result: {analysis}")  # Debug log
            except Exception as e:
                print(f"Error in analyze_message: {str(e)}")
                return jsonify({"error": f"Error analyzing message: {str(e)}"}), 500

            # Step 2 — LLM response based on analysis
            try:
                bot_reply = get_llm_response(user_input, analysis)
                print(f"Generated response: {bot_reply[:100]}...")  # Debug log first 100 chars
            except Exception as e:
                print(f"Error in get_llm_response: {str(e)}")
                return jsonify({"error": f"Error generating response: {str(e)}"}), 500

            return jsonify({
                "analysis": analysis,
                "response": bot_reply
            })
            
        except Exception as e:
            print(f"Unexpected error in chat endpoint: {str(e)}")
            return jsonify({"error": f"Internal server error: {str(e)}"}), 500
        
    # Test route to verify static file serving
    @app.route('/test-js')
    def test_js():
        root_dir = os.path.dirname(os.getcwd())
        return send_from_directory(os.path.join(root_dir, 'static', 'js'), 'main.js')