import os
import json
import numpy as np
from flask import jsonify, request, render_template, send_from_directory
from .utils.phishing_analyzer import analyze_message
from .utils.incident_detector import detect_incident, get_incident_response, get_reporting_resources
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

            print(f"Received message: {user_input}")
            
            # Step 1 - Check if this is an incident report
            incident = detect_incident(user_input)
            
            if incident:
                print(f"🚨 Incident detected: {incident['type']} (severity: {incident['severity']})")
                
                # Get incident-specific response
                incident_details = get_incident_response(incident['type'])
                reporting = get_reporting_resources()
                
                # Get empathetic LLM response
                bot_reply = get_llm_response(user_input, {}, incident=incident)
                
                # Return incident response
                return jsonify({
                    "type": "incident",
                    "incident": {
                        "detected": True,
                        "type": incident['type'],
                        "severity": incident['severity'],
                        "description": incident['description'],
                        "confidence": float(incident['confidence'])
                    },
                    "response": bot_reply,
                    "actions": incident_details.get('immediate_actions', []),
                    "prevention": incident_details.get('prevention', []),
                    "urgency": incident_details.get('urgency', 'medium'),
                    "reporting": reporting
                })
            
            # Step 2 - Normal phishing analysis (if not an incident)
            try:
                analysis = analyze_message(user_input)
                print(f"Analysis result: {analysis}")
                
                # Ensure JSON serializable
                analysis = {
                    k: (bool(v) if isinstance(v, (bool, np.bool_)) else 
                         float(v) if isinstance(v, (float, np.floating)) else 
                         int(v) if isinstance(v, (int, np.integer)) else 
                         v)
                    for k, v in analysis.items()
                }
            except Exception as e:
                print(f"Error in analyze_message: {str(e)}")
                return jsonify({"error": f"Error analyzing message: {str(e)}"}), 500

            # Step 3 - Get LLM response
            try:
                bot_reply = get_llm_response(user_input, analysis)
                print(f"Generated response: {bot_reply[:100]}...")
            except Exception as e:
                print(f"Error in get_llm_response: {str(e)}")
                return jsonify({"error": f"Error generating response: {str(e)}"}), 500

            # Return normal phishing analysis
            response_data = {
                "type": "analysis",
                "analysis": analysis,
                "response": bot_reply
            }
            
            json.dumps(response_data)  # Test serialization
            return jsonify(response_data)
            
        except Exception as e:
            print(f"Unexpected error in chat endpoint: {str(e)}")
            return jsonify({"error": f"Internal server error: {str(e)}"}), 500
    
    
    @app.route('/report-resources', methods=['GET'])
    def report_resources():
        """
        Endpoint to get reporting resources
        """
        try:
            resources = get_reporting_resources()
            return jsonify(resources)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
        
    
    # Test route
    @app.route('/test-js')
    def test_js():
        root_dir = os.path.dirname(os.getcwd())
        return send_from_directory(os.path.join(root_dir, 'static', 'js'), 'main.js')