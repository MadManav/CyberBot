import os
import json
import numpy as np
from flask import jsonify, request, render_template, send_from_directory
from .utils.phishing_analyzer import analyze_message
from .utils.incident_detector import detect_incident, get_incident_response, get_reporting_resources
from .services.llm_service import get_llm_response, classify_intent, analyze_code_with_ai
from .utils.code_security import analyze_code_security

def init_routes(app):
    @app.route('/')
    def home():
        return render_template('home.html')
        
    @app.route('/code-review')
    def code_review():
        return render_template('code_review.html')

    @app.route('/chat', methods=['POST'])
    def chat():
        print("\n" + "="*60)
        print("📨 CHAT ENDPOINT CALLED")
        print("="*60)
        
        try:
            # Get and validate input
            if not request.is_json:
                print("❌ Request is not JSON")
                return jsonify({"error": "Request must be JSON"}), 400
                
            data = request.get_json()
            user_input = data.get("message", "")
            
            if not user_input:
                print("❌ Empty message")
                return jsonify({"error": "Message is required"}), 400

            print(f"📩 Received: '{user_input}'")
            
            # Step 1 - Check if this is an incident report
            print("\n🔍 Step 1: Checking for incident...")
            incident = detect_incident(user_input)
            
            if incident:
                print(f"🚨 Incident detected: {incident['type']} (severity: {incident['severity']})")
                
                # Get incident-specific response
                incident_details = get_incident_response(incident['type'])
                reporting = get_reporting_resources()
                
                # Get empathetic LLM response
                try:
                    bot_reply = get_llm_response(user_input, analysis=None, incident=incident)
                    print(f"✅ LLM incident response generated")
                except Exception as e:
                    print(f"❌ Error getting LLM response for incident: {str(e)}")
                    bot_reply = "I'm sorry, I encountered an error processing your incident report. Please try again."
                
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
            
            print("ℹ️  No incident detected")
            
            # Step 2 - Classify intent
            print("\n🎯 Step 2: Classifying intent...")
            try:
                intent = classify_intent(user_input)
                print(f"   Intent: {intent}")
            except Exception as e:
                print(f"❌ Error classifying intent: {str(e)}")
                intent = "casual"
            
            # Step 3 - Decide if we need analysis
            analysis = None
            
            # Only run analysis for 'check' or 'hybrid' intents (messages with URLs/suspicious content)
            if intent in ['check', 'hybrid']:
                print("\n📊 Step 3: Running 3-layer analysis...")
                try:
                    analysis = analyze_message(user_input)
                    print(f"   ✅ Analysis complete:")
                    print(f"      ML Score: {analysis.get('ml_ensemble_score', 0):.2%}")
                    print(f"      VT Score: {analysis.get('virustotal_score', 0):.2%}")
                    print(f"      Final Score: {analysis.get('final_score', 0):.2%}")
                    print(f"      Risk: {analysis.get('risk_level', 'UNKNOWN')}")
                    
                    # Ensure JSON serializable
                    analysis = {
                        k: (bool(v) if isinstance(v, (bool, np.bool_)) else 
                             float(v) if isinstance(v, (float, np.floating)) else 
                             int(v) if isinstance(v, (int, np.integer)) else 
                             str(v) if v is not None else None)
                        for k, v in analysis.items()
                    }
                except Exception as e:
                    print(f"   ❌ Error in analyze_message: {str(e)}")
                    import traceback
                    traceback.print_exc()
                    analysis = {
                        "error": str(e), 
                        "is_suspicious": False, 
                        "keywords": [],
                        "ml_ensemble_score": 0.0,
                        "virustotal_score": 0.0,
                        "final_score": 0.0,
                        "risk_level": "UNKNOWN"
                    }
            else:
                print(f"   ℹ️  Skipping analysis for '{intent}' intent")

            # Step 4 - Get LLM response (works for ALL intents)
            print("\n🤖 Step 4: Getting LLM response...")
            try:
                bot_reply = get_llm_response(user_input, analysis=analysis)
                print(f"   ✅ Response generated: {bot_reply[:80]}...")
            except Exception as e:
                print(f"   ❌ Error in get_llm_response: {str(e)}")
                import traceback
                traceback.print_exc()
                bot_reply = "I'm sorry, I encountered an error processing your request. Please try again."

            # Step 5 - Prepare response
            print("\n📦 Step 5: Preparing response...")
            
            if analysis:
                # If we have analysis (check/hybrid intent), return it
                response_data = {
                    "type": "analysis",
                    "response": bot_reply,
                    "analysis": analysis
                }
                print("   📊 Returning: analysis response")
            else:
                # For casual/learn intents, just return the message
                response_data = {
                    "type": "message",
                    "response": bot_reply
                }
                print("   💬 Returning: message response")
            
            # Test serialization
            try:
                json.dumps(response_data)
                print("   ✅ JSON serialization OK")
            except Exception as e:
                print(f"   ❌ Serialization error: {str(e)}")
                response_data = {
                    "type": "message",
                    "response": "I'm sorry, I encountered an error. Please try again."
                }
            
            print("="*60 + "\n")
            return jsonify(response_data)
            
        except Exception as e:
            print(f"\n💥 FATAL ERROR in chat endpoint: {str(e)}")
            import traceback
            traceback.print_exc()
            print("="*60 + "\n")
            return jsonify({
                "type": "message",
                "response": "I'm sorry, I encountered an unexpected error. Please try again later.",
                "error": str(e)
            }), 500
    
    
    @app.route('/report-resources', methods=['GET'])
    def report_resources():
        """Endpoint to get reporting resources"""
        try:
            resources = get_reporting_resources()
            return jsonify(resources)
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    
    
    @app.route('/quiz-feedback', methods=['POST'])
    def quiz_feedback():
        """Generate personalized LLM feedback for quiz answers"""
        print("\n📝 QUIZ FEEDBACK ENDPOINT CALLED")
        
        try:
            if not request.is_json:
                return jsonify({"error": "Request must be JSON"}), 400
            
            data = request.get_json()
            print(f"📥 Quiz data received: question={data.get('question', '')[:50]}...")
            
            question = data.get("question", "")
            selected_answer = data.get("selected_answer", "")
            correct_answer = data.get("correct_answer", "")
            is_correct = data.get("is_correct", False)
            category = data.get("category", "")
            user_score = data.get("user_score", 0)
            total_answered = data.get("total_answered", 1)
            
            if not question or not selected_answer or not correct_answer:
                print("❌ Missing required fields")
                return jsonify({"error": "Missing required fields"}), 400
            
            # Get feedback from LLM
            from .services.llm_service import get_quiz_feedback
            
            print(f"🤖 Generating feedback (correct={is_correct})...")
            feedback = get_quiz_feedback(
                question=question,
                selected_answer=selected_answer,
                correct_answer=correct_answer,
                is_correct=is_correct,
                category=category,
                user_score=user_score,
                total_answered=total_answered
            )
            
            print(f"✅ Feedback generated: {feedback[:80]}...")
            return jsonify({"feedback": feedback})
            
        except Exception as e:
            print(f"❌ Error in quiz feedback: {str(e)}")
            import traceback
            traceback.print_exc()
            return jsonify({
                "error": str(e),
                "feedback": "Unable to generate personalized feedback at this time. Please review the explanation above."
            }), 200  # Return 200 so frontend doesn't break
    
    
    # Test route
    @app.route('/test-js')
    def test_js():
        root_dir = os.path.dirname(os.getcwd())
        return send_from_directory(os.path.join(root_dir, 'static', 'js'), 'main.js')
        
    @app.route('/analyze-code', methods=['POST'])
    def analyze_code():
        """Endpoint to analyze code for security vulnerabilities"""
        print("\n🔍 CODE ANALYSIS ENDPOINT CALLED")
        
        try:
            if not request.is_json:
                return jsonify({"error": "Request must be JSON"}), 400
                
            data = request.get_json()
            code = data.get("code", "")
            language = data.get("language", "auto")
            use_ai = data.get("use_ai", True)
            
            if not code:
                return jsonify({"error": "Code is required"}), 400
                
            print(f"📝 Analyzing {len(code)} chars of {language} code (AI: {use_ai})")
            
            # Step 1: Run rule-based analysis
            print("🔍 Running rule-based analysis...")
            rule_results = analyze_code_security(code, language)
            
            rule_issues = rule_results.get("issues", [])
            rule_count = len(rule_issues)
            print(f"✅ Rule-based analysis complete: {rule_count} issues found")
            
            # Step 2: Run AI analysis if requested
            ai_results = {
                "ai_issues": [],
                "ai_fixes": code,
                "best_practices": [],
                "summary": "Static analysis only"
            }
            
            if use_ai:
                print("🤖 Running AI analysis...")
                try:
                    ai_results = analyze_code_with_ai(code, language, rule_issues)
                    print(f"✅ AI analysis complete: {len(ai_results.get('ai_issues', []))} issues found")
                except Exception as e:
                    print(f"❌ Error in AI analysis: {str(e)}")
                    ai_results["error"] = str(e)
            
            # Step 3: Combine results
            all_issues = rule_issues.copy()
            
            # Add AI issues with source field
            for ai_issue in ai_results.get("ai_issues", []):
                ai_issue["source"] = "ai"
                all_issues.append(ai_issue)
            
            # Generate diff if AI provided fixes
            diff = ""
            if ai_results.get("ai_fixes") and ai_results.get("ai_fixes") != code:
                try:
                    import difflib
                    d = difflib.Differ()
                    diff_lines = list(d.compare(code.splitlines(), ai_results.get("ai_fixes").splitlines()))
                    diff = "\n".join(diff_lines)
                except Exception as e:
                    diff = f"Error generating diff: {str(e)}"
            
            # Prepare response
            response = {
                "issues": all_issues,
                "rule_based_count": rule_count,
                "ai_count": len(ai_results.get("ai_issues", [])),
                "summary": ai_results.get("summary", "Analysis complete"),
                "best_practices": ai_results.get("best_practices", []),
                "fixed_code": ai_results.get("ai_fixes", code),
                "diff": diff
            }
            
            return jsonify(response)
            
        except Exception as e:
            print(f"❌ Error in code analysis: {str(e)}")
            import traceback
            traceback.print_exc()
            return jsonify({
                "error": str(e),
                "issues": [],
                "summary": f"Analysis failed: {str(e)}"
            }), 500