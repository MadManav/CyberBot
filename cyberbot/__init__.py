import os
from flask import Flask, send_from_directory, url_for

def create_app():
    # Get the root path of the project
    root_path = os.path.abspath(os.path.dirname(__file__))
    
    # Initialize Flask app with explicit static folder
    app = Flask(__name__, 
                static_folder='static',
                static_url_path='/static',
                template_folder='templates')
    
    # Enable debug mode for better error messages
    app.config['DEBUG'] = True
    
    # Add a test route to verify static file serving
    @app.route('/test-static')
    def test_static():
        return f"""
        <h1>Static File Test</h1>
        <p>Static URL for quiz.js: {url_for('static', filename='js/quiz.js')}</p>
        <p>Static URL for questions.json: {url_for('static', filename='questions.json')}</p>
        """
    
    # Import and initialize routes
    from . import routes
    routes.init_routes(app)
    
    return app