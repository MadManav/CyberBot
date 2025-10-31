import os
from flask import Flask, send_from_directory

def create_app():
    # Get the root path of the project
    root_path = os.path.abspath(os.path.dirname(__file__))
    static_path = os.path.join(root_path, '..', 'static')
    
    # Initialize Flask app with explicit static folder
    app = Flask(__name__, 
                static_folder=static_path,
                template_folder='templates')
    
    # Enable debug mode for better error messages
    app.config['DEBUG'] = True
    
    # Add a route to serve static files
    @app.route('/static/<path:path>')
    def serve_static(path):
        return send_from_directory(static_path, path)
    
    # Import and initialize routes
    from . import routes
    routes.init_routes(app)
    
    return app