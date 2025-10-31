from flask import Flask

def create_app():
    app = Flask(__name__)
    
    # Import and initialize routes
    from . import routes
    routes.init_routes(app)
    
    return app