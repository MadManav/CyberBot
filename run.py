import os
from cyberbot import create_app

app = create_app()

if __name__ == '__main__':
    # Get port from environment variable or use 5000 as default
    port = int(os.environ.get('PORT', 5000))
    
    # Run the app with debug mode and auto-reloader
    app.run(
        host='0.0.0.0',
        port=port,
        debug=True,
        use_reloader=True,
        use_debugger=True,
        threaded=True
    )
    
    # Print a message to confirm the app is runn
    print(f"\n\n*** Application is running on http://localhost:{port} ***\n")