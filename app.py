import logging
import os
import sys
from flask import Flask
from routes import app as web_app
from demo_interface import register_demo_routes
from config import Config
from main import orchestrator

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)

logger = logging.getLogger(__name__)

def create_app():
    app = web_app
    register_demo_routes(app)
    
    @app.route('/main')
    def main_interface():
        return app.view_functions['index']()
    
    logger.info("SAML-LDAP Bridge application created successfully")
    return app

app = create_app()

if __name__ == '__main__':
    logger.info("Starting SAML-LDAP Bridge application")
    try:
        if os.path.exists(Config.SSL_CERT_PATH) and os.path.exists(Config.SSL_KEY_PATH):
            logger.info("Starting with HTTPS on port 5000")
            app.run(host='0.0.0.0', port=5000,
                    ssl_context=(Config.SSL_CERT_PATH, Config.SSL_KEY_PATH),
                    debug=Config.DEBUG)
        else:
            logger.warning("SSL certificates not found, starting with HTTP")
            app.run(host='0.0.0.0', port=5000, debug=Config.DEBUG)
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
        sys.exit(1)
