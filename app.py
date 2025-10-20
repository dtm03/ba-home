"""
SAML-LDAP Bridge Application Entry Point
Main Flask application that combines all components
"""
import logging
import os
import sys
from flask import Flask
from web_interface import app as web_app
from demo_interface import register_demo_routes
from config import Config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('saml_ldap_bridge.log'),
        logging.StreamHandler(sys.stdout)
    ]
)

logger = logging.getLogger(__name__)

def create_app():
    """
    Application factory function
    Creates and configures the Flask application
    """
    app = web_app
    
    # Register demo routes
    register_demo_routes(app)
    
    # Add some additional routes for the combined app
    @app.route('/health')
    def health_check():
        """Health check endpoint"""
        return {'status': 'healthy', 'service': 'saml-ldap-bridge'}, 200
    
    @app.route('/info')
    def app_info():
        """Application information endpoint"""
        return {
            'name': 'SAML-LDAP Bridge',
            'version': '1.0.0',
            'description': 'Bridge service for SAML authentication to LDAP credentials',
            'endpoints': {
                'main': '/',
                'login': '/login',
                'saml_acs': '/saml/acs',
                'demo': '/demo',
                'api_validate': '/api/validate',
                'status': '/status',
                'health': '/health'
            }
        }
    
    # Add main interface route alias
    @app.route('/main')
    def main_interface():
        """Alias for main interface"""
        return app.view_functions['index']()
    
    logger.info("SAML-LDAP Bridge application created successfully")
    return app

# Create the application instance
app = create_app()

if __name__ == '__main__':
    logger.info("Starting SAML-LDAP Bridge application")
    
    try:
        # Check if SSL certificates exist
        if os.path.exists(Config.SSL_CERT_PATH) and os.path.exists(Config.SSL_KEY_PATH):
            logger.info(f"Starting with HTTPS on port 5000")
            app.run(
                host='0.0.0.0',
                port=5000,
                ssl_context=(Config.SSL_CERT_PATH, Config.SSL_KEY_PATH),
                debug=Config.DEBUG
            )
        else:
            logger.warning("SSL certificates not found, starting with HTTP")
            logger.warning("For production use, please configure SSL certificates")
            app.run(
                host='0.0.0.0',
                port=5000,
                debug=Config.DEBUG
            )
    except Exception as e:
        logger.error(f"Failed to start application: {str(e)}")
        sys.exit(1)