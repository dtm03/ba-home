import logging
import os
import sys
import time
from flask import Flask, request, session, redirect, url_for, render_template, jsonify
from orchestrator import get_orchestrator
from config import Config

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY
app.config['DEBUG'] = Config.DEBUG
app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
)

orchestrator = get_orchestrator()

# Log SAML config at startup
try:
    logger.debug(
        "SAML config: SP_ACS=%s, SP_ENTITY=%s, IDP_SSO=%s, IDP_ENTITY=%s, IDP_CERT_PRESENT=%s",
        Config.SAML_SP_ACS_URL,
        Config.SAML_SP_ENTITY_ID,
        Config.SAML_IDP_SSO_URL,
        Config.SAML_IDP_ENTITY_ID,
        bool(Config.SAML_IDP_X509_CERT),
    )
except Exception:
    logger.exception("Failed to log SAML config")

# Format timestamps for all templates
@app.template_filter('timestamp_to_date')
def timestamp_to_date(ts):
    import datetime
    return datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')

@app.route('/')
def index():
    if session.get('authenticated'):
        return redirect(url_for('credentials'))
    error = session.pop('error', None)
    info = session.pop('info', None)
    return render_template('login.html', config=Config, error=error, info=info)

@app.route('/login', methods=['GET', 'POST'], endpoint='login')
def saml_login():
    """Initiate SAML login flow"""
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth as Auth
        auth = Auth(orchestrator.saml_token_validator._prepare_flask_request(request),
                    orchestrator.saml_token_validator.saml_settings)
        redirect_url = auth.login()
        logger.info("SAML login redirect URL: %s", redirect_url)
        if not redirect_url:
            logger.error("Auth.login() returned no redirect URL")
            session['error'] = 'Failed to initiate SAML login'
            return redirect(url_for('index'))
        return redirect(redirect_url)
    except Exception as e:
        logger.error(f"SAML login error: {e}")
        session['error'] = 'SAML login failed'
        return redirect(url_for('index'))

@app.route('/acs', methods=['POST'])
def acs():
    """Assertion Consumer Service endpoint."""
    try:
        saml_response = request.form
        result = orchestrator.process_saml_response(saml_response)

        if not result.get('success'):
            session['error'] = result.get('error')
            return redirect(url_for('index'))

        session['authenticated'] = True
        session['user_info'] = result['user_info']
        session['saml_nameid'] = result['saml_data']['nameid']
        session['saml_session_index'] = result['saml_data']['session_index']
        session['timestamp'] = time.time()

        return redirect(url_for('credentials'))
    except Exception as e:
        logger.error(f"SAML ACS error: {e}")
        session['error'] = 'SAML authentication failed'
        return redirect(url_for('index'))
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
