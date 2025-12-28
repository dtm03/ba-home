import logging
import os
import sys
import time
from flask import Flask, request, session, redirect, url_for, render_template, jsonify
from orchestrator import get_orchestrator
from config import Config
from ldap3 import Server, Connection, ALL

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
    # Validate SAML configuration
    missing_config = []
    if not Config.SAML_SP_ENTITY_ID:
        missing_config.append('SAML_SP_ENTITY_ID')
    if not Config.SAML_SP_ACS_URL:
        missing_config.append('SAML_SP_ACS_URL')
    if not Config.SAML_IDP_ENTITY_ID:
        missing_config.append('SAML_IDP_ENTITY_ID')
    if not Config.SAML_IDP_SSO_URL:
        missing_config.append('SAML_IDP_SSO_URL')
    if not Config.SAML_IDP_X509_CERT:
        missing_config.append('SAML_IDP_X509_CERT')
    
    if missing_config:
        logger.error(f"SAML configuration incomplete. Missing: {', '.join(missing_config)}")
        session['error'] = f'SAML configuration incomplete. Missing: {", ".join(missing_config)}'
        return redirect(url_for('index'))
    
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth as Auth
        auth = Auth(orchestrator.saml_token_validator._prepare_flask_request(request),
                    orchestrator.saml_token_validator.saml_settings)
        redirect_url= auth.login(force_authn=True)
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
        result = orchestrator.process_saml_response(request)

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


@app.route('/credentials')
def credentials():
    """Show temporary LDAP credentials for authenticated user."""
    if not session.get('authenticated'):
        session['error'] = 'Please authenticate first'
        return redirect(url_for('index'))

    user_info = session.get('user_info', {})
    try:
        credentials = orchestrator.ldap_credential_generator.generate_temporary_credentials(user_info)
    except Exception as e:
        logger.error(f"Failed to generate credentials: {e}")
        session['error'] = 'Failed to generate credentials'
        return redirect(url_for('index'))

    return render_template('credentials.html', user_info=user_info, credentials=credentials)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


@app.route('/demo')
def demo():
    """Show demo LDAP login page with pre-filled username."""
    if not session.get('authenticated'):
        session['error'] = 'Please authenticate first'
        return redirect(url_for('index'))
    
    user_info = session.get('user_info', {})
    username = user_info.get('username', '')
    email = user_info.get('email', '')
    demo_result = session.pop('demo_result', None)
    
    return render_template('demo.html', username=username, email=email, demo_result=demo_result)


@app.route('/demo_test', methods=['POST'])
def demo_test():
    """Test LDAP login with the provided credentials."""
    if not session.get('authenticated'):
        session['error'] = 'Please authenticate first'
        return redirect(url_for('index'))
    
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    if not username or not password:
        session['demo_result'] = {'success': False, 'error': 'Username and password are required'}
        return redirect(url_for('demo'))
    
    try:
        ldap_host = Config.LDAP_HOST if Config.LDAP_HOST and Config.LDAP_HOST != 'localhost' else os.getenv('LDAP_HOST', 'openldap')
        ldap_port = Config.LDAP_PORT
        server = Server(ldap_host, port=ldap_port, get_info=ALL)
        
        ldap_base_dn = Config.LDAP_BASE_DN or os.getenv('LDAP_BASE_DN') or 'dc=outlook,dc=de'
        bind_dn = f"uid={username},ou=people,{ldap_base_dn}"
        
        conn = Connection(server, user=bind_dn, password=password, auto_bind=True)
        conn.unbind()
        
        logger.info(f"LDAP test login successful for {username}")
        session['demo_result'] = {
            'success': True,
            'message': f'Successfully logged in as {username}!'
        }
    except Exception as e:
        logger.error(f"LDAP test login failed for {username}: {e}")
        session['demo_result'] = {
            'success': False,
            'error': f'Login failed: {str(e)}'
        }
    
    return redirect(url_for('demo'))


@app.route('/api/ldap/change-password', methods=['POST'])
def api_change_ldap_password():
    """Change LDAP user's password by mail address. JSON: {"mail":..., "new_password":...}
    Binds as the configured LDAP admin and uses the password modify extended operation.
    """
    data = request.get_json(force=True, silent=True) or {}
    mail = data.get('mail')
    new_password = data.get('new_password')
    if not mail or not new_password:
        return jsonify({'success': False, 'error': 'mail and new_password are required'}), 400

    ldap_host = Config.LDAP_HOST if Config.LDAP_HOST and Config.LDAP_HOST != 'localhost' else os.getenv('LDAP_HOST', 'openldap')
    ldap_port = Config.LDAP_PORT
    server = Server(ldap_host, port=ldap_port, get_info=ALL)

    bind_dn = Config.LDAP_BIND_DN or os.getenv('LDAP_BIND_DN') or f"cn=admin,{os.getenv('LDAP_BASE_DN', Config.LDAP_BASE_DN or 'dc=outlook,dc=de')}"
    bind_password = Config.LDAP_BIND_PASSWORD or os.getenv('LDAP_BIND_PASSWORD') or os.getenv('LDAP_ADMIN_PASSWORD', 'admin')

    try:
        conn = Connection(server, user=bind_dn, password=bind_password, auto_bind=True)
    except Exception as e:
        return jsonify({'success': False, 'error': f'Failed to bind to LDAP as admin: {e}'}), 500

    search_base = Config.LDAP_BASE_DN or os.getenv('LDAP_BASE_DN') or 'dc=outlook,dc=de'
    try:
        conn.search(search_base, f"(mail={mail})", attributes=['dn'])
        if not conn.entries:
            conn.unbind()
            return jsonify({'success': False, 'error': 'user not found'}), 404
        user_dn = conn.entries[0].entry_dn
    except Exception as e:
        conn.unbind()
        return jsonify({'success': False, 'error': f'LDAP search failed: {e}'}), 500

    try:
        # Use password modify extended operation; ldap3 returns True on success
        result = conn.extend.standard.modify_password(user_dn, new_password)
        conn.unbind()
        if result:
            return jsonify({'success': True})
        else:
            return jsonify({'success': False, 'error': 'password change failed'}), 500
    except Exception as e:
        try:
            conn.unbind()
        except Exception:
            pass
        return jsonify({'success': False, 'error': f'password modify exception: {e}'}), 500

if __name__ == '__main__':
    logger.info("Starting SAML-LDAP Bridge application")
    try:
        logger.info("CWD: %s", os.getcwd())
        logger.info("Cert exists: %s", os.path.exists(Config.SSL_CERT_PATH))
        logger.info("Key exists: %s", os.path.exists(Config.SSL_KEY_PATH))
        logger.info("Cert path: %s", Config.SSL_CERT_PATH)
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
