import logging, time
from flask import Flask, request, session, redirect, url_for, render_template, jsonify
from main import get_orchestrator
from config import Config

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='templates')
app.secret_key = Config.SECRET_KEY
app.config['DEBUG'] = Config.DEBUG
# Ensure session cookie is sent on cross-site POSTs from the IdP (SAML ACS)
# Modern browsers block cookies on third-party POSTs unless SameSite=None and Secure=True
app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
)

orchestrator = get_orchestrator()

# Log minimal SAML configuration at startup to help diagnose misconfigurations
try:
    logger.info(
        "SAML config: SP_ACS=%s, SP_ENTITY=%s, IDP_SSO=%s, IDP_ENTITY=%s, IDP_CERT_PRESENT=%s",
        Config.SAML_SP_ACS_URL,
        Config.SAML_SP_ENTITY_ID,
        Config.SAML_IDP_SSO_URL,
        Config.SAML_IDP_ENTITY_ID,
        bool(Config.SAML_IDP_X509_CERT),
    )
except Exception:
    logger.exception("Failed to log SAML config")

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

@app.route('/login', methods=['POST'])
def login():
    try:
        result = orchestrator.process_authentication_request(request)
        if not result.get('success'):
            session['error'] = result.get('error', 'Authentication failed')
            return redirect(url_for('index'))
        action = result.get('action')
        if action == 'redirect_to_idp':
            return redirect(result.get('redirect_url'))
        elif action == 'session_valid':
            session['authenticated'] = True
            session['user_info'] = result.get('user_info')
            session['session_data'] = result.get('session_data')
            return redirect(url_for('credentials'))
        session['error'] = 'Unexpected authentication result'
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"Login error: {e}")
        session['error'] = 'Login failed'
        return redirect(url_for('index'))

@app.route('/saml/login')
def saml_login():
    """Initiate SAML login flow"""
    try:
        from onelogin.saml2.auth import OneLogin_Saml2_Auth as Auth
        # Log the OneLogin settings being used (non-sensitive)
        try:
            logger.debug("OneLogin settings: %s", orchestrator.token_validator.saml_settings)
        except Exception:
            logger.exception("Failed to log OneLogin settings")

        auth = Auth(orchestrator.token_validator._prepare_flask_request(request),
                    orchestrator.token_validator.saml_settings)
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

@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    try:
        result = orchestrator.process_authentication_request(request)
        if not result.get('success'):
            session['error'] = result.get('error', 'SAML authentication failed')
            return redirect(url_for('index'))
        action = result.get('action')
        if action == 'mfa_required':
            session['temp_user_info'] = result.get('user_info')
            session['temp_saml_data'] = result.get('saml_data')
            return render_template('mfa.html',
                                   username=result.get('user_info', {}).get('username'),
                                   transaction_id=result.get('transaction_id'),
                                   challenge_message=result.get('mfa_challenge', {}).get('message'))
        elif action == 'saml_authenticated':
            user_info = result.get('user_info')
            saml_data = result.get('saml_data')
            session['authenticated'] = True
            session['user_info'] = user_info
            session['saml_nameid'] = saml_data.get('nameid')
            session['saml_session_index'] = saml_data.get('session_index')
            session['timestamp'] = time.time()
            return redirect(url_for('credentials'))
        session['error'] = 'Unexpected SAML response'
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"SAML ACS error: {e}")
        session['error'] = 'SAML authentication failed'
        return redirect(url_for('index'))

@app.route('/mfa/verify', methods=['POST'])
def mfa_verify():
    try:
        result = orchestrator.process_authentication_request(request)
        if result.get('success') and result.get('action') == 'mfa_authenticated':
            user_info = result.get('user_info')
            saml_data = result.get('saml_data')
            session['authenticated'] = True
            session['user_info'] = user_info
            session['saml_nameid'] = saml_data.get('nameid')
            session['saml_session_index'] = saml_data.get('session_index')
            session['timestamp'] = time.time()
            session.pop('temp_user_info', None)
            session.pop('temp_saml_data', None)
            return redirect(url_for('credentials'))
        error = result.get('error', 'MFA verification failed')
        return render_template('mfa.html',
                               username=request.form.get('username'),
                               transaction_id=request.form.get('transaction_id'),
                               error=error)
    except Exception as e:
        logger.error(f"MFA verification error: {e}")
        return render_template('mfa.html',
                               username=request.form.get('username'),
                               transaction_id=request.form.get('transaction_id'),
                               error='MFA verification failed')

@app.route('/credentials')
def credentials():
    if not session.get('authenticated'):
        return redirect(url_for('index'))
    try:
        user_info = session.get('user_info', {})
        session_data = {'nameid': session.get('saml_nameid'), 'session_index': session.get('saml_session_index')}
        result = orchestrator.process_credential_request(user_info, session_data)
        if not result.get('success'):
            session['error'] = result.get('error', 'Failed to generate credentials')
            return redirect(url_for('index'))
        credentials = result.get('credentials')
        session['credential_id'] = credentials.get('credential_id')
        return render_template('credentials.html', user_info=user_info, credentials=credentials)
    except Exception as e:
        logger.error(f"Credentials error: {e}")
        session['error'] = 'Failed to generate credentials'
        return redirect(url_for('index'))

@app.route('/status')
def status():
    try:
        status_info = orchestrator.get_system_status()
        if not status_info.get('success'):
            return jsonify({'error': 'Failed to get status'}), 500
        return render_template('status.html', status=status_info)
    except Exception as e:
        logger.error(f"Status error: {e}")
        return jsonify({'error': 'Failed to get status'}), 500

@app.route('/logout')
def logout():
    try:
        orchestrator.process_logout_request({'session': session})
        session.clear()
        session['info'] = 'Logged out'
        return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"Logout error: {e}")
        session.clear()
        session['info'] = 'Logged out'
        return redirect(url_for('index'))
