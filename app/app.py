import logging
import sys
import time
from flask import Flask, request, session, redirect, url_for, render_template, jsonify
from config import Config
from orchestrator import orchestrator

logging.basicConfig(
    level=logging.DEBUG if Config.DEBUG else logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = Config.SECRET_KEY

app.config.update(
    SESSION_COOKIE_SAMESITE='None',
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
)

@app.route('/')
def index():
    if session.get('authenticated'):
        return redirect(url_for('credentials'))
    return render_template('login.html', error=session.pop('error', None))

@app.route('/login', methods=['GET', 'POST'], endpoint='login')
def saml_login():
    try:
        return redirect(orchestrator.get_login_url(request))
    except Exception as e:
        logger.error(f"SAML-Redirect failed: {e}")
        session['error'] = "Authentification couldn't be started."
        return redirect(url_for('index'))

@app.route('/acs', methods=['POST'])
def acs():
    result = orchestrator.process_saml_response(request)
    if not result['success']:
        session['error'] = result['error']
        return redirect(url_for('index'))
    
    session.update({
        'authenticated': True,
        'user_info': result['user_info'],
        'saml_nameid': result['saml_data']['nameid'],
        'timestamp': time.time()
    })
    return redirect(url_for('credentials'))

@app.route('/credentials')
def credentials():
    if not session.get('authenticated'):
        return redirect(url_for('index'))
    
    creds = orchestrator.get_ldap_credentials(session['user_info'])
    return render_template('credentials.html', 
                           user_info=session['user_info'], 
                           credentials=creds)

@app.route('/demo')
def demo():
    if not session.get('authenticated'):
        return redirect(url_for('index'))
    
    return render_template('demo.html', 
                           username=session['user_info'].get('username'),
                           demo_result=session.pop('demo_result', None))

@app.route('/demo_test', methods=['POST'])
def demo_test():
    if not session.get('authenticated'):
        return redirect(url_for('index')), 403
        
    username = request.form.get('username')
    password = request.form.get('password')
    
    res = orchestrator.test_ldap_login(username, password)
    session['demo_result'] = res
    return redirect(url_for('demo'))

@app.route('/api/ldap/change-password', methods=['POST'])
def api_change_password():
    data = request.get_json() or {}
    res = orchestrator.change_ldap_password(data.get('mail'), data.get('new_password'))
    return jsonify(res), 200 if res['success'] else 400

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    cert, key = Config.SSL_CERT_PATH, Config.SSL_KEY_PATH
    if cert and key:
        app.run(host='0.0.0.0', port=5000, ssl_context=(cert, key), debug=Config.DEBUG)
    else:
        logger.warning("Starting without SSL (Authentication won't work)")
        app.run(host='0.0.0.0', port=5000, debug=Config.DEBUG)