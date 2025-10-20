"""
Web Interface for SAML-LDAP Bridge
Flask application providing web interface for authentication flow
"""
import logging
import time
from flask import Flask, request, session, redirect, url_for, render_template_string, jsonify, flash
from main import get_orchestrator
from config import Config

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Create Flask app
app = Flask(__name__)
app.secret_key = Config.SECRET_KEY
app.config['DEBUG'] = Config.DEBUG

# Get orchestrator instance
orchestrator = get_orchestrator()

# HTML Templates
LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAML-LDAP Bridge - Login</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .card { border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin: 20px 0; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        .btn:hover { background: #0056b3; }
        .error { color: #dc3545; background: #f8d7da; padding: 10px; border-radius: 4px; margin: 10px 0; }
        .info { color: #0c5460; background: #d1ecf1; padding: 10px; border-radius: 4px; margin: 10px 0; }
        .form-group { margin: 15px 0; }
        .form-control { width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; }
    </style>
</head>
<body>
    <h1>SAML-LDAP Bridge Authentication</h1>
    
    {% if error %}
    <div class="error">{{ error }}</div>
    {% endif %}
    
    {% if info %}
    <div class="info">{{ info }}</div>
    {% endif %}
    
    <div class="card">
        <h2>Login</h2>
        <p>Click the button below to authenticate using your institutional credentials.</p>
        <form method="post" action="{{ url_for('login') }}">
            <button type="submit" class="btn">Login with SAML</button>
        </form>
    </div>
    
    <div class="card">
        <h3>System Information</h3>
        <p><strong>SAML Identity Provider:</strong> {{ config.SAML_IDP_ENTITY_ID }}</p>
        <p><strong>eduMFA Integration:</strong> {{ 'Enabled' if config.EDUMFA_API_KEY else 'Disabled' }}</p>
        <p><strong>LDAP Server:</strong> {{ config.LDAP_HOST }}:{{ config.LDAP_PORT }}</p>
    </div>
</body>
</html>
"""

MFA_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAML-LDAP Bridge - MFA Required</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; }
        .card { border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin: 20px 0; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; }
        .btn:hover { background: #0056b3; }
        .error { color: #dc3545; background: #f8d7da; padding: 10px; border-radius: 4px; margin: 10px 0; }
        .form-group { margin: 15px 0; }
        .form-control { width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; }
        .challenge { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; border-radius: 4px; margin: 10px 0; }
    </style>
</head>
<body>
    <h1>Multi-Factor Authentication Required</h1>
    
    {% if error %}
    <div class="error">{{ error }}</div>
    {% endif %}
    
    <div class="card">
        <h2>Hello, {{ username }}!</h2>
        <p>Please complete the multi-factor authentication to continue.</p>
        
        {% if challenge_message %}
        <div class="challenge">
            <strong>Challenge:</strong> {{ challenge_message }}
        </div>
        {% endif %}
        
        <form method="post" action="{{ url_for('mfa_verify') }}">
            <input type="hidden" name="transaction_id" value="{{ transaction_id }}">
            <input type="hidden" name="username" value="{{ username }}">
            
            <div class="form-group">
                <label for="mfa_code">Enter your MFA code:</label>
                <input type="text" id="mfa_code" name="mfa_code" class="form-control" required autocomplete="off">
            </div>
            
            <button type="submit" class="btn">Verify</button>
        </form>
    </div>
</body>
</html>
"""

CREDENTIALS_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAML-LDAP Bridge - Temporary Credentials</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1000px; margin: 50px auto; padding: 20px; }
        .card { border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin: 20px 0; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn:hover { background: #0056b3; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .success { color: #155724; background: #d4edda; padding: 10px; border-radius: 4px; margin: 10px 0; }
        .credentials { background: #f8f9fa; border: 1px solid #dee2e6; padding: 15px; border-radius: 4px; font-family: monospace; }
        .copy-btn { background: #28a745; font-size: 12px; padding: 5px 10px; margin-left: 10px; }
        .copy-btn:hover { background: #218838; }
        .user-info { background: #e7f3ff; border: 1px solid #b3d9ff; padding: 15px; border-radius: 4px; }
        table { width: 100%; border-collapse: collapse; }
        table th, table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        table th { background-color: #f8f9fa; }
    </style>
    <script>
        function copyToClipboard(text) {
            navigator.clipboard.writeText(text).then(function() {
                alert('Copied to clipboard!');
            });
        }
    </script>
</head>
<body>
    <h1>Authentication Successful</h1>
    
    <div class="success">
        Welcome, {{ user_info.display_name or user_info.username }}! Your temporary LDAP credentials have been generated.
    </div>
    
    <div class="card">
        <h2>User Information</h2>
        <div class="user-info">
            <table>
                <tr><td><strong>Username:</strong></td><td>{{ user_info.username }}</td></tr>
                <tr><td><strong>Name:</strong></td><td>{{ user_info.display_name or (user_info.first_name + ' ' + user_info.last_name) if user_info.first_name else user_info.username }}</td></tr>
                <tr><td><strong>Email:</strong></td><td>{{ user_info.email or 'Not provided' }}</td></tr>
                {% if user_info.affiliation %}
                <tr><td><strong>Affiliation:</strong></td><td>{{ user_info.affiliation }}</td></tr>
                {% endif %}
                {% if user_info.groups %}
                <tr><td><strong>Groups:</strong></td><td>{{ user_info.groups if user_info.groups is string else ', '.join(user_info.groups) }}</td></tr>
                {% endif %}
            </table>
        </div>
    </div>
    
    <div class="card">
        <h2>Temporary LDAP Credentials</h2>
        <p><strong>⚠️ Important:</strong> These credentials are temporary and will expire at {{ credentials.expires_at }}.</p>
        
        <div class="credentials">
            <div><strong>LDAP Server:</strong> {{ credentials.ldap_server }}:{{ credentials.ldap_port }}
                <button class="btn copy-btn" onclick="copyToClipboard('{{ credentials.ldap_server }}:{{ credentials.ldap_port }}')">Copy</button>
            </div>
            <br>
            <div><strong>Bind DN:</strong> {{ credentials.bind_dn }}
                <button class="btn copy-btn" onclick="copyToClipboard('{{ credentials.bind_dn }}')">Copy</button>
            </div>
            <br>
            <div><strong>Password:</strong> <span id="password">{{ credentials.password }}</span>
                <button class="btn copy-btn" onclick="copyToClipboard('{{ credentials.password }}')">Copy</button>
            </div>
        </div>
        
        <h3>Connection Examples</h3>
        <div class="credentials">
            <p><strong>ldapsearch command:</strong></p>
            <code>ldapsearch -H ldap://{{ credentials.ldap_server }}:{{ credentials.ldap_port }} -D "{{ credentials.bind_dn }}" -W -b "{{ credentials.bind_dn }}"</code>
            <button class="btn copy-btn" onclick="copyToClipboard('ldapsearch -H ldap://{{ credentials.ldap_server }}:{{ credentials.ldap_port }} -D \"{{ credentials.bind_dn }}\" -W -b \"{{ credentials.bind_dn }}\"')">Copy</button>
        </div>
    </div>
    
    <div class="card">
        <h2>Actions</h2>
        <a href="/demo" class="btn">Test LDAP Connection</a>
        <a href="/status" class="btn">System Status</a>
        <a href="/logout" class="btn btn-danger">Logout</a>
    </div>
</body>
</html>
"""

STATUS_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAML-LDAP Bridge - System Status</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1000px; margin: 50px auto; padding: 20px; }
        .card { border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin: 20px 0; }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }
        .btn:hover { background: #0056b3; }
        .status-good { color: #155724; background: #d4edda; padding: 10px; border-radius: 4px; }
        .status-warning { color: #856404; background: #fff3cd; padding: 10px; border-radius: 4px; }
        table { width: 100%; border-collapse: collapse; }
        table th, table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        table th { background-color: #f8f9fa; }
    </style>
</head>
<body>
    <h1>System Status</h1>
    
    <div class="card">
        <h2>Service Status</h2>
        <div class="status-good">
            ✅ SAML-LDAP Bridge is running
        </div>
        
        <table style="margin-top: 20px;">
            <tr><td><strong>Status:</strong></td><td>{{ status.status }}</td></tr>
            <tr><td><strong>Active Credentials:</strong></td><td>{{ status.active_credentials }}</td></tr>
            <tr><td><strong>Last Updated:</strong></td><td>{{ status.timestamp | int | timestamp_to_date }}</td></tr>
        </table>
    </div>
    
    <div class="card">
        <h2>Configuration</h2>
        <table>
            <tr><td><strong>SAML SP Entity ID:</strong></td><td>{{ status.configuration.saml_sp_entity_id }}</td></tr>
            <tr><td><strong>SAML IdP Entity ID:</strong></td><td>{{ status.configuration.saml_idp_entity_id }}</td></tr>
            <tr><td><strong>eduMFA Integration:</strong></td><td>{{ 'Enabled' if status.configuration.edumfa_configured else 'Disabled' }}</td></tr>
            <tr><td><strong>LDAP Server:</strong></td><td>{{ status.configuration.ldap_host }}:{{ status.configuration.ldap_port }}</td></tr>
        </table>
    </div>
    
    <div class="card">
        <h2>Actions</h2>
        <a href="/" class="btn">Back to Login</a>
        {% if session.get('authenticated') %}
        <a href="/credentials" class="btn">View Credentials</a>
        <a href="/demo" class="btn">Test LDAP</a>
        {% endif %}
    </div>
</body>
</html>
"""

@app.template_filter('timestamp_to_date')
def timestamp_to_date(timestamp):
    """Convert timestamp to readable date"""
    import datetime
    return datetime.datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')

@app.route('/')
def index():
    """Main page - login or show credentials"""
    if session.get('authenticated'):
        return redirect(url_for('credentials'))
    
    error = session.pop('error', None)
    info = session.pop('info', None)
    
    return render_template_string(LOGIN_TEMPLATE, 
                                config=Config, 
                                error=error, 
                                info=info)

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Handle login request"""
    if request.method == 'GET':
        return redirect(url_for('index'))
    
    try:
        # Process authentication request
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
        
        else:
            session['error'] = 'Unexpected authentication result'
            return redirect(url_for('index'))
            
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        session['error'] = 'Login failed'
        return redirect(url_for('index'))

@app.route('/saml/acs', methods=['POST'])
def saml_acs():
    """SAML Assertion Consumer Service"""
    try:
        # Process SAML response
        result = orchestrator.process_authentication_request(request)
        
        if not result.get('success'):
            session['error'] = result.get('error', 'SAML authentication failed')
            return redirect(url_for('index'))
        
        action = result.get('action')
        
        if action == 'mfa_required':
            # Store temporary data in session
            session['temp_user_info'] = result.get('user_info')
            session['temp_saml_data'] = result.get('saml_data')
            
            return render_template_string(MFA_TEMPLATE,
                                        username=result.get('user_info', {}).get('username'),
                                        transaction_id=result.get('transaction_id'),
                                        challenge_message=result.get('mfa_challenge', {}).get('message'))
        
        elif action == 'saml_authenticated':
            # Complete authentication
            user_info = result.get('user_info')
            saml_data = result.get('saml_data')
            
            session['authenticated'] = True
            session['user_info'] = user_info
            session['saml_nameid'] = saml_data.get('nameid')
            session['saml_session_index'] = saml_data.get('session_index')
            session['timestamp'] = time.time()
            
            return redirect(url_for('credentials'))
        
        else:
            session['error'] = 'Unexpected SAML response'
            return redirect(url_for('index'))
            
    except Exception as e:
        logger.error(f"SAML ACS error: {str(e)}")
        session['error'] = 'SAML authentication failed'
        return redirect(url_for('index'))

@app.route('/mfa/verify', methods=['POST'])
def mfa_verify():
    """Verify MFA code"""
    try:
        # Process MFA response
        result = orchestrator.process_authentication_request(request)
        
        if not result.get('success'):
            error = result.get('error', 'MFA verification failed')
            
            return render_template_string(MFA_TEMPLATE,
                                        username=request.form.get('username'),
                                        transaction_id=request.form.get('transaction_id'),
                                        error=error)
        
        action = result.get('action')
        
        if action == 'mfa_authenticated':
            # Complete authentication
            user_info = result.get('user_info')
            saml_data = result.get('saml_data')
            
            session['authenticated'] = True
            session['user_info'] = user_info
            session['saml_nameid'] = saml_data.get('nameid')
            session['saml_session_index'] = saml_data.get('session_index')
            session['timestamp'] = time.time()
            
            # Clean up temporary session data
            session.pop('temp_user_info', None)
            session.pop('temp_saml_data', None)
            
            return redirect(url_for('credentials'))
        
        else:
            session['error'] = 'MFA verification failed'
            return redirect(url_for('index'))
            
    except Exception as e:
        logger.error(f"MFA verification error: {str(e)}")
        return render_template_string(MFA_TEMPLATE,
                                    username=request.form.get('username'),
                                    transaction_id=request.form.get('transaction_id'),
                                    error='MFA verification failed')

@app.route('/credentials')
def credentials():
    """Show temporary credentials"""
    if not session.get('authenticated'):
        return redirect(url_for('index'))
    
    try:
        user_info = session.get('user_info', {})
        session_data = {
            'nameid': session.get('saml_nameid'),
            'session_index': session.get('saml_session_index')
        }
        
        # Generate temporary credentials
        result = orchestrator.process_credential_request(user_info, session_data)
        
        if not result.get('success'):
            session['error'] = result.get('error', 'Failed to generate credentials')
            return redirect(url_for('index'))
        
        credentials = result.get('credentials')
        session['credential_id'] = credentials.get('credential_id')
        
        return render_template_string(CREDENTIALS_TEMPLATE,
                                    user_info=user_info,
                                    credentials=credentials)
        
    except Exception as e:
        logger.error(f"Credentials error: {str(e)}")
        session['error'] = 'Failed to generate credentials'
        return redirect(url_for('index'))

@app.route('/status')
def status():
    """Show system status"""
    try:
        status_info = orchestrator.get_system_status()
        
        if not status_info.get('success'):
            return jsonify({'error': 'Failed to get status'}), 500
        
        return render_template_string(STATUS_TEMPLATE, status=status_info)
        
    except Exception as e:
        logger.error(f"Status error: {str(e)}")
        return jsonify({'error': 'Failed to get status'}), 500

@app.route('/logout')
def logout():
    """Logout"""
    try:
        # Process logout request
        result = orchestrator.process_logout_request({'session': session})
        
        # Clear session
        session.clear()
        
        if result.get('success') and result.get('action') == 'saml_logout':
            return redirect(result.get('redirect_url'))
        
        session['info'] = 'Logged out successfully'
        return redirect(url_for('index'))
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        session.clear()
        session['info'] = 'Logged out'
        return redirect(url_for('index'))

@app.route('/api/validate', methods=['POST'])
def api_validate():
    """API endpoint for LDAP credential validation"""
    try:
        data = request.get_json()
        username = data.get('username')
        password = data.get('password')
        
        if not username or not password:
            return jsonify({'error': 'Username and password required'}), 400
        
        result = orchestrator.validate_ldap_credentials(username, password)
        
        if result.get('success'):
            return jsonify(result)
        else:
            return jsonify(result), 400
            
    except Exception as e:
        logger.error(f"API validation error: {str(e)}")
        return jsonify({'error': 'Validation failed'}), 500

@app.route('/demo-login', methods=['GET', 'POST'])
def demo_login():
    """Demo login bypass - TESTING ONLY"""
    if request.method == 'GET':
        return '''
        <!DOCTYPE html>
        <html>
        <head>
            <title>Demo Login</title>
            <style>
                body { font-family: Arial; max-width: 500px; margin: 100px auto; padding: 20px; }
                .card { border: 1px solid #ddd; padding: 30px; border-radius: 8px; }
                input { width: 100%; padding: 10px; margin: 10px 0; border: 1px solid #ccc; border-radius: 4px; }
                button { background: #007bff; color: white; padding: 12px 30px; border: none; border-radius: 4px; cursor: pointer; width: 100%; }
                button:hover { background: #0056b3; }
                .warning { background: #fff3cd; padding: 10px; border-radius: 4px; margin-bottom: 20px; color: #856404; }
            </style>
        </head>
        <body>
            <div class="card">
                <h2>🧪 Demo Login (Testing Only)</h2>
                <div class="warning">
                    ⚠️ This bypasses SAML authentication for testing purposes only.
                </div>
                <form method="post">
                    <label>Username:</label>
                    <input name="username" placeholder="Enter any username" value="testuser" required>
                    <button type="submit">Generate Credentials</button>
                </form>
            </div>
        </body>
        </html>
        '''
    
    # POST request - create session
    username = request.form.get('username', 'testuser')
    
    # Create fake user info
    user_info = {
        'username': username,
        'email': f'{username}@demo.local',
        'display_name': username.title(),
        'first_name': username.title(),
        'last_name': 'Demo'
    }
    
    session['authenticated'] = True
    session['user_info'] = user_info
    session['timestamp'] = time.time()
    
    return redirect(url_for('credentials'))

if __name__ == '__main__':
    # Run the application
    if Config.SSL_CERT_PATH and Config.SSL_KEY_PATH:
        try:
            app.run(host='0.0.0.0', port=5000, 
                   ssl_context=(Config.SSL_CERT_PATH, Config.SSL_KEY_PATH),
                   debug=Config.DEBUG)
        except FileNotFoundError:
            logger.warning("SSL certificates not found, running without HTTPS")
            app.run(host='0.0.0.0', port=5000, debug=Config.DEBUG)
    else:
        app.run(host='0.0.0.0', port=5000, debug=Config.DEBUG)