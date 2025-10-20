"""
Demo Web Interface
Web interface for testing LDAP connections and demonstrating functionality
"""
import logging
import json
from flask import Flask, request, session, render_template_string, jsonify, redirect, url_for
from demo_ldap import get_demo_client, get_demo_server
from main import get_orchestrator
from config import Config

logger = logging.getLogger(__name__)

# Create Flask app for demo interface
demo_app = Flask(__name__, template_folder='templates')
demo_app.secret_key = Config.SECRET_KEY + '_demo'

# Get instances
demo_client = get_demo_client()
demo_server = get_demo_server()
orchestrator = get_orchestrator()

# HTML Templates
DEMO_INDEX_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SAML-LDAP Bridge - Demo Interface</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1200px; margin: 20px auto; padding: 20px; background: #f5f5f5; }
        .header { background: #007bff; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .card { background: white; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; margin: 5px; }
        .btn:hover { background: #0056b3; }
        .btn-success { background: #28a745; }
        .btn-success:hover { background: #218838; }
        .btn-warning { background: #ffc107; color: #212529; }
        .btn-warning:hover { background: #e0a800; }
        .btn-danger { background: #dc3545; }
        .btn-danger:hover { background: #c82333; }
        .error { color: #dc3545; background: #f8d7da; padding: 10px; border-radius: 4px; margin: 10px 0; }
        .success { color: #155724; background: #d4edda; padding: 10px; border-radius: 4px; margin: 10px 0; }
        .warning { color: #856404; background: #fff3cd; padding: 10px; border-radius: 4px; margin: 10px 0; }
        .form-group { margin: 15px 0; }
        .form-control { width: 100%; padding: 8px; border: 1px solid #ccc; border-radius: 4px; box-sizing: border-box; }
        .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
        .code { background: #f8f9fa; border: 1px solid #dee2e6; padding: 10px; border-radius: 4px; font-family: monospace; overflow-x: auto; }
        .status-indicator { width: 10px; height: 10px; border-radius: 50%; display: inline-block; margin-right: 5px; }
        .status-active { background: #28a745; }
        .status-inactive { background: #dc3545; }
        .status-unknown { background: #6c757d; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        table th, table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        table th { background-color: #f8f9fa; }
        .test-result { margin: 10px 0; padding: 10px; border-left: 4px solid #007bff; background: #f8f9fa; }
        .test-pass { border-left-color: #28a745; }
        .test-fail { border-left-color: #dc3545; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔗 SAML-LDAP Bridge Demo Interface</h1>
        <p>Test LDAP connectivity using temporary credentials from SAML authentication</p>
    </div>
    
    {% if message %}
    <div class="{{ message_type }}">{{ message }}</div>
    {% endif %}
    
    <div class="grid">
        <!-- Connection Test Card -->
        <div class="card">
            <h2>🧪 Test LDAP Connection</h2>
            <form method="post" action="{{ url_for('demo_test') }}">
                <div class="form-group">
                    <label for="username">Username:</label>
                    <input type="text" id="username" name="username" class="form-control" value="{{ last_username }}" required>
                </div>
                <div class="form-group">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" class="form-control" required>
                </div>
                <button type="submit" class="btn btn-success">Test Connection</button>
            </form>
            
            <h3>Quick Actions</h3>
            <a href="{{ url_for('demo_search') }}" class="btn">Search LDAP</a>
            <a href="{{ url_for('demo_examples') }}" class="btn">Connection Examples</a>
            <a href="{{ url_for('demo_api_test') }}" class="btn">API Test</a>
        </div>
        
        <!-- System Status Card -->
        <div class="card">
            <h2>📊 System Status</h2>
            <table>
                <tr>
                    <td><strong>Bridge Status:</strong></td>
                    <td>
                        <span class="status-indicator status-active"></span>
                        {{ system_status.status | title }}
                    </td>
                </tr>
                <tr>
                    <td><strong>Active Credentials:</strong></td>
                    <td>{{ system_status.active_credentials }}</td>
                </tr>
                <tr>
                    <td><strong>LDAP Server:</strong></td>
                    <td>{{ system_status.configuration.ldap_host }}:{{ system_status.configuration.ldap_port }}</td>
                </tr>
                <tr>
                    <td><strong>eduMFA:</strong></td>
                    <td>
                        <span class="status-indicator {{ 'status-active' if system_status.configuration.edumfa_configured else 'status-inactive' }}"></span>
                        {{ 'Enabled' if system_status.configuration.edumfa_configured else 'Disabled' }}
                    </td>
                </tr>
            </table>
            
            <h3>Actions</h3>
            <a href="{{ url_for('demo_status') }}" class="btn">Detailed Status</a>
            <a href="{{ url_for('demo_credentials') }}" class="btn">Active Credentials</a>
        </div>
        
        <!-- Getting Started Card -->
        <div class="card">
            <h2>🚀 Getting Started</h2>
            <ol>
                <li><strong>Authenticate:</strong> Go to the <a href="{{ url_for('main_interface') }}">main interface</a> and log in with SAML</li>
                <li><strong>Get Credentials:</strong> After authentication, temporary LDAP credentials will be generated</li>
                <li><strong>Test Connection:</strong> Use the form above to test LDAP connectivity</li>
                <li><strong>Integrate:</strong> Use the connection examples for your applications</li>
            </ol>
            
            <div class="warning">
                <strong>Note:</strong> This is a demonstration environment. In production, ensure proper security measures are in place.
            </div>
        </div>
        
        <!-- Available Tools Card -->
        <div class="card">
            <h2>🛠️ Available Tools</h2>
            
            <h3>Web Interface</h3>
            <a href="{{ url_for('main_interface') }}" class="btn">Main Authentication Interface</a>
            <a href="{{ url_for('demo_interface') }}" class="btn btn-warning">Demo Interface (Current)</a>
            
            <h3>Command Line</h3>
            <div class="code">
                # Interactive demo
                python demo_main.py interactive
                
                # Automated test
                python demo_main.py auto
                
                # System status
                python demo_main.py status
            </div>
            
            <h3>API Endpoints</h3>
            <div class="code">
                POST /api/validate
                GET /status
                GET /demo/api/test
            </div>
        </div>
    </div>
    
    <script>
        // Auto-refresh status every 30 seconds
        setTimeout(function() {
            location.reload();
        }, 30000);
    </script>
</body>
</html>
"""

DEMO_TEST_RESULTS_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>LDAP Connection Test Results</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 1200px; margin: 20px auto; padding: 20px; background: #f5f5f5; }
        .header { background: #007bff; color: white; padding: 20px; border-radius: 8px; margin-bottom: 20px; }
        .card { background: white; border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin: 20px 0; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .btn { background: #007bff; color: white; padding: 10px 20px; border: none; border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; margin: 5px; }
        .btn:hover { background: #0056b3; }
        .success { color: #155724; background: #d4edda; padding: 15px; border-radius: 4px; margin: 10px 0; }
        .error { color: #dc3545; background: #f8d7da; padding: 15px; border-radius: 4px; margin: 10px 0; }
        .warning { color: #856404; background: #fff3cd; padding: 15px; border-radius: 4px; margin: 10px 0; }
        .code { background: #f8f9fa; border: 1px solid #dee2e6; padding: 10px; border-radius: 4px; font-family: monospace; overflow-x: auto; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        table th, table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        table th { background-color: #f8f9fa; }
        .test-section { margin: 20px 0; padding: 15px; border-left: 4px solid #007bff; background: #f8f9fa; }
        .test-pass { border-left-color: #28a745; }
        .test-fail { border-left-color: #dc3545; }
        .json-display { max-height: 300px; overflow-y: auto; }
    </style>
</head>
<body>
    <div class="header">
        <h1>LDAP Connection Test Results</h1>
        <p>User: <strong>{{ username }}</strong></p>
    </div>
    
    {% if test_result.success %}
    <div class="success">
        <h2>✅ Connection Test Successful</h2>
        <p>{{ test_result.message or 'LDAP connection test passed successfully.' }}</p>
    </div>
    
    <div class="card">
        <h2>User Information</h2>
        <table>
            {% for key, value in test_result.user_info.items() %}
            <tr>
                <td><strong>{{ key | title | replace('_', ' ') }}:</strong></td>
                <td>{{ value }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
    
    {% if test_result.ldap_connection %}
    <div class="test-section {{ 'test-pass' if test_result.ldap_connection.success else 'test-fail' }}">
        <h3>🔗 LDAP Server Connection</h3>
        {% if test_result.ldap_connection.success %}
            <p><strong>Status:</strong> ✅ Connected successfully</p>
            <table>
                <tr><td><strong>Bind Successful:</strong></td><td>{{ test_result.ldap_connection.bind_successful }}</td></tr>
                <tr><td><strong>Search Successful:</strong></td><td>{{ test_result.ldap_connection.search_successful }}</td></tr>
                {% if test_result.ldap_connection.entry_dn %}
                <tr><td><strong>Entry DN:</strong></td><td>{{ test_result.ldap_connection.entry_dn }}</td></tr>
                {% endif %}
                {% if test_result.ldap_connection.attributes_found %}
                <tr><td><strong>Attributes Found:</strong></td><td>{{ test_result.ldap_connection.attributes_found }}</td></tr>
                {% endif %}
            </table>
        {% else %}
            <p><strong>Status:</strong> ❌ Connection failed</p>
            <p><strong>Error:</strong> {{ test_result.ldap_connection.error }}</p>
            {% if test_result.ldap_connection.note %}
            <div class="warning">
                <strong>Note:</strong> {{ test_result.ldap_connection.note }}
            </div>
            {% endif %}
        {% endif %}
    </div>
    {% endif %}
    
    <div class="card">
        <h2>LDAP Attributes</h2>
        {% if test_result.attributes %}
        <table>
            {% for key, value in test_result.attributes.items() %}
            <tr>
                <td><strong>{{ key }}:</strong></td>
                <td>
                    {% if value is sequence and value is not string %}
                        {{ value | join(', ') }}
                    {% else %}
                        {{ value }}
                    {% endif %}
                </td>
            </tr>
            {% endfor %}
        </table>
        {% else %}
        <p>No attributes available.</p>
        {% endif %}
    </div>
    
    {% else %}
    <div class="error">
        <h2>❌ Connection Test Failed</h2>
        <p><strong>Error:</strong> {{ test_result.error }}</p>
        {% if test_result.details %}
        <p><strong>Details:</strong> {{ test_result.details }}</p>
        {% endif %}
    </div>
    
    <div class="card">
        <h2>Troubleshooting</h2>
        <ol>
            <li>Ensure you have authenticated via the main interface first</li>
            <li>Check that your temporary credentials haven't expired</li>
            <li>Verify the LDAP server configuration</li>
            <li>Check the system logs for more details</li>
        </ol>
    </div>
    {% endif %}
    
    <div class="card">
        <h2>Actions</h2>
        <a href="{{ url_for('demo_interface') }}" class="btn">Back to Demo</a>
        <a href="{{ url_for('demo_search') }}?username={{ username }}" class="btn">Search LDAP</a>
        <a href="{{ url_for('demo_examples') }}?username={{ username }}" class="btn">Connection Examples</a>
        <a href="{{ url_for('main_interface') }}" class="btn">Main Interface</a>
    </div>
    
    <div class="card">
        <h2>Raw Test Data</h2>
        <div class="code json-display">
            {{ test_result | tojson(indent=2) }}
        </div>
    </div>
</body>
</html>
"""

@demo_app.route('/demo')
def demo_interface():
    """Main demo interface"""
    try:
        # Get system status
        status = orchestrator.get_system_status()
        
        message = session.pop('demo_message', None)
        message_type = session.pop('demo_message_type', 'info')
        last_username = session.get('last_demo_username', '')
        
        return render_template_string(DEMO_INDEX_TEMPLATE,
                                    system_status=status,
                                    message=message,
                                    message_type=message_type,
                                    last_username=last_username)
        
    except Exception as e:
        logger.error(f"Demo interface error: {str(e)}")
        return f"Demo interface error: {str(e)}", 500

@demo_app.route('/demo/test', methods=['POST'])
def demo_test():
    """Test LDAP connection"""
    try:
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        
        if not username or not password:
            session['demo_message'] = 'Username and password are required'
            session['demo_message_type'] = 'error'
            return redirect(url_for('demo_interface'))
        
        session['last_demo_username'] = username
        
        # Test connection
        result = demo_client.test_connection(username, password)
        
        return render_template_string(DEMO_TEST_RESULTS_TEMPLATE,
                                    username=username,
                                    test_result=result)
        
    except Exception as e:
        logger.error(f"Demo test error: {str(e)}")
        session['demo_message'] = f'Test failed: {str(e)}'
        session['demo_message_type'] = 'error'
        return redirect(url_for('demo_interface'))

@demo_app.route('/demo/search')
def demo_search():
    """LDAP search interface"""
    username = request.args.get('username', '')
    
    if not username:
        return redirect(url_for('demo_interface'))
    
    # For demo purposes, return a simple search interface
    search_template = """
    <h1>LDAP Search - Demo</h1>
    <p>This would perform LDAP searches using the authenticated credentials.</p>
    <p>Username: {{ username }}</p>
    <a href="{{ url_for('demo_interface') }}">Back to Demo</a>
    """
    
    return render_template_string(search_template, username=username)

@demo_app.route('/demo/examples')
def demo_examples():
    """Connection examples interface"""
    username = request.args.get('username', '')
    
    if not username:
        return redirect(url_for('demo_interface'))
    
    try:
        result = demo_client.get_connection_examples(username)
        
        examples_template = """
        <h1>Connection Examples</h1>
        {% if result.success %}
        <h2>Examples for user: {{ username }}</h2>
        {% for name, example in result.examples.items() %}
        <h3>{{ name | title }}</h3>
        <pre style="background: #f5f5f5; padding: 10px; border-radius: 4px;">{{ example }}</pre>
        {% endfor %}
        {% else %}
        <p>Error: {{ result.error }}</p>
        {% endif %}
        <a href="{{ url_for('demo_interface') }}">Back to Demo</a>
        """
        
        return render_template_string(examples_template, 
                                    username=username, 
                                    result=result)
        
    except Exception as e:
        return f"Error generating examples: {str(e)}"

@demo_app.route('/demo/api/test')
def demo_api_test():
    """API test interface"""
    api_template = """
    <h1>API Test Interface</h1>
    <h2>Credential Validation API</h2>
    <p>Test the REST API for credential validation:</p>
    <pre style="background: #f5f5f5; padding: 10px; border-radius: 4px;">
    POST /api/validate
    Content-Type: application/json
    
    {
        "username": "your_username",
        "password": "your_password"
    }
    </pre>
    
    <h2>System Status API</h2>
    <p><a href="{{ url_for('demo_status') }}">GET /demo/status</a></p>
    
    <a href="{{ url_for('demo_interface') }}">Back to Demo</a>
    """
    
    return render_template_string(api_template)

@demo_app.route('/demo/status')
def demo_status():
    """Detailed system status"""
    try:
        status = orchestrator.get_system_status()
        return jsonify(status)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@demo_app.route('/demo/credentials')
def demo_credentials():
    """List active credentials (for demo purposes)"""
    try:
        result = orchestrator.credential_generator.list_active_credentials()
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Make demo routes available to main app
def register_demo_routes(main_app):
    """Register demo routes with the main Flask app"""
    
    # Get the view functions from demo_app
    demo_views = {
        'demo_interface': demo_app.view_functions['demo_interface'],
        'demo_test': demo_app.view_functions['demo_test'],
        'demo_search': demo_app.view_functions['demo_search'],
        'demo_examples': demo_app.view_functions['demo_examples'],
        'demo_api_test': demo_app.view_functions['demo_api_test'],
        'demo_status': demo_app.view_functions['demo_status'],
        'demo_credentials': demo_app.view_functions['demo_credentials']
    }
    
    # Register routes with unique endpoint names to avoid conflicts
    main_app.add_url_rule('/demo', 'demo_interface_route', demo_views['demo_interface'], methods=['GET'])
    main_app.add_url_rule('/demo/test', 'demo_test_route', demo_views['demo_test'], methods=['POST'])
    main_app.add_url_rule('/demo/search', 'demo_search_route', demo_views['demo_search'], methods=['GET'])
    main_app.add_url_rule('/demo/examples', 'demo_examples_route', demo_views['demo_examples'], methods=['GET'])
    main_app.add_url_rule('/demo/api/test', 'demo_api_test_route', demo_views['demo_api_test'], methods=['GET'])
    main_app.add_url_rule('/demo/status', 'demo_status_route', demo_views['demo_status'], methods=['GET'])
    main_app.add_url_rule('/demo/credentials', 'demo_credentials_route', demo_views['demo_credentials'], methods=['GET'])

    """Register demo routes with the main Flask app"""
    
    @main_app.route('/demo')
    def demo_interface():
        return demo_app.view_functions['demo_interface']()
    
    @main_app.route('/demo/test', methods=['POST'])
    def demo_test():
        return demo_app.view_functions['demo_test']()
    
    @main_app.route('/demo/search')
    def demo_search():
        return demo_app.view_functions['demo_search']()
    
    @main_app.route('/demo/examples')
    def demo_examples():
        return demo_app.view_functions['demo_examples']()
    
    @main_app.route('/demo/api/test')
    def demo_api_test():
        return demo_app.view_functions['demo_api_test']()
    
    @main_app.route('/demo/status')
    def demo_status():
        return demo_app.view_functions['demo_status']()
    
    @main_app.route('/demo/credentials')
    def demo_credentials():
        return demo_app.view_functions['demo_credentials']()

if __name__ == '__main__':
    # Run demo app standalone
    demo_app.run(host='0.0.0.0', port=5001, debug=Config.DEBUG)