import logging
from flask import Blueprint, request, session, render_template, redirect, url_for
from demo_ldap import get_demo_client
from main import get_orchestrator
from config import Config

logger = logging.getLogger(__name__)

demo_bp = Blueprint('demo', __name__, template_folder='templates')

demo_client = get_demo_client()
orchestrator = get_orchestrator()

@demo_bp.route('/demo')
def demo_interface():
    try:
        status = orchestrator.get_system_status()
        message = session.pop('demo_message', None)
        message_type = session.pop('demo_message_type', 'info')
        last_username = session.get('last_demo_username', '')
        return render_template('demo_index.html',
                               system_status=status,
                               message=message,
                               message_type=message_type,
                               last_username=last_username)
    except Exception as e:
        logger.error(f"Demo interface error: {e}")
        return f"Demo interface error: {e}", 500

@demo_bp.route('/demo/test', methods=['POST'])
def demo_test():
    try:
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        if not username or not password:
            session['demo_message'] = 'Username and password are required'
            session['demo_message_type'] = 'error'
            return redirect(url_for('demo_interface'))
        session['last_demo_username'] = username
        result = demo_client.test_connection(username, password)
        return render_template('demo_test_results.html',
                               username=username,
                               test_result=result)
    except Exception as e:
        logger.error(f"Demo test error: {e}")
        session['demo_message'] = f'Test failed: {e}'
        session['demo_message_type'] = 'error'
        return redirect(url_for('demo_interface'))

def register_demo_routes(app):
    """Register demo routes with the main Flask application"""
    app.register_blueprint(demo_bp)
