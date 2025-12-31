import logging
from onelogin.saml2.auth import OneLogin_Saml2_Auth as Auth
from saml_token_validator import TokenValidator
from ldap_credential_generator import CredentialGenerator
from ldap3 import Server, Connection, ALL
from config import Config

logger = logging.getLogger(__name__)

class WorkflowOrchestrator:
    def __init__(self):
        self.ldap_gen = CredentialGenerator()
        self.validator = TokenValidator()

    def get_login_url(self, request):
        req = self.validator._prepare_flask_request(request)
        auth = Auth(req, self.validator.saml_settings)
        return auth.login(force_authn=True)

    def process_saml_response(self, request):
        result = self.validator.validate_saml_response(request)
        if result['success']:
            result['saml_data'] = {
                'nameid': result['user_info'].get('nameid'),
                'session_index': None 
            }
        return result

    def get_ldap_credentials(self, user_info):
        return self.ldap_gen.issue_temporary_credentials(user_info)

    def test_ldap_login(self, username, password):
        try:
            server = Server(Config.LDAP_HOST, port=Config.LDAP_PORT, get_info=ALL)
            bind_dn = f"uid={username},{Config.LDAP_BASE_DN}"
            
            conn = Connection(server, user=bind_dn, password=password, auto_bind=True)
            conn.unbind()
            return {'success': True, 'message': f'Successfully signed in as {username}!'}
        except Exception as e:
            logger.error(f"LDAP-Test failed: {e}")
            return {'success': False, 'error': str(e)}

    def change_ldap_password(self, mail, new_password):
        try:
            server = Server(Config.LDAP_HOST, port=Config.LDAP_PORT, get_info=ALL)
            conn = Connection(server, user=Config.LDAP_BIND_DN, 
                              password=Config.LDAP_BIND_PASSWORD, auto_bind=True)
            
            conn.search(Config.LDAP_BASE_DN, f"(mail={mail})", attributes=['dn'])
            if not conn.entries:
                return {'success': False, 'error': 'User not found'}
            
            user_dn = conn.entries[0].entry_dn
            result = conn.extend.standard.modify_password(user_dn, new_password)
            conn.unbind()
            return {'success': result}
        except Exception as e:
            return {'success': False, 'error': str(e)}

orchestrator = WorkflowOrchestrator()