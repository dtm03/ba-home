from saml_token_validator import TokenValidator
from config import Config
from ldap_credential_generator import CredentialGenerator

class WorkflowOrchestrator:
    def __init__(self, ldap_credential_generator, auth_handler):
        self.ldap_credential_generator = ldap_credential_generator
        self.auth_handler = auth_handler
        self.saml_token_validator = TokenValidator()

    def initiate_login(self):
        """Return redirect URL for IdP login."""
        return {'success': True, 'redirect_url': '/login'}

    def process_saml_response(self, request):
        """
        Validate incoming SAML response using the Flask `request` and extract user info.
        Returns dict with user_info and SAML session data.
        """
        result = self.saml_token_validator.validate_saml_response(request)
        if not result.get('success'):
            return {'success': False, 'error': result.get('error', 'SAML validation failed')}
        user_info = result.get('user_info')
        # TokenValidator returns user_info which includes 'nameid' when present
        saml_data = {
            'nameid': user_info.get('nameid') if isinstance(user_info, dict) else None,
            'session_index': None
        }
        return {'success': True, 'user_info': user_info, 'saml_data': saml_data}

# Factory to create orchestrator
def get_orchestrator():
    # AuthHandler implementation is not present in this repo; pass None for now.
    ldap_gen = CredentialGenerator()
    auth_handler = None
    return WorkflowOrchestrator(ldap_gen, auth_handler)



orchestrator = get_orchestrator()
