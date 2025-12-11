from token_validator import TokenValidator
from config import Config

class WorkflowOrchestrator:
    def __init__(self, credential_generator, auth_handler):
        self.credential_generator = credential_generator
        self.auth_handler = auth_handler
        self.token_validator = TokenValidator()

    def check_session(self, session):
        return self.auth_handler.check_session(session)

    def generate_credentials(self, user_info):
        return self.credential_generator.generate_temporary_credentials(user_info)

    def validate_credentials(self, username, password):
        return self.credential_generator.validate_credentials(username, password)

    def initiate_auth(self, request_data):
        return {'success': True, 'redirect_url': '/auth0-login'}

    def process_authentication_request(self, request):
        """Process authentication request (login or SAML ACS)"""
        try:
            # Check if this is a SAML response
            if 'SAMLResponse' in request.form:
                result = self.token_validator.validate_saml_response(request)
                if not result.get('success'):
                    return {'success': False, 'error': result.get('error', 'SAML validation failed')}
                user_info = result.get('user_info')
                saml_data = {'nameid': result.get('nameid'), 'session_index': result.get('session_index')}
                return {
                    'success': True,
                    'action': 'saml_authenticated',
                    'user_info': user_info,
                    'saml_data': saml_data
                }
            # Check for MFA verification
            elif 'mfa_code' in request.form:
                username = request.form.get('username')
                mfa_code = request.form.get('mfa_code')
                # Validate MFA (placeholder)
                if mfa_code and len(mfa_code) >= 6:
                    user_info = {'username': username}
                    saml_data = {'nameid': username, 'session_index': None}
                    return {
                        'success': True,
                        'action': 'mfa_authenticated',
                        'user_info': user_info,
                        'saml_data': saml_data
                    }
                return {'success': False, 'error': 'Invalid MFA code'}
            # Regular login - initiate SAML
            else:
                return {
                    'success': True,
                    'action': 'redirect_to_idp',
                    'redirect_url': '/saml/login'
                }
        except Exception as e:
            return {'success': False, 'error': f'Authentication request failed: {str(e)}'}

    def process_credential_request(self, user_info, session_data):
        """Generate temporary credentials for authenticated user"""
        try:
            credentials = self.credential_generator.generate_temporary_credentials(user_info)
            return {'success': True, 'credentials': credentials}
        except Exception as e:
            return {'success': False, 'error': f'Credential generation failed: {str(e)}'}

    def process_logout_request(self, request_data):
        """Process logout request"""
        try:
            return {'success': True}
        except Exception as e:
            return {'success': False, 'error': f'Logout failed: {str(e)}'}

    def get_system_status(self):
        """Get system status information"""
        try:
            return {
                'success': True,
                'status': 'healthy',
                'components': {
                    'auth': 'operational',
                    'credentials': 'operational'
                }
            }
        except Exception as e:
            return {'success': False, 'error': f'Status check failed: {str(e)}'}


def get_orchestrator():
    """Factory function to create and return the WorkflowOrchestrator instance"""
    # Import here to avoid circular dependencies
    from credential_generator import CredentialGenerator
    from auth_handler import AuthHandler
    
    credential_generator = CredentialGenerator()
    auth_handler = AuthHandler()
    return WorkflowOrchestrator(credential_generator, auth_handler)


orchestrator = get_orchestrator()
