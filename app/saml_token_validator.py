import logging
from onelogin.saml2.auth import OneLogin_Saml2_Auth as Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings as Settings
from config import Config

logger = logging.getLogger(__name__)

class TokenValidator:
    def __init__(self):
        self.saml_settings = Config.get_saml_settings()
        
    def validate_saml_response(self, request):
        try:
            auth = Auth(self._prepare_flask_request(request), self.saml_settings)
            auth.process_response()
            
            errors = auth.get_errors()
            if errors:
                raise ValueError(f"SAML Error: {', '.join(errors)} ({auth.get_last_error_reason()})")

            user_info = self._extract_user_info(auth.get_nameid(), auth.get_attributes())
            logger.info(f"User {user_info['username']} validated successfully")
            return {'success': True, 'user_info': user_info}

        except Exception as e:
            logger.error(f"Validation failed: {str(e)}")
            return {'success': False, 'error': str(e)}

    def _prepare_flask_request(self, request):
        return {
            'https': 'on' if request.scheme == 'https' else 'off',
            'http_host': request.host,
            'script_name': '',
            'get_data': request.args.copy(),
            'post_data': request.form.copy()
        }

    def _extract_user_info(self, nameid, attributes):
        email = attributes.get('http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress', 
                            attributes.get('email', [None]))[0]

        email = email or nameid

        user_info = {
            'nameid': nameid,
            'email': email,
            'username': email.split('@')[0] if email and '@' in email else email,
            'display_name': attributes.get('name', [email])[0]
        }

        logger.debug(f"User extracted: {user_info['username']}")
        return user_info
