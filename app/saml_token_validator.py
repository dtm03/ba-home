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
                logger.debug(f"SAML validation errors: {errors}")
                return {'success': False, 'error': ', '.join(errors)}

            nameid = auth.get_nameid()
            attributes = auth.get_attributes()
            logger.debug(f"SAML nameid: {nameid}, attributes: {attributes}")
            user_info = self._extract_user_info(nameid, attributes)
            return {'success': True, 'user_info': user_info}

        except Exception as e:
            logger.error(f"SAML validation exception: {str(e)}")
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
        user_info = {
            'nameid': nameid,
            'email': None,
            'username': None,
            'display_name': None
        }

        # Auth0 sends email as http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress
        # Also support standard SAML attribute names
        email_attr_names = [
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/email',
            'mail',
            'email',
            'emailAddress'
        ]
        
        for email_attr in email_attr_names:
            if email_attr in attributes and attributes[email_attr]:
                user_info['email'] = attributes[email_attr][0] if isinstance(attributes[email_attr], list) else attributes[email_attr]
                break

        # Extract username from email (before @) if email exists
        if user_info['email']:
            user_info['username'] = user_info['email'].split('@')[0]
        
        # Try to get display name from various attributes
        display_name_attrs = [
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name',
            'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn',
            'displayName',
            'cn'
        ]
        
        for display_attr in display_name_attrs:
            if display_attr in attributes and attributes[display_attr]:
                user_info['display_name'] = attributes[display_attr][0] if isinstance(attributes[display_attr], list) else attributes[display_attr]
                break

        logger.debug(f"Extracted user_info: email={user_info['email']}, username={user_info['username']}, display_name={user_info['display_name']}")
        return user_info
