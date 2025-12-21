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
        logger.debug(f"Preparing Flask request for OneLogin: {request.path}")
        return {
            'https': 'on' if request.scheme == 'https' else 'off',
            'http_host': request.host,
            'script_name': request.path,
            'get_data': request.args,
            'post_data': request.form
        }

        
    def _extract_user_info(self, nameid, attributes):
        user_info = {
            'nameid': nameid,
            'email': None
        }

        for email_attr in ['mail', 'email', 'emailAddress']:
            if email_attr in attributes and attributes[email_attr]:
                user_info['email'] = attributes[email_attr][0] if isinstance(attributes[email_attr], list) else attributes[email_attr]
                break

        return user_info
