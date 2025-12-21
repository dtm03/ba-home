import logging
from onelogin.saml2.auth import OneLogin_Saml2_Auth as Auth
from onelogin.saml2.settings import OneLogin_Saml2_Settings as Settings
from config import Config

logger = logging.getLogger(__name__)

class TokenValidator:
    def __init__(self):
        self.saml_settings = Config.get_saml_settings()
        
    def validate_saml_response(self, request_data):
        try:
            auth = Auth(self._prepare_flask_request(request_data), self.saml_settings)
            auth.process_response()
            errors = auth.get_errors()
            if errors:
                return {'success': False, 'error': 'SAML validation failed', 'details': ', '.join(errors)}
            attributes = auth.get_attributes()
            nameid = auth.get_nameid()
            session_index = auth.get_session_index()
            user_info = self._extract_user_info(nameid, attributes)
            return {
                'success': True,
                'user_info': user_info,
                'session_index': session_index,
                'nameid': nameid,
                'attributes': attributes
            }
        except Exception as e:
            logger.error(f"SAML validation exception: {str(e)}")
            return {'success': False, 'error': 'Token validation exception', 'details': str(e)}
    
    def _prepare_flask_request(self, request_data):
        if hasattr(request_data, 'form') and hasattr(request_data, 'args'):
            return {
                'https': 'on' if request_data.scheme == 'https' else 'off',
                'http_host': request_data.headers.get('Host', ''),
                'server_port': request_data.environ.get('SERVER_PORT', ''),
                'script_name': request_data.path,
                'get_data': request_data.args.copy(),
                'post_data': request_data.form.copy()
            }
        return request_data
    
    def _extract_user_info(self, nameid, attributes):
        user_info = {'username': nameid, 'nameid': nameid}
        mapping = {
            'uid': ['uid', 'username', 'user'],
            'email': ['mail', 'email', 'emailAddress'],
            'first_name': ['givenName', 'firstName', 'fname'],
            'last_name': ['sn', 'surname', 'lastName', 'lname'],
            'display_name': ['displayName', 'cn', 'commonName'],
            'groups': ['groups', 'memberOf', 'isMemberOf'],
            'affiliation': ['eduPersonAffiliation', 'affiliation'],
            'scoped_affiliation': ['eduPersonScopedAffiliation'],
            'primary_affiliation': ['eduPersonPrimaryAffiliation']
        }
        for key, attrs in mapping.items():
            for attr in attrs:
                if attr in attributes and attributes[attr]:
                    user_info[key] = attributes[attr][0] if isinstance(attributes[attr], list) else attributes[attr]
                    break
        if 'uid' not in user_info and 'email' in user_info:
            user_info['username'] = user_info['email'].split('@')[0]
        elif 'uid' in user_info:
            user_info['username'] = user_info['uid']
        return user_info
    
    def validate_token_signature(self, token):
        try:
            settings = Settings(self.saml_settings)
            return settings.check_idp_x509cert()
        except Exception as e:
            logger.error(f"Token signature validation failed: {str(e)}")
            return False
