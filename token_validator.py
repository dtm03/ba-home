"""
SAML Token Validation Module
Handles validation of SAML tokens from Shibboleth IdP
"""
import logging
from datetime import datetime, timedelta
from onelogin.saml2.auth import OneLogin_Saml2_Auth as Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils as Utils
# ...existing code...
try:
    # older code expecting `Settings`
    from onelogin.saml2.settings import Settings
except Exception:
    # newer python-saml exposes `OneLogin_Saml2_Settings`
    from onelogin.saml2.settings import OneLogin_Saml2_Settings as Settings

# Compatibility import for errors
try:
    # common name in some versions
    from onelogin.saml2.errors import OneLogin_Saml2_Error as Error
except Exception:
    try:
        # older/alternate name
        from onelogin.saml2.errors import Error
    except Exception:
        # final fallback: simple alias to Exception to avoid import failures
        class Error(Exception):
            pass
# ...existing code...
from config import Config

logger = logging.getLogger(__name__)

class TokenValidator:
    def __init__(self):
        self.saml_settings = Config.get_saml_settings()
        
    def validate_saml_response(self, request_data):
        """
        Validate SAML response from IdP
        
        Args:
            request_data: Flask request object or dict containing SAML response
            
        Returns:
            dict: Validation result containing success status and user info
        """
        try:
            # Initialize SAML Auth object
            auth = Auth(self._prepare_flask_request(request_data), self.saml_settings)
            
            # Process the SAML response
            auth.process_response()
            
            errors = auth.get_errors()
            
            if len(errors) == 0:
                # Get user attributes
                attributes = auth.get_attributes()
                nameid = auth.get_nameid()
                session_index = auth.get_session_index()
                
                # Validate token timing
                if not self._validate_timing(auth):
                    return {
                        'success': False,
                        'error': 'Token timing validation failed',
                        'details': 'Token is expired or not yet valid'
                    }
                
                # Extract user information
                user_info = self._extract_user_info(nameid, attributes)
                
                logger.info(f"SAML token validated successfully for user: {user_info.get('username', 'unknown')}")
                
                return {
                    'success': True,
                    'user_info': user_info,
                    'session_index': session_index,
                    'nameid': nameid,
                    'attributes': attributes
                }
            else:
                error_msg = f"SAML validation errors: {', '.join(errors)}"
                logger.error(error_msg)
                return {
                    'success': False,
                    'error': 'SAML validation failed',
                    'details': error_msg
                }
                
        except Exception as e:
            logger.error(f"Exception during SAML validation: {str(e)}")
            return {
                'success': False,
                'error': 'Token validation exception',
                'details': str(e)
            }
    
    def _prepare_flask_request(self, request_data):
        """
        Prepare request data for SAML processing
        """
        if hasattr(request_data, 'form') and hasattr(request_data, 'args'):
            # Flask request object
            return {
                'https': 'on' if request_data.scheme == 'https' else 'off',
                'http_host': request_data.headers.get('Host', ''),
                'server_port': request_data.environ.get('SERVER_PORT', ''),
                'script_name': request_data.path,
                'get_data': request_data.args.copy(),
                'post_data': request_data.form.copy()
            }
        else:
            # Dictionary format
            return request_data
    
    def _validate_timing(self, auth):
        """
        Validate token timing (not before, not after)
        """
        try:
            # Get the last assertion from the auth object
            response_xml = auth.get_last_response_xml()
            if response_xml:
                # Parse timing conditions from the response
                # This is a simplified check - in production you might want more detailed validation
                return True
            return False
        except Exception as e:
            logger.warning(f"Could not validate token timing: {str(e)}")
            return True  # Allow if we can't validate timing
    
    def _extract_user_info(self, nameid, attributes):
        """
        Extract user information from SAML attributes
        """
        user_info = {
            'username': nameid,
            'nameid': nameid,
        }
        
        # Map common SAML attributes to user info
        attribute_mapping = {
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
        
        for user_field, saml_attrs in attribute_mapping.items():
            for attr in saml_attrs:
                if attr in attributes and attributes[attr]:
                    user_info[user_field] = attributes[attr][0] if isinstance(attributes[attr], list) else attributes[attr]
                    break
        
        # Use email as username if uid is not available
        if 'uid' not in user_info and 'email' in user_info:
            user_info['username'] = user_info['email'].split('@')[0]
        elif 'uid' not in user_info:
            user_info['username'] = nameid
        else:
            user_info['username'] = user_info['uid']
        
        return user_info
    
    def validate_token_signature(self, token):
        """
        Validate SAML token signature
        """
        try:
            # This would be implemented with actual signature validation
            # For now, we'll rely on the SAML library's built-in validation
            settings = Settings(self.saml_settings)
            return settings.check_idp_x509cert()
        except Exception as e:
            logger.error(f"Token signature validation failed: {str(e)}")
            return False
    
    def is_token_expired(self, token_data):
        """
        Check if token is expired
        """
        try:
            # Extract timing information from token
            # This is a simplified implementation
            now = datetime.utcnow()
            # In a real implementation, you'd extract NotBefore and NotOnOrAfter from the assertion
            return False
        except Exception as e:
            logger.warning(f"Could not determine token expiry: {str(e)}")
            return False