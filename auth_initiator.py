"""
Authentication Initiator Module
Handles token acquisition from Shibboleth and eduMFA
"""
import logging
import requests
from urllib.parse import urlencode
from onelogin.saml2.auth import OneLogin_Saml2_Auth as Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils as Utils
from config import Config

logger = logging.getLogger(__name__)

class AuthInitiator:
    def __init__(self):
        self.saml_settings = Config.get_saml_settings()
        self.edumfa_base_url = Config.EDUMFA_BASE_URL
        self.edumfa_api_key = Config.EDUMFA_API_KEY
        
    def initiate_saml_auth(self, request_data, return_to=None):
        """
        Initiate SAML authentication flow
        
        Args:
            request_data: Flask request data
            return_to: URL to return to after authentication
            
        Returns:
            dict: Contains redirect URL for authentication
        """
        try:
            auth = Auth(self._prepare_flask_request(request_data), self.saml_settings)
            
            # Build the SAML authentication request
            sso_url = auth.login(return_to=return_to)
            
            logger.info(f"Initiating SAML authentication, redirecting to: {sso_url}")
            
            return {
                'success': True,
                'redirect_url': sso_url,
                'method': 'GET'
            }
            
        except Exception as e:
            logger.error(f"Failed to initiate SAML authentication: {str(e)}")
            return {
                'success': False,
                'error': 'Failed to initiate authentication',
                'details': str(e)
            }
    
    def check_existing_session(self, request_data):
            """
            Check if user has an existing valid session
            
            Args:
                request_data: Flask request data including session
                
            Returns:
                dict: Session validation result
            """
            try:
                # Import session from Flask here to access it
                from flask import session as flask_session
                
                if 'saml_nameid' in flask_session and 'saml_session_index' in flask_session:
                    # Check if session is still valid
                    if self._is_session_valid(flask_session):
                        return {
                            'success': True,
                            'has_session': True,
                            'user_info': flask_session.get('user_info', {}),
                            'session_data': {
                                'nameid': flask_session.get('saml_nameid'),
                                'session_index': flask_session.get('saml_session_index')
                            }
                        }
                
                return {
                    'success': True,
                    'has_session': False
                }
                
            except Exception as e:
                logger.error(f"Error checking existing session: {str(e)}")
                return {
                    'success': False,
                    'has_session': False,
                    'error': str(e)
                }
    
    def request_mfa_challenge(self, username, realm=None):
        """
        Request MFA challenge from eduMFA
        
        Args:
            username: Username for MFA challenge
            realm: eduMFA realm (optional)
            
        Returns:
            dict: MFA challenge response
        """
        try:
            if not self.edumfa_api_key:
                logger.warning("eduMFA API key not configured")
                return {
                    'success': False,
                    'error': 'eduMFA not configured'
                }
            
            realm = realm or Config.EDUMFA_REALM
            
            # Prepare API request to eduMFA
            url = f"{self.edumfa_base_url}/auth"
            headers = {
                'Authorization': f'Bearer {self.edumfa_api_key}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            data = {
                'username': username,
                'realm': realm,
                'pass': '',  # Empty password to trigger MFA challenge
            }
            
            response = requests.post(url, headers=headers, data=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get('result', {}).get('status'):
                    return {
                        'success': True,
                        'challenge': result.get('detail', {}),
                        'transaction_id': result.get('detail', {}).get('transaction_id')
                    }
                else:
                    return {
                        'success': False,
                        'error': 'MFA challenge failed',
                        'details': result.get('detail', {})
                    }
            else:
                logger.error(f"eduMFA API error: {response.status_code} - {response.text}")
                return {
                    'success': False,
                    'error': f'eduMFA API error: {response.status_code}'
                }
                
        except requests.RequestException as e:
            logger.error(f"eduMFA request failed: {str(e)}")
            return {
                'success': False,
                'error': 'eduMFA service unavailable',
                'details': str(e)
            }
        except Exception as e:
            logger.error(f"MFA challenge error: {str(e)}")
            return {
                'success': False,
                'error': 'MFA challenge failed',
                'details': str(e)
            }
    
    def validate_mfa_response(self, username, transaction_id, mfa_code, realm=None):
        """
        Validate MFA response with eduMFA
        
        Args:
            username: Username
            transaction_id: Transaction ID from challenge
            mfa_code: MFA code from user
            realm: eduMFA realm (optional)
            
        Returns:
            dict: MFA validation result
        """
        try:
            if not self.edumfa_api_key:
                return {
                    'success': False,
                    'error': 'eduMFA not configured'
                }
            
            realm = realm or Config.EDUMFA_REALM
            
            url = f"{self.edumfa_base_url}/auth"
            headers = {
                'Authorization': f'Bearer {self.edumfa_api_key}',
                'Content-Type': 'application/x-www-form-urlencoded'
            }
            
            data = {
                'username': username,
                'realm': realm,
                'pass': mfa_code,
                'transaction_id': transaction_id
            }
            
            response = requests.post(url, headers=headers, data=data, timeout=10)
            
            if response.status_code == 200:
                result = response.json()
                
                if result.get('result', {}).get('status') and result.get('result', {}).get('value'):
                    return {
                        'success': True,
                        'authenticated': True,
                        'details': result.get('detail', {})
                    }
                else:
                    return {
                        'success': True,
                        'authenticated': False,
                        'error': 'MFA validation failed',
                        'details': result.get('detail', {})
                    }
            else:
                return {
                    'success': False,
                    'error': f'eduMFA API error: {response.status_code}'
                }
                
        except Exception as e:
            logger.error(f"MFA validation error: {str(e)}")
            return {
                'success': False,
                'error': 'MFA validation failed',
                'details': str(e)
            }
    
    def initiate_logout(self, request_data, nameid=None, session_index=None):
        """
        Initiate SAML logout
        
        Args:
            request_data: Flask request data
            nameid: SAML NameID
            session_index: SAML session index
            
        Returns:
            dict: Logout initiation result
        """
        try:
            auth = Auth(self._prepare_flask_request(request_data), self.saml_settings)
            
            logout_url = auth.logout(
                name_id=nameid,
                session_index=session_index,
                return_to=f"{Config.SAML_SP_ENTITY_ID}/logout-complete"
            )
            
            return {
                'success': True,
                'redirect_url': logout_url
            }
            
        except Exception as e:
            logger.error(f"Failed to initiate logout: {str(e)}")
            return {
                'success': False,
                'error': 'Logout initiation failed',
                'details': str(e)
            }
    
    def _prepare_flask_request(self, request_data):
        """
        Prepare request data for SAML processing
        """
        if hasattr(request_data, 'form') and hasattr(request_data, 'args'):
            return {
                'https': 'on' if request_data.scheme == 'https' else 'off',
                'http_host': request_data.headers.get('Host', ''),
                'server_port': request_data.environ.get('SERVER_PORT', ''),
                'script_name': request_data.path,
                'get_data': request_data.args.copy(),
                'post_data': request_data.form.copy()
            }
        else:
            return request_data
    
    def _is_session_valid(self, session_data):
        """
        Check if session is still valid
        """
        try:
            # Check session timestamp
            session_time = session_data.get('timestamp')
            if session_time:
                import time
                current_time = time.time()
                if current_time - session_time > Config.TEMP_CREDENTIAL_EXPIRY:
                    return False
            
            return True
        except:
            return False