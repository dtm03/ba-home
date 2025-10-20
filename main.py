"""
Main Workflow Orchestrator
Central coordination of SAML-LDAP bridge operations
"""
import logging
import time
from typing import Dict, Optional
from token_validator import TokenValidator
from auth_initiator import AuthInitiator
from credential_generator import CredentialGenerator
from config import Config

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('saml_ldap_bridge.log'),
        logging.StreamHandler()
    ]
)

logger = logging.getLogger(__name__)

class WorkflowOrchestrator:
    def __init__(self):
        self.token_validator = TokenValidator()
        self.auth_initiator = AuthInitiator()
        self.credential_generator = CredentialGenerator()
        
        logger.info("SAML-LDAP Bridge Workflow Orchestrator initialized")
    
    def process_authentication_request(self, request_data: Dict) -> Dict:
        """
        Process incoming authentication request
        
        Args:
            request_data: Request data from web interface
            
        Returns:
            dict: Authentication processing result
        """
        try:
            logger.info("Processing authentication request")
            
            # Check for existing session
            session_check = self.auth_initiator.check_existing_session(request_data)
            
            if session_check.get('success') and session_check.get('has_session'):
                logger.info("Found existing valid session")
                return {
                    'success': True,
                    'action': 'session_valid',
                    'user_info': session_check.get('user_info'),
                    'session_data': session_check.get('session_data')
                }
            
            # Check if this is a SAML response
            if self._is_saml_response(request_data):
                return self._process_saml_response(request_data)
            
            # Check if this is an MFA response
            if self._is_mfa_response(request_data):
                return self._process_mfa_response(request_data)
            
            # Initiate new authentication
            return self._initiate_authentication(request_data)
            
        except Exception as e:
            logger.error(f"Error processing authentication request: {str(e)}")
            return {
                'success': False,
                'error': 'Authentication processing failed',
                'details': str(e)
            }
    
    def process_credential_request(self, user_info: Dict, session_data: Dict) -> Dict:
        """
        Process request for temporary LDAP credentials
        
        Args:
            user_info: Validated user information
            session_data: Session data from authentication
            
        Returns:
            dict: Credential generation result
        """
        try:
            logger.info(f"Processing credential request for user: {user_info.get('username', 'unknown')}")
            
            # Generate temporary credentials
            credential_result = self.credential_generator.generate_temporary_credentials(user_info)
            
            if credential_result.get('success'):
                # Log successful credential generation
                logger.info(f"Successfully generated credentials for user: {user_info.get('username')}")
                
                return {
                    'success': True,
                    'action': 'credentials_generated',
                    'credentials': credential_result,
                    'user_info': user_info
                }
            else:
                logger.error(f"Failed to generate credentials: {credential_result.get('error')}")
                return {
                    'success': False,
                    'error': 'Credential generation failed',
                    'details': credential_result.get('details')
                }
                
        except Exception as e:
            logger.error(f"Error processing credential request: {str(e)}")
            return {
                'success': False,
                'error': 'Credential request processing failed',
                'details': str(e)
            }
    
    def validate_ldap_credentials(self, username: str, password: str) -> Dict:
        """
        Validate LDAP credentials against temporary store
        
        Args:
            username: Username to validate
            password: Password to validate
            
        Returns:
            dict: Validation result
        """
        try:
            logger.info(f"Validating LDAP credentials for user: {username}")
            
            validation_result = self.credential_generator.validate_credentials(username, password)
            
            if validation_result.get('success') and validation_result.get('valid'):
                logger.info(f"LDAP credential validation successful for user: {username}")
                return {
                    'success': True,
                    'valid': True,
                    'user_info': validation_result.get('user_info'),
                    'user_dn': validation_result.get('user_dn'),
                    'attributes': validation_result.get('attributes')
                }
            else:
                logger.warning(f"LDAP credential validation failed for user: {username}")
                return {
                    'success': True,
                    'valid': False,
                    'error': validation_result.get('error', 'Invalid credentials')
                }
                
        except Exception as e:
            logger.error(f"Error validating LDAP credentials: {str(e)}")
            return {
                'success': False,
                'error': 'LDAP credential validation failed',
                'details': str(e)
            }
    
    def process_logout_request(self, request_data: Dict) -> Dict:
        """
        Process logout request
        
        Args:
            request_data: Request data including session info
            
        Returns:
            dict: Logout processing result
        """
        try:
            logger.info("Processing logout request")
            
            session = request_data.get('session', {})
            nameid = session.get('saml_nameid')
            session_index = session.get('saml_session_index')
            credential_id = session.get('credential_id')
            
            # Revoke temporary credentials if they exist
            if credential_id:
                revoke_result = self.credential_generator.revoke_credentials(credential_id)
                if revoke_result.get('success'):
                    logger.info(f"Revoked temporary credentials: {credential_id}")
            
            # Initiate SAML logout if we have session data
            if nameid and session_index:
                logout_result = self.auth_initiator.initiate_logout(
                    request_data, nameid=nameid, session_index=session_index
                )
                
                if logout_result.get('success'):
                    return {
                        'success': True,
                        'action': 'saml_logout',
                        'redirect_url': logout_result.get('redirect_url')
                    }
            
            # Local logout only
            return {
                'success': True,
                'action': 'local_logout',
                'message': 'Logged out successfully'
            }
            
        except Exception as e:
            logger.error(f"Error processing logout: {str(e)}")
            return {
                'success': False,
                'error': 'Logout processing failed',
                'details': str(e)
            }
    
    def get_system_status(self) -> Dict:
        """
        Get system status information
        
        Returns:
            dict: System status
        """
        try:
            # Get active credentials count
            credentials_info = self.credential_generator.list_active_credentials()
            active_credentials_count = credentials_info.get('count', 0) if credentials_info.get('success') else 0
            
            return {
                'success': True,
                'status': 'running',
                'active_credentials': active_credentials_count,
                'configuration': {
                    'saml_sp_entity_id': Config.SAML_SP_ENTITY_ID,
                    'saml_idp_entity_id': Config.SAML_IDP_ENTITY_ID,
                    'edumfa_configured': bool(Config.EDUMFA_API_KEY),
                    'ldap_host': Config.LDAP_HOST,
                    'ldap_port': Config.LDAP_PORT
                },
                'timestamp': time.time()
            }
            
        except Exception as e:
            logger.error(f"Error getting system status: {str(e)}")
            return {
                'success': False,
                'error': 'Failed to get system status',
                'details': str(e)
            }
    
    def _is_saml_response(self, request_data: Dict) -> bool:
        """Check if request contains SAML response"""
        if hasattr(request_data, 'form'):
            return 'SAMLResponse' in request_data.form
        return 'SAMLResponse' in request_data.get('post_data', {})
    
    def _is_mfa_response(self, request_data: Dict) -> bool:
        """Check if request contains MFA response"""
        if hasattr(request_data, 'form'):
            return 'mfa_code' in request_data.form and 'transaction_id' in request_data.form
        return 'mfa_code' in request_data.get('post_data', {})
    
    def _process_saml_response(self, request_data: Dict) -> Dict:
        """Process SAML authentication response"""
        logger.info("Processing SAML response")
        
        # Validate SAML token
        validation_result = self.token_validator.validate_saml_response(request_data)
        
        if not validation_result.get('success'):
            logger.error(f"SAML validation failed: {validation_result.get('error')}")
            return {
                'success': False,
                'action': 'validation_failed',
                'error': validation_result.get('error'),
                'details': validation_result.get('details')
            }
        
        user_info = validation_result.get('user_info', {})
        username = user_info.get('username')
        
        # Check if MFA is required
        if Config.EDUMFA_API_KEY:
            logger.info(f"Requesting MFA challenge for user: {username}")
            
            mfa_result = self.auth_initiator.request_mfa_challenge(username)
            
            if mfa_result.get('success'):
                return {
                    'success': True,
                    'action': 'mfa_required',
                    'user_info': user_info,
                    'mfa_challenge': mfa_result.get('challenge'),
                    'transaction_id': mfa_result.get('transaction_id'),
                    'saml_data': {
                        'nameid': validation_result.get('nameid'),
                        'session_index': validation_result.get('session_index')
                    }
                }
            else:
                logger.warning(f"MFA challenge failed, proceeding without MFA: {mfa_result.get('error')}")
        
        # Proceed without MFA or if MFA failed
        return {
            'success': True,
            'action': 'saml_authenticated',
            'user_info': user_info,
            'saml_data': {
                'nameid': validation_result.get('nameid'),
                'session_index': validation_result.get('session_index'),
                'attributes': validation_result.get('attributes')
            }
        }
    
    def _process_mfa_response(self, request_data: Dict) -> Dict:
        """Process MFA authentication response"""
        logger.info("Processing MFA response")
        
        if hasattr(request_data, 'form'):
            mfa_code = request_data.form.get('mfa_code')
            transaction_id = request_data.form.get('transaction_id')
            username = request_data.form.get('username')
        else:
            post_data = request_data.get('post_data', {})
            mfa_code = post_data.get('mfa_code')
            transaction_id = post_data.get('transaction_id')
            username = post_data.get('username')
        
        if not all([mfa_code, transaction_id, username]):
            return {
                'success': False,
                'error': 'Missing MFA parameters'
            }
        
        # Validate MFA response
        mfa_result = self.auth_initiator.validate_mfa_response(
            username, transaction_id, mfa_code
        )
        
        if mfa_result.get('success') and mfa_result.get('authenticated'):
            logger.info(f"MFA validation successful for user: {username}")
            
            # Get user info from session or reconstruct
            session = request_data.get('session', {})
            user_info = session.get('temp_user_info', {'username': username})
            
            return {
                'success': True,
                'action': 'mfa_authenticated',
                'user_info': user_info,
                'saml_data': session.get('temp_saml_data', {})
            }
        else:
            logger.warning(f"MFA validation failed for user: {username}")
            return {
                'success': False,
                'action': 'mfa_failed',
                'error': 'MFA validation failed',
                'details': mfa_result.get('details')
            }
    
    def _initiate_authentication(self, request_data: Dict) -> Dict:
            """Initiate new authentication flow"""
            logger.info("Initiating new authentication flow")
            
            # Handle Flask request object properly
            if hasattr(request_data, 'args'):
                return_to = request_data.args.get('return_to')
            else:
                return_to = request_data.get('return_to') if isinstance(request_data, dict) else None
            
            auth_result = self.auth_initiator.initiate_saml_auth(request_data, return_to=return_to)
            
            if auth_result.get('success'):
                return {
                    'success': True,
                    'action': 'redirect_to_idp',
                    'redirect_url': auth_result.get('redirect_url')
                }
            else:
                return {
                    'success': False,
                    'error': 'Failed to initiate authentication',
                    'details': auth_result.get('details')
                }


# Global orchestrator instance
orchestrator = WorkflowOrchestrator()

def get_orchestrator():
    """Get the global orchestrator instance"""
    return orchestrator