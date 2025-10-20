"""
Temporary LDAP Credential Generator
Creates and manages temporary LDAP-compatible credentials
"""
import logging
import secrets
import string
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, Optional
import bcrypt
from config import Config

logger = logging.getLogger(__name__)

class CredentialGenerator:
    def __init__(self):
        self.temp_credentials = {}  # In-memory storage for demo (use Redis in production)
        self.cleanup_interval = Config.TEMP_CREDENTIAL_CLEANUP_INTERVAL
        self.credential_expiry = Config.TEMP_CREDENTIAL_EXPIRY
        self.base_dn = Config.LDAP_BASE_DN
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired_credentials, daemon=True)
        self.cleanup_thread.start()
        
    def generate_temporary_credentials(self, user_info: Dict) -> Dict:
        """
        Generate temporary LDAP credentials for authenticated user
        
        Args:
            user_info: Dictionary containing user information from SAML
            
        Returns:
            dict: Temporary credential information
        """
        try:
            username = user_info.get('username', 'unknown')
            
            # Generate temporary password
            temp_password = self._generate_secure_password()
            
            # Create LDAP DN
            user_dn = f"uid={username},ou=people,{self.base_dn}"
            
            # Hash the password for storage
            password_hash = bcrypt.hashpw(temp_password.encode('utf-8'), bcrypt.gensalt())
            
            # Create credential entry
            credential_id = self._generate_credential_id()
            expiry_time = time.time() + self.credential_expiry
            
            credential_data = {
                'credential_id': credential_id,
                'username': username,
                'user_dn': user_dn,
                'password': temp_password,
                'password_hash': password_hash,
                'user_info': user_info,
                'created_at': time.time(),
                'expires_at': expiry_time,
                'ldap_attributes': self._create_ldap_attributes(user_info)
            }
            
            # Store credentials
            self.temp_credentials[credential_id] = credential_data
            
            logger.info(f"Generated temporary credentials for user: {username} (ID: {credential_id})")
            
            return {
                'success': True,
                'credential_id': credential_id,
                'username': username,
                'user_dn': user_dn,
                'password': temp_password,
                'expires_at': datetime.fromtimestamp(expiry_time).isoformat(),
                'ldap_server': Config.LDAP_HOST,
                'ldap_port': Config.LDAP_PORT,
                'bind_dn': user_dn,
                'attributes': credential_data['ldap_attributes']
            }
            
        except Exception as e:
            logger.error(f"Failed to generate temporary credentials: {str(e)}")
            return {
                'success': False,
                'error': 'Credential generation failed',
                'details': str(e)
            }
    
    def validate_credentials(self, username: str, password: str) -> Dict:
        """
        Validate temporary LDAP credentials
        
        Args:
            username: Username to validate
            password: Password to validate
            
        Returns:
            dict: Validation result
        """
        try:
            current_time = time.time()
            
            # Find matching credentials
            for credential_id, cred_data in self.temp_credentials.items():
                if (cred_data['username'] == username and 
                    cred_data['expires_at'] > current_time):
                    
                    # Validate password
                    if bcrypt.checkpw(password.encode('utf-8'), cred_data['password_hash']):
                        logger.info(f"Credential validation successful for user: {username}")
                        return {
                            'success': True,
                            'valid': True,
                            'user_info': cred_data['user_info'],
                            'user_dn': cred_data['user_dn'],
                            'attributes': cred_data['ldap_attributes'],
                            'expires_at': cred_data['expires_at']
                        }
            
            logger.warning(f"Credential validation failed for user: {username}")
            return {
                'success': True,
                'valid': False,
                'error': 'Invalid credentials or expired'
            }
            
        except Exception as e:
            logger.error(f"Credential validation error: {str(e)}")
            return {
                'success': False,
                'error': 'Credential validation failed',
                'details': str(e)
            }
    
    def get_user_attributes(self, username: str) -> Dict:
        """
        Get LDAP attributes for a user
        
        Args:
            username: Username to lookup
            
        Returns:
            dict: User attributes
        """
        try:
            current_time = time.time()
            
            for credential_id, cred_data in self.temp_credentials.items():
                if (cred_data['username'] == username and 
                    cred_data['expires_at'] > current_time):
                    
                    return {
                        'success': True,
                        'attributes': cred_data['ldap_attributes'],
                        'user_dn': cred_data['user_dn']
                    }
            
            return {
                'success': False,
                'error': 'User not found or credentials expired'
            }
            
        except Exception as e:
            logger.error(f"Error getting user attributes: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def revoke_credentials(self, credential_id: str) -> Dict:
        """
        Revoke temporary credentials
        
        Args:
            credential_id: ID of credentials to revoke
            
        Returns:
            dict: Revocation result
        """
        try:
            if credential_id in self.temp_credentials:
                username = self.temp_credentials[credential_id]['username']
                del self.temp_credentials[credential_id]
                
                logger.info(f"Revoked credentials for user: {username} (ID: {credential_id})")
                
                return {
                    'success': True,
                    'message': 'Credentials revoked successfully'
                }
            else:
                return {
                    'success': False,
                    'error': 'Credential ID not found'
                }
                
        except Exception as e:
            logger.error(f"Error revoking credentials: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def list_active_credentials(self) -> Dict:
        """
        List all active credentials (for admin purposes)
        
        Returns:
            dict: List of active credentials
        """
        try:
            current_time = time.time()
            active_credentials = []
            
            for credential_id, cred_data in self.temp_credentials.items():
                if cred_data['expires_at'] > current_time:
                    active_credentials.append({
                        'credential_id': credential_id,
                        'username': cred_data['username'],
                        'user_dn': cred_data['user_dn'],
                        'created_at': datetime.fromtimestamp(cred_data['created_at']).isoformat(),
                        'expires_at': datetime.fromtimestamp(cred_data['expires_at']).isoformat()
                    })
            
            return {
                'success': True,
                'credentials': active_credentials,
                'count': len(active_credentials)
            }
            
        except Exception as e:
            logger.error(f"Error listing credentials: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _generate_secure_password(self, length: int = 16) -> str:
        """Generate a secure random password"""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        password = ''.join(secrets.choice(alphabet) for _ in range(length))
        return password
    
    def _generate_credential_id(self) -> str:
        """Generate a unique credential ID"""
        return secrets.token_urlsafe(16)
    
    def _create_ldap_attributes(self, user_info: Dict) -> Dict:
        """
        Create LDAP attributes from SAML user info
        
        Args:
            user_info: User information from SAML
            
        Returns:
            dict: LDAP attributes
        """
        username = user_info.get('username', 'unknown')
        
        attributes = {
            'objectClass': ['inetOrgPerson', 'posixAccount', 'top'],
            'uid': [username],
            'cn': [user_info.get('display_name', username)],
            'sn': [user_info.get('last_name', username)],
            'givenName': [user_info.get('first_name', '')],
            'mail': [user_info.get('email', f"{username}@example.com")],
            'uidNumber': [str(hash(username) % 65535 + 1000)],  # Generate UID number
            'gidNumber': ['1000'],  # Default group
            'homeDirectory': [f"/home/{username}"],
            'loginShell': ['/bin/bash'],
            'description': [f"Temporary account for {username} via SAML bridge"]
        }
        
        # Add additional attributes if available
        if 'groups' in user_info:
            groups = user_info['groups']
            if isinstance(groups, str):
                groups = [groups]
            attributes['memberOf'] = groups
        
        if 'affiliation' in user_info:
            attributes['eduPersonAffiliation'] = [user_info['affiliation']]
        
        if 'scoped_affiliation' in user_info:
            attributes['eduPersonScopedAffiliation'] = [user_info['scoped_affiliation']]
        
        return attributes
    
    def _cleanup_expired_credentials(self):
        """Background thread to clean up expired credentials"""
        while True:
            try:
                current_time = time.time()
                expired_ids = []
                
                for credential_id, cred_data in self.temp_credentials.items():
                    if cred_data['expires_at'] <= current_time:
                        expired_ids.append(credential_id)
                
                for credential_id in expired_ids:
                    username = self.temp_credentials[credential_id]['username']
                    del self.temp_credentials[credential_id]
                    logger.info(f"Cleaned up expired credentials for user: {username} (ID: {credential_id})")
                
                if expired_ids:
                    logger.info(f"Cleaned up {len(expired_ids)} expired credentials")
                
            except Exception as e:
                logger.error(f"Error in credential cleanup: {str(e)}")
            
            time.sleep(self.cleanup_interval)