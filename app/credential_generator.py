import logging
import secrets
import string
import time
import threading
from datetime import datetime
import bcrypt
from config import Config

logger = logging.getLogger(__name__)

class CredentialGenerator:
    def __init__(self):
        self.temp_credentials = {}
        self.cleanup_interval = Config.TEMP_CREDENTIAL_CLEANUP_INTERVAL
        self.credential_expiry = Config.TEMP_CREDENTIAL_EXPIRY
        self.base_dn = Config.LDAP_BASE_DN
        threading.Thread(target=self._cleanup_expired_credentials, daemon=True).start()
        
    def generate_temporary_credentials(self, user_info):
        try:
            username = user_info.get('username', 'unknown')
            temp_password = self._generate_secure_password()
            user_dn = f"uid={username},ou=people,{self.base_dn}"
            password_hash = bcrypt.hashpw(temp_password.encode('utf-8'), bcrypt.gensalt())
            expiry_time = time.time() + self.credential_expiry
            self.temp_credentials[username] = {
                'username': username,
                'user_dn': user_dn,
                'password': temp_password,
                'password_hash': password_hash,
                'user_info': user_info,
                'created_at': time.time(),
                'expires_at': expiry_time,
                'ldap_attributes': self._create_ldap_attributes(user_info)
            }
            return {
                'success': True,
                'username': username,
                'user_dn': user_dn,
                'password': temp_password,
                'expires_at': datetime.fromtimestamp(expiry_time).isoformat(),
                'ldap_server': Config.LDAP_HOST,
                'ldap_port': Config.LDAP_PORT,
                'bind_dn': user_dn,
                'attributes': self.temp_credentials[username]['ldap_attributes']
            }
        except Exception as e:
            logger.error(f"Failed to generate temporary credentials: {str(e)}")
            return {'success': False, 'error': 'Credential generation failed', 'details': str(e)}
    
    def validate_credentials(self, username, password):
        try:
            cred_data = self.temp_credentials.get(username)
            if cred_data and cred_data['expires_at'] > time.time():
                if bcrypt.checkpw(password.encode('utf-8'), cred_data['password_hash']):
                    return {
                        'success': True,
                        'valid': True,
                        'user_info': cred_data['user_info'],
                        'user_dn': cred_data['user_dn'],
                        'attributes': cred_data['ldap_attributes'],
                        'expires_at': cred_data['expires_at']
                    }
            return {'success': True, 'valid': False, 'error': 'Invalid credentials or expired'}
        except Exception as e:
            logger.error(f"Credential validation error: {str(e)}")
            return {'success': False, 'error': 'Credential validation failed', 'details': str(e)}
    
    def get_user_attributes(self, username):
        try:
            cred_data = self.temp_credentials.get(username)
            if cred_data and cred_data['expires_at'] > time.time():
                return {'success': True, 'attributes': cred_data['ldap_attributes'], 'user_dn': cred_data['user_dn']}
            return {'success': False, 'error': 'User not found or credentials expired'}
        except Exception as e:
            logger.error(f"Error getting user attributes: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def revoke_credentials(self, username):
        try:
            if username in self.temp_credentials:
                del self.temp_credentials[username]
                return {'success': True, 'message': 'Credentials revoked successfully'}
            return {'success': False, 'error': 'User not found'}
        except Exception as e:
            logger.error(f"Error revoking credentials: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def list_active_credentials(self):
        try:
            current_time = time.time()
            active = []
            for username, cred in self.temp_credentials.items():
                if cred['expires_at'] > current_time:
                    active.append({
                        'username': username,
                        'user_dn': cred['user_dn'],
                        'created_at': datetime.fromtimestamp(cred['created_at']).isoformat(),
                        'expires_at': datetime.fromtimestamp(cred['expires_at']).isoformat()
                    })
            return {'success': True, 'credentials': active, 'count': len(active)}
        except Exception as e:
            logger.error(f"Error listing credentials: {str(e)}")
            return {'success': False, 'error': str(e)}
    
    def _generate_secure_password(self, length=16):
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    def _create_ldap_attributes(self, user_info):
        username = user_info.get('username', 'unknown')
        attrs = {
            'objectClass': ['inetOrgPerson', 'posixAccount', 'top'],
            'uid': [username],
            'cn': [user_info.get('display_name', username)],
            'sn': [user_info.get('last_name', username)],
            'givenName': [user_info.get('first_name', '')],
            'mail': [user_info.get('email', f"{username}@example.com")],
            'uidNumber': [str(hash(username) % 65535 + 1000)],
            'gidNumber': ['1000'],
            'homeDirectory': [f"/home/{username}"],
            'loginShell': ['/bin/bash'],
            'description': [f"Temporary account for {username} via SAML bridge"]
        }
        if 'groups' in user_info:
            groups = user_info['groups']
            if isinstance(groups, str):
                groups = [groups]
            attrs['memberOf'] = groups
        if 'affiliation' in user_info:
            attrs['eduPersonAffiliation'] = [user_info['affiliation']]
        if 'scoped_affiliation' in user_info:
            attrs['eduPersonScopedAffiliation'] = [user_info['scoped_affiliation']]
        return attrs
    
    def _cleanup_expired_credentials(self):
        while True:
            current_time = time.time()
            expired = [user for user, cred in self.temp_credentials.items() if cred['expires_at'] <= current_time]
            for user in expired:
                del self.temp_credentials[user]
            time.sleep(self.cleanup_interval)
