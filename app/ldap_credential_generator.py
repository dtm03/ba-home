import logging, secrets, string, time, threading, bcrypt
from datetime import datetime
from config import Config

logger = logging.getLogger(__name__)

class CredentialGenerator:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*"

    def __init__(self):
        self.temp_credentials = {}
        self.cleanup_interval = Config.TEMP_CREDENTIAL_CLEANUP_INTERVAL
        self.credential_expiry = Config.TEMP_CREDENTIAL_EXPIRY
        self.base_dn = Config.LDAP_BASE_DN

    def generate_temporary_credentials(self, user_info):
        username = user_info.get('username', 'unknown')
        password = ''.join(secrets.choice(self.alphabet) for _ in range(16))
        password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
        expiry = time.time() + self.credential_expiry
        user_dn = f"uid={username},ou=people,{self.base_dn}"
        attrs = self._create_ldap_attributes(user_info, username)
        
        self.temp_credentials[username] = {
            'username': username,
            'user_dn': user_dn,
            'password': password,
            'password_hash': password_hash,
            'expires_at': expiry,
            'user_info': user_info,
            'ldap_attributes': attrs
        }

        return {
            'success': True,
            'username': username,
            'user_dn': user_dn,
            'password': password,
            'expires_at': datetime.fromtimestamp(expiry).isoformat(),
            'ldap_server': Config.LDAP_HOST,
            'ldap_port': Config.LDAP_PORT,
            'bind_dn': user_dn,
            'attributes': attrs
        }

    def _create_ldap_attributes(self, user_info, username):
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
        if groups := user_info.get('groups'):
            attrs['memberOf'] = groups if isinstance(groups, list) else [groups]
        for key in ['affiliation', 'scoped_affiliation']:
            if val := user_info.get(key):
                attrs[f"eduPerson{key[0].upper() + key[1:]}"] = [val]
        return attrs