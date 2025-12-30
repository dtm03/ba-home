import logging, secrets, string, time, threading, bcrypt, os
from datetime import datetime
from config import Config
from ldap3 import Server, Connection, ALL

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
        
        # Define the structure
        people_ou = f"ou=people,{self.base_dn}"
        user_dn = f"uid={username},{people_ou}"
        
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

        try:
            ldap_host = Config.LDAP_HOST or os.getenv('LDAP_HOST', 'localhost')
            ldap_port = Config.LDAP_PORT
            server = Server(ldap_host, port=ldap_port, get_info=ALL)

            bind_dn = Config.LDAP_BIND_DN or os.getenv('LDAP_BIND_DN') or f"cn=admin,{self.base_dn}"
            bind_password = Config.LDAP_BIND_PASSWORD or os.getenv('LDAP_BIND_PASSWORD') or os.getenv('LDAP_ADMIN_PASSWORD')

            from ldap3 import Connection, MODIFY_REPLACE
            conn = Connection(server, user=bind_dn, password=bind_password, auto_bind=True)
            
            if conn:
                logger.info("LDAP admin bind successful")

                # --- NEW FIX: Ensure ou=people exists ---
                conn.search(self.base_dn, f"(&(objectClass=organizationalUnit)(ou=people))")
                if not conn.entries:
                    logger.info("Creating missing OU: %s", people_ou)
                    conn.add(people_ou, attributes={'objectClass': ['organizationalUnit', 'top'], 'ou': 'people'})

                # Ensure user entry exists
                conn.search(self.base_dn, f"(uid={username})")
                if not conn.entries:
                    logger.info("Creating LDAP entry for %s", username)
                    conn.add(user_dn, attributes=attrs)
                
                # Set the password using MODIFY_REPLACE
                conn.modify(user_dn, {'userPassword': [(MODIFY_REPLACE, [password])]})
                
                if conn.result['description'] == 'success':
                    logger.info("Successfully set LDAP password for %s", user_dn)
                else:
                    logger.error("Failed to set password: %s", conn.result)

                conn.unbind()
        
        except Exception as e:
            logger.exception("LDAP Error: %s", e)

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
            # Basis-Attribute, die immer da sein müssen
            attrs = {
                'objectClass': ['inetOrgPerson', 'posixAccount', 'top'],
                'uid': [username],
                'cn': [user_info.get('display_name', username)],
                'sn': [user_info.get('last_name', username)],
                'uidNumber': [str(hash(username) % 65535 + 1000)],
                'gidNumber': ['1000'],
                'homeDirectory': [f"/home/{username}"],
                'loginShell': ['/bin/bash'],
                'description': [f"Temporary account for {username} via SAML bridge"]
            }

            # Optionale Attribute NUR hinzufügen, wenn sie nicht leer sind
            email = user_info.get('email')
            if email:
                attrs['mail'] = [email]

            given_name = user_info.get('first_name')
            if given_name:
                attrs['givenName'] = [given_name]
            
            # Falls Auth0 nur 'display_name' liefert, aber kein 'last_name' (sn)
            if not attrs['sn'][0]:
                attrs['sn'] = [username]

            if groups := user_info.get('groups'):
                attrs['memberOf'] = groups if isinstance(groups, list) else [groups]
                
            return attrs

    def _log_temp_credentials_info(self):
        try:
            if not self.temp_credentials:
                logger.info("No temporary credentials currently stored")
                return
            entries = []
            from datetime import datetime
            for u, v in self.temp_credentials.items():
                expires = v.get('expires_at')
                expires_str = datetime.fromtimestamp(expires).isoformat() if expires else 'unknown'
                entries.append(f"{u} (expires: {expires_str})")
            logger.info("Temporary credentials: %s", ", ".join(entries))
        except Exception:
            logger.exception("Error while logging temporary credentials (info)")

    def _log_temp_credentials_debug(self):
        try:
            if not self.temp_credentials:
                logger.debug("No temporary credentials currently stored")
                return
            for u, v in self.temp_credentials.items():
                logger.debug("Temp credential - username: %s, user_dn: %s, password: %s, expires_at: %s, attributes: %s", u, v.get('user_dn'), v.get('password'), v.get('expires_at'), v.get('ldap_attributes'))
        except Exception:
            logger.exception("Error while logging temporary credentials (debug)")