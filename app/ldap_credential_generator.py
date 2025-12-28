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

        # Try to write the temporary password into the configured LDAP server
        try:
            ldap_host = Config.LDAP_HOST or os.getenv('LDAP_HOST', 'localhost')
            ldap_port = Config.LDAP_PORT
            server = Server(ldap_host, port=ldap_port, get_info=ALL)

            bind_dn = Config.LDAP_BIND_DN or os.getenv('LDAP_BIND_DN') or f"cn=admin,{self.base_dn}"
            bind_password = Config.LDAP_BIND_PASSWORD or os.getenv('LDAP_BIND_PASSWORD') or os.getenv('LDAP_ADMIN_PASSWORD')

            # Log LDAP target and bind information
            logger.debug("LDAP target: %s:%s, base_dn=%s", ldap_host, ldap_port, self.base_dn)
            logger.debug("Attempting LDAP bind as: %s", bind_dn)

            if bind_dn and bind_password:
                # Try primary bind, then fall back to common admin DNs if it fails
                bind_attempts = []
                tried = []
                def try_bind(dn, pwd):
                    try:
                        c = Connection(server, user=dn, password=pwd, auto_bind=True)
                        return c
                    except Exception as e:
                        logger.debug("Bind attempt failed for %s: %s", dn, e)
                        return None

                conn = try_bind(bind_dn, bind_password)
                if conn:
                    logger.info("LDAP admin bind successful as %s", bind_dn)
                else:
                    # build fallback candidate DNs
                    candidates = []
                    if self.base_dn:
                        candidates.extend([
                            f"cn=admin,{self.base_dn}",
                            f"cn=Manager,{self.base_dn}",
                            f"cn=admin,{self.base_dn}".replace('dc=', 'dc=')
                        ])
                    # also include generic Manager DN used by some images
                    candidates.append(f"cn=Manager,{self.base_dn}" if self.base_dn else 'cn=Manager')
                    # remove duplicates but preserve order
                    seen = set()
                    candidates = [x for x in candidates if not (x in seen or seen.add(x))]

                    logger.debug("Primary admin bind failed; trying fallback admin DNs: %s", candidates)
                    for cand in candidates:
                        if cand in tried:
                            continue
                        tried.append(cand)
                        conn = try_bind(cand, bind_password)
                        if conn:
                            logger.info("LDAP admin bind successful as fallback DN %s", cand)
                            bind_dn = cand
                            break

                if not conn:
                    logger.warning("All admin bind attempts failed; cannot write LDAP password for %s", user_dn)
                    logger.debug("Tried bind DNs: %s with password present: %s", tried, bool(bind_password))
                else:
                    # proceed with LDAP operations using conn

                    # Ensure the entry exists (create if not)
                    try:
                        found = conn.search(self.base_dn, f"(uid={username})", attributes=['dn'])
                        logger.debug("LDAP search for uid=%s returned: %s", username, found)
                        if not conn.entries:
                            logger.info("LDAP entry for %s not found; creating %s", username, user_dn)
                            conn.add(user_dn, attributes=attrs)
                        else:
                            logger.debug("LDAP entries: %s", [e.entry_dn for e in conn.entries])
                    except Exception as e:
                        logger.warning("LDAP search/add operation failed for %s: %s", user_dn, e)

                    # Use password modify extended operation where available
                    try:
                        conn.extend.standard.modify_password(user_dn, password)
                        logger.info("Password modify operation attempted for %s", user_dn)
                    except Exception as e:
                        logger.debug("Password modify not supported or failed: %s", e)
                        # Fallback: replace userPassword attribute
                        try:
                            from ldap3 import MODIFY_REPLACE
                            conn.modify(user_dn, {'userPassword': [(MODIFY_REPLACE, [password])]})
                            logger.info("Replaced userPassword attribute for %s", user_dn)
                        except Exception as e2:
                            logger.warning("Failed to set password for %s using fallback modify: %s", user_dn, e2)

                    # Optionally log connection result details at debug level
                    try:
                        logger.debug("LDAP operation result: %s", getattr(conn, 'result', None))
                    except Exception:
                        pass

                    conn.unbind()
                    logger.info("Set temporary LDAP password for %s", user_dn)
            else:
                logger.debug("LDAP bind DN/password not configured; skipping LDAP password write")
        except Exception as e:
            logger.exception("Unexpected error while writing temporary LDAP password: %s", e)

        # Log current temporary credentials state (masked at INFO, full at DEBUG)
        try:
            self._log_temp_credentials_info()
            self._log_temp_credentials_debug()
        except Exception:
            logger.exception("Failed to log temporary credentials")

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