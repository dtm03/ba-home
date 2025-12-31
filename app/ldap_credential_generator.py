import logging
import secrets
import string
import os
from datetime import datetime, timedelta
from typing import Optional, Union
from ldap3 import Server, Connection, MODIFY_REPLACE, ALL
from config import Config

logger = logging.getLogger(__name__)

class CredentialGenerator:
    PASSWORD_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*"

    def __init__(self):
        self.base_dn = Config.LDAP_BASE_DN
        self.ldap_host = Config.LDAP_HOST or os.getenv("LDAP_HOST", "localhost")
        self.ldap_port = Config.LDAP_PORT

        self.bind_dn = (
            Config.LDAP_BIND_DN
            or os.getenv("LDAP_BIND_DN")
            or f"cn=admin,{self.base_dn}"
        )

        self.bind_password = (
            Config.LDAP_BIND_PASSWORD
            or os.getenv("LDAP_BIND_PASSWORD")
            or os.getenv("LDAP_ADMIN_PASSWORD")
        )

    def _generate_password(self, length: int = 16) -> str:
        return "".join(secrets.choice(self.PASSWORD_ALPHABET) for _ in range(length))

    def issue_temporary_credentials(self, user_data: Union[str, dict], email: Optional[str] = None) -> dict:
        if isinstance(user_data, dict):
            username = user_data.get('username')
            email = email or user_data.get('email')
        else:
            username = user_data

        if not username:
            raise ValueError(f"Could not determine username from input: {user_data}")

        user_dn = f"uid={username},{self.base_dn}"
        password = self._generate_password()

        server = Server(
            self.ldap_host,
            port=self.ldap_port,
            get_info=ALL
        )

        conn = Connection(
            server,
            user=self.bind_dn,
            password=self.bind_password,
            auto_bind=True
        )

        if not conn.search(self.base_dn, f"(uid={username})"):
            conn.unbind()
            raise ValueError(f"LDAP user not found: {username}")

        changes = {
            "userPassword": [(MODIFY_REPLACE, [password])]
        }

        conn.modify(user_dn, changes)

        if conn.result["description"] != "success":
            result_error = conn.result
            conn.unbind()
            raise RuntimeError(f"LDAP modify failed: {result_error}")

        conn.unbind()

        logger.debug("Temporary LDAP password issued for %s", user_dn)

        return {
            "username": username,
            "dn": user_dn,
            "password": password,
            'expires_at': (datetime.utcnow() + timedelta(hours=1)).isoformat() 
        }