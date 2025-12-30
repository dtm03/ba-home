import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY = os.getenv("SECRET_KEY")
    DEBUG = os.getenv("DEBUG", "False").lower() == "true"

    LDAP_HOST = os.getenv("LDAP_HOST")
    LDAP_PORT = int(os.getenv("LDAP_PORT"))
    LDAP_BASE_DN = os.getenv("LDAP_BASE_DN")
    LDAP_BIND_DN = os.getenv("LDAP_BIND_DN")
    LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD")

    SSL_CERT_PATH = os.getenv("SSL_CERT_PATH")
    SSL_KEY_PATH = os.getenv("SSL_KEY_PATH")

    TEMP_CREDENTIAL_CLEANUP_INTERVAL = int(os.getenv("TEMP_CREDENTIAL_CLEANUP_INTERVAL"))
    TEMP_CREDENTIAL_EXPIRY = int(os.getenv("TEMP_CREDENTIAL_EXPIRY"))

    SAML_SP_ENTITY_ID = os.getenv("SAML_SP_ENTITY_ID")
    SAML_SP_ACS_URL = os.getenv("SAML_SP_ACS_URL")
    SAML_SP_SLS_URL = os.getenv("SAML_SP_SLS_URL")
    SAML_IDP_ENTITY_ID = os.getenv("SAML_IDP_ENTITY_ID")
    SAML_IDP_SSO_URL = os.getenv("SAML_IDP_SSO_URL")
    SAML_IDP_X509_CERT = os.getenv("SAML_IDP_X509_CERT")

    @staticmethod
    def get_saml_settings():
        return {
            "strict": True,
            "debug": Config.DEBUG,
            "sp": {
                "entityId": Config.SAML_SP_ENTITY_ID,
                "assertionConsumerService": {
                    "url": Config.SAML_SP_ACS_URL,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                },
                "singleLogoutService": {
                    "url": Config.SAML_SP_SLS_URL,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
            },
            "idp": {
                "entityId": Config.SAML_IDP_ENTITY_ID,
                "singleSignOnService": {
                    "url": Config.SAML_IDP_SSO_URL,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "x509cert": Config.SAML_IDP_X509_CERT
            }
        }