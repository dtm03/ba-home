"""
Configuration module for SAML-LDAP Bridge
"""
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    # Flask configuration
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    DEBUG = os.environ.get('DEBUG', 'False').lower() == 'true'
    
    # SAML configuration
    SAML_SP_ENTITY_ID = os.environ.get('SAML_SP_ENTITY_ID') or 'https://localhost:5000'
    SAML_SP_ASSERTION_CONSUMER_SERVICE_URL = os.environ.get('SAML_SP_ACS_URL') or 'https://localhost:5000/saml/acs'
    SAML_SP_SINGLE_LOGOUT_SERVICE_URL = os.environ.get('SAML_SP_SLS_URL') or 'https://localhost:5000/saml/sls'
    
    # Identity Provider (Shibboleth) configuration
    SAML_IDP_ENTITY_ID = os.environ.get('SAML_IDP_ENTITY_ID') or 'https://your-shibboleth-idp.edu'
    SAML_IDP_SSO_URL = os.environ.get('SAML_IDP_SSO_URL') or 'https://your-shibboleth-idp.edu/idp/profile/SAML2/Redirect/SSO'
    SAML_IDP_SLO_URL = os.environ.get('SAML_IDP_SLO_URL') or 'https://your-shibboleth-idp.edu/idp/profile/SAML2/Redirect/SLO'
    SAML_IDP_X509_CERT = os.environ.get('SAML_IDP_X509_CERT') or ''
    
    # eduMFA configuration
    EDUMFA_BASE_URL = os.environ.get('EDUMFA_BASE_URL') or 'https://your-edumfa-instance.edu'
    EDUMFA_API_KEY = os.environ.get('EDUMFA_API_KEY') or ''
    EDUMFA_REALM = os.environ.get('EDUMFA_REALM') or 'default'
    
    # LDAP configuration
    LDAP_HOST = os.environ.get('LDAP_HOST') or 'localhost'
    LDAP_PORT = int(os.environ.get('LDAP_PORT') or 389)
    LDAP_BASE_DN = os.environ.get('LDAP_BASE_DN') or 'dc=example,dc=com'
    LDAP_BIND_DN = os.environ.get('LDAP_BIND_DN') or 'cn=admin,dc=example,dc=com'
    LDAP_BIND_PASSWORD = os.environ.get('LDAP_BIND_PASSWORD') or 'admin'
    
    # Temporary credentials configuration
    TEMP_CREDENTIAL_EXPIRY = int(os.environ.get('TEMP_CREDENTIAL_EXPIRY') or 3600)  # 1 hour
    TEMP_CREDENTIAL_CLEANUP_INTERVAL = int(os.environ.get('TEMP_CREDENTIAL_CLEANUP_INTERVAL') or 300)  # 5 minutes
    
    # SSL/TLS configuration
    SSL_CERT_PATH = os.environ.get('SSL_CERT_PATH') or 'certs/cert.pem'
    SSL_KEY_PATH = os.environ.get('SSL_KEY_PATH') or 'certs/key.pem'
    
    @staticmethod
    def get_saml_settings():
        """Get SAML settings dictionary for python3-saml"""
        return {
            "strict": True,
            "debug": Config.DEBUG,
            "sp": {
                "entityId": Config.SAML_SP_ENTITY_ID,
                "assertionConsumerService": {
                    "url": Config.SAML_SP_ASSERTION_CONSUMER_SERVICE_URL,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
                },
                "singleLogoutService": {
                    "url": Config.SAML_SP_SINGLE_LOGOUT_SERVICE_URL,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "NameIDFormat": "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                "x509cert": "",
                "privateKey": ""
            },
            "idp": {
                "entityId": Config.SAML_IDP_ENTITY_ID,
                "singleSignOnService": {
                    "url": Config.SAML_IDP_SSO_URL,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "singleLogoutService": {
                    "url": Config.SAML_IDP_SLO_URL,
                    "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect"
                },
                "x509cert": Config.SAML_IDP_X509_CERT
            }
        }   