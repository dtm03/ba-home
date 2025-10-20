#!/usr/bin/env python3
"""
Command Line Interface for SAML-LDAP Bridge
Management and administration tools
"""
import argparse
import sys
import json
import time
from datetime import datetime
from main import get_orchestrator
from config import Config

def print_status():
    """Print system status"""
    print("🔍 SAML-LDAP Bridge Status")
    print("=" * 40)
    
    orchestrator = get_orchestrator()
    status = orchestrator.get_system_status()
    
    if status.get('success'):
        print(f"Status: {status.get('status', 'Unknown').upper()}")
        print(f"Active Credentials: {status.get('active_credentials', 0)}")
        
        config_info = status.get('configuration', {})
        print(f"SAML IdP: {config_info.get('saml_idp_entity_id', 'Not configured')}")
        print(f"eduMFA: {'Enabled' if config_info.get('edumfa_configured') else 'Disabled'}")
        print(f"LDAP: {config_info.get('ldap_host')}:{config_info.get('ldap_port')}")
        
        timestamp = status.get('timestamp', time.time())
        print(f"Last Updated: {datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')}")
    else:
        print(f"❌ Failed to get status: {status.get('error')}")

def list_credentials():
    """List active credentials"""
    print("📋 Active Credentials")
    print("=" * 50)
    
    orchestrator = get_orchestrator()
    result = orchestrator.credential_generator.list_active_credentials()
    
    if result.get('success'):
        credentials = result.get('credentials', [])
        if credentials:
            print(f"Found {len(credentials)} active credentials:\n")
            
            for i, cred in enumerate(credentials, 1):
                print(f"{i}. Username: {cred['username']}")
                print(f"   Credential ID: {cred['credential_id']}")
                print(f"   DN: {cred['user_dn']}")
                print(f"   Created: {cred['created_at']}")
                print(f"   Expires: {cred['expires_at']}")
                print()
        else:
            print("No active credentials found")
    else:
        print(f"❌ Failed to list credentials: {result.get('error')}")

def revoke_credential(credential_id):
    """Revoke a specific credential"""
    print(f"🚫 Revoking credential: {credential_id}")
    
    orchestrator = get_orchestrator()
    result = orchestrator.credential_generator.revoke_credentials(credential_id)
    
    if result.get('success'):
        print("✅ Credential revoked successfully")
    else:
        print(f"❌ Failed to revoke credential: {result.get('error')}")

def validate_credentials(username, password):
    """Validate credentials"""
    print(f"🔐 Validating credentials for user: {username}")
    
    orchestrator = get_orchestrator()
    result = orchestrator.validate_ldap_credentials(username, password)
    
    if result.get('success') and result.get('valid'):
        print("✅ Credentials are valid")
        user_info = result.get('user_info', {})
        print(f"User DN: {result.get('user_dn')}")
        print(f"Display Name: {user_info.get('display_name', 'N/A')}")
        print(f"Email: {user_info.get('email', 'N/A')}")
    else:
        print(f"❌ Invalid credentials: {result.get('error', 'Unknown error')}")

def cleanup_expired():
    """Manually trigger cleanup of expired credentials"""
    print("🧹 Cleaning up expired credentials...")
    
    orchestrator = get_orchestrator()
    
    # Get current credentials count
    before_result = orchestrator.credential_generator.list_active_credentials()
    before_count = before_result.get('count', 0) if before_result.get('success') else 0
    
    # Force cleanup by checking expiry
    current_time = time.time()
    expired_ids = []
    
    for cred_id, cred_data in orchestrator.credential_generator.temp_credentials.items():
        if cred_data['expires_at'] <= current_time:
            expired_ids.append(cred_id)
    
    # Remove expired credentials
    for cred_id in expired_ids:
        orchestrator.credential_generator.revoke_credentials(cred_id)
    
    # Get updated count
    after_result = orchestrator.credential_generator.list_active_credentials()
    after_count = after_result.get('count', 0) if after_result.get('success') else 0
    
    cleaned_count = before_count - after_count
    print(f"✅ Cleaned up {cleaned_count} expired credentials")
    print(f"Active credentials: {after_count}")

def test_configuration():
    """Test system configuration"""
    print("🧪 Testing Configuration")
    print("=" * 30)
    
    # Test imports
    try:
        from token_validator import TokenValidator
        from auth_initiator import AuthInitiator
        from credential_generator import CredentialGenerator
        print("✅ All modules imported successfully")
    except Exception as e:
        print(f"❌ Module import failed: {e}")
        return
    
    # Test configuration
    try:
        print(f"✅ Configuration loaded")
        print(f"   SAML SP Entity ID: {Config.SAML_SP_ENTITY_ID}")
        print(f"   SAML IdP Entity ID: {Config.SAML_IDP_ENTITY_ID}")
        print(f"   LDAP Server: {Config.LDAP_HOST}:{Config.LDAP_PORT}")
        print(f"   eduMFA Configured: {'Yes' if Config.EDUMFA_API_KEY else 'No'}")
        print(f"   Credential Expiry: {Config.TEMP_CREDENTIAL_EXPIRY}s")
    except Exception as e:
        print(f"❌ Configuration error: {e}")
        return
    
    # Test orchestrator
    try:
        orchestrator = get_orchestrator()
        print("✅ Workflow orchestrator initialized")
    except Exception as e:
        print(f"❌ Orchestrator initialization failed: {e}")
        return
    
    print("\n✅ Configuration test completed successfully")

def export_config():
    """Export current configuration (sanitized)"""
    config_data = {
        'saml': {
            'sp_entity_id': Config.SAML_SP_ENTITY_ID,
            'idp_entity_id': Config.SAML_IDP_ENTITY_ID,
            'idp_sso_url': Config.SAML_IDP_SSO_URL,
            'idp_slo_url': Config.SAML_IDP_SLO_URL
        },
        'ldap': {
            'host': Config.LDAP_HOST,
            'port': Config.LDAP_PORT,
            'base_dn': Config.LDAP_BASE_DN
        },
        'edumfa': {
            'base_url': Config.EDUMFA_BASE_URL,
            'realm': Config.EDUMFA_REALM,
            'configured': bool(Config.EDUMFA_API_KEY)
        },
        'credentials': {
            'expiry_seconds': Config.TEMP_CREDENTIAL_EXPIRY,
            'cleanup_interval': Config.TEMP_CREDENTIAL_CLEANUP_INTERVAL
        }
    }
    
    print("📋 Current Configuration")
    print("=" * 25)
    print(json.dumps(config_data, indent=2))

def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description='SAML-LDAP Bridge Management CLI',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py status                    # Show system status
  python cli.py list                      # List active credentials
  python cli.py validate user pass       # Validate credentials
  python cli.py revoke cred_id            # Revoke credential
  python cli.py cleanup                   # Clean expired credentials
  python cli.py test                      # Test configuration
  python cli.py config                    # Export configuration
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Status command
    subparsers.add_parser('status', help='Show system status')
    
    # List command
    subparsers.add_parser('list', help='List active credentials')
    
    # Validate command
    validate_parser = subparsers.add_parser('validate', help='Validate credentials')
    validate_parser.add_argument('username', help='Username to validate')
    validate_parser.add_argument('password', help='Password to validate')
    
    # Revoke command
    revoke_parser = subparsers.add_parser('revoke', help='Revoke credential')
    revoke_parser.add_argument('credential_id', help='Credential ID to revoke')
    
    # Cleanup command
    subparsers.add_parser('cleanup', help='Clean up expired credentials')
    
    # Test command
    subparsers.add_parser('test', help='Test system configuration')
    
    # Config command
    subparsers.add_parser('config', help='Export configuration')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        if args.command == 'status':
            print_status()
        elif args.command == 'list':
            list_credentials()
        elif args.command == 'validate':
            validate_credentials(args.username, args.password)
        elif args.command == 'revoke':
            revoke_credential(args.credential_id)
        elif args.command == 'cleanup':
            cleanup_expired()
        elif args.command == 'test':
            test_configuration()
        elif args.command == 'config':
            export_config()
        else:
            parser.print_help()
    except KeyboardInterrupt:
        print("\n\n👋 Goodbye!")
    except Exception as e:
        print(f"\n❌ Command failed: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()