"""
Setup script for SAML-LDAP Bridge
Handles installation, configuration, and SSL certificate generation
"""
import os
import sys
import subprocess
import shutil
from pathlib import Path
import secrets
import string

def generate_secret_key():
    """Generate a secure secret key"""
    alphabet = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(alphabet) for _ in range(50))

def create_ssl_certificates():
    """Create self-signed SSL certificates for development"""
    cert_dir = Path('certs')
    cert_dir.mkdir(exist_ok=True)
    
    cert_file = cert_dir / 'cert.pem'
    key_file = cert_dir / 'key.pem'
    
    if cert_file.exists() and key_file.exists():
        print("✅ SSL certificates already exist")
        return True
    
    print("🔒 Generating SSL certificates...")
    
    try:
        # Generate private key
        subprocess.run([
            'openssl', 'genrsa', '-out', str(key_file), '2048'
        ], check=True, capture_output=True)
        
        # Generate self-signed certificate
        subprocess.run([
            'openssl', 'req', '-new', '-x509', '-key', str(key_file),
            '-out', str(cert_file), '-days', '365', '-subj',
            '/C=US/ST=State/L=City/O=Organization/CN=localhost'
        ], check=True, capture_output=True)
        
        print("✅ SSL certificates generated successfully")
        print(f"   Certificate: {cert_file}")
        print(f"   Private key: {key_file}")
        return True
        
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to generate SSL certificates: {e}")
        print("   You can run the application without HTTPS or provide your own certificates")
        return False
    except FileNotFoundError:
        print("⚠️  OpenSSL not found. Skipping SSL certificate generation.")
        print("   Install OpenSSL or provide your own certificates for HTTPS")
        return False

def create_env_file():
    """Create .env file from template"""
    env_file = Path('.env')
    env_example = Path('.env.example')
    
    if env_file.exists():
        print("✅ .env file already exists")
        return
    
    if not env_example.exists():
        print("❌ .env.example not found")
        return
    
    print("📝 Creating .env file...")
    
    # Read template
    with open(env_example, 'r') as f:
        content = f.read()
    
    # Replace placeholders
    content = content.replace(
        'your-secret-key-change-this-in-production',
        generate_secret_key()
    )
    
    # Write .env file
    with open(env_file, 'w') as f:
        f.write(content)
    
    print("✅ .env file created successfully")
    print("   Please edit .env file to configure your SAML IdP and LDAP settings")

def create_directories():
    """Create necessary directories"""
    directories = ['certs', 'logs', 'config', 'templates']
    
    for dir_name in directories:
        Path(dir_name).mkdir(exist_ok=True)
        print(f"📁 Created directory: {dir_name}")

def install_requirements():
    """Install Python requirements"""
    print("📦 Installing Python requirements...")
    
    try:
        subprocess.run([
            sys.executable, '-m', 'pip', 'install', '-r', 'requirements.txt'
        ], check=True)
        print("✅ Requirements installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install requirements: {e}")
        return False

def check_system_requirements():
    """Check system requirements"""
    print("🔍 Checking system requirements...")
    
    # Check Python version
    if sys.version_info < (3, 8):
        print(f"❌ Python 3.8+ required, found {sys.version}")
        return False
    
    print(f"✅ Python {sys.version.split()[0]} found")
    
    # Check pip
    try:
        import pip
        print(f"✅ pip available")
    except ImportError:
        print("❌ pip not found")
        return False
    
    return True

def run_initial_test():
    """Run initial application test"""
    print("🧪 Running initial test...")
    
    try:
        # Import main modules to check for syntax errors
        import config
        import token_validator
        import auth_initiator
        import credential_generator
        import main
        
        print("✅ All modules imported successfully")
        
        # Test configuration
        from config import Config
        print(f"✅ Configuration loaded")
        print(f"   SAML SP Entity ID: {Config.SAML_SP_ENTITY_ID}")
        print(f"   LDAP Host: {Config.LDAP_HOST}:{Config.LDAP_PORT}")
        
        return True
        
    except Exception as e:
        print(f"❌ Initial test failed: {e}")
        return False

def print_next_steps():
    """Print next steps for user"""
    print("\n" + "="*60)
    print("🎉 SAML-LDAP Bridge Setup Complete!")
    print("="*60)
    
    print("\n📋 Next Steps:")
    print("1. Edit .env file with your SAML IdP and LDAP configuration")
    print("2. Configure your SAML Identity Provider to trust this service")
    print("3. Start the application:")
    print("   python app.py")
    print("\n4. Or use Docker:")
    print("   docker-compose up -d")
    
    print("\n🔗 Application URLs:")
    print("   Main Interface: https://localhost:5000")
    print("   Demo Interface: https://localhost:5000/demo")
    print("   Health Check:   https://localhost:5000/health")
    print("   System Status:  https://localhost:5000/status")
    
    print("\n📖 Documentation:")
    print("   See README.md for detailed configuration instructions")
    
    print("\n⚠️  Important Security Notes:")
    print("   - Change the SECRET_KEY in .env for production")
    print("   - Use proper SSL certificates (not self-signed) in production")
    print("   - Configure your SAML IdP with proper security settings")
    print("   - Review and adjust LDAP server settings")

def main():
    """Main setup function"""
    print("🚀 SAML-LDAP Bridge Setup")
    print("=" * 30)
    
    # Check system requirements
    if not check_system_requirements():
        print("❌ System requirements not met")
        sys.exit(1)
    
    # Create directories
    create_directories()
    
    # Install requirements
    if not install_requirements():
        print("❌ Failed to install requirements")
        sys.exit(1)
    
    # Create .env file
    create_env_file()
    
    # Create SSL certificates
    create_ssl_certificates()
    
    # Run initial test
    if not run_initial_test():
        print("❌ Initial test failed")
        print("   Check your configuration and try again")
        sys.exit(1)
    
    # Print next steps
    print_next_steps()

if __name__ == '__main__':
    main()