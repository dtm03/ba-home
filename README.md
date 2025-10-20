# SAML-LDAP Bridge

A bridge service that converts SAML authentication into temporary LDAP credentials, enabling legacy LDAP-based applications to work with modern SAML Identity Providers like Shibboleth.

## 🏗️ Architecture

The SAML-LDAP Bridge provides a seamless way to integrate legacy LDAP applications with SAML-based authentication systems:

```
[User] → [SAML IdP] → [Bridge Service] → [Temporary LDAP Credentials] → [Legacy App]
```

### Key Components

- **Token Validator**: Validates SAML tokens from Shibboleth IdP
- **Auth Initiator**: Manages authentication flow and MFA integration
- **Credential Generator**: Creates temporary LDAP-compatible credentials
- **Web Interface**: User-friendly authentication interface
- **Demo Interface**: Testing and validation tools

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- SAML Identity Provider (Shibboleth recommended)
- Optional: eduMFA for multi-factor authentication
- Optional: LDAP server for testing

### Installation

1. **Clone and Setup**

   ```bash
   git clone <repository-url>
   cd saml-ldap-bridge
   python setup.py
   ```

2. **Configure Environment**

   ```bash
   cp .env.example .env
   # Edit .env with your configuration
   ```

3. **Start the Service**

   ```bash
   python app.py
   ```

4. **Access the Application**
   - Main Interface: https://localhost:5000
   - Demo Interface: https://localhost:5000/demo
   - System Status: https://localhost:5000/status

## ⚙️ Configuration

### Environment Variables

Edit the `.env` file with your configuration:

```bash
# SAML Configuration
SAML_SP_ENTITY_ID=https://your-domain.com/saml-ldap-bridge
SAML_IDP_ENTITY_ID=https://your-shibboleth-idp.edu/idp/shibboleth
SAML_IDP_SSO_URL=https://your-shibboleth-idp.edu/idp/profile/SAML2/Redirect/SSO

# LDAP Configuration
LDAP_HOST=your-ldap-server.com
LDAP_PORT=389
LDAP_BASE_DN=dc=example,dc=com

# eduMFA (Optional)
EDUMFA_BASE_URL=https://your-edumfa-instance.edu
EDUMFA_API_KEY=your-api-key
```

### SAML Identity Provider Setup

Configure your Shibboleth IdP to trust this service:

1. **Add Service Provider Metadata**

   ```xml
   <EntityDescriptor entityID="https://your-domain.com/saml-ldap-bridge">
     <SPSSODescriptor>
       <AssertionConsumerService
         Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
         Location="https://your-domain.com/saml/acs" />
     </SPSSODescriptor>
   </EntityDescriptor>
   ```

2. **Configure Attribute Release**
   Release necessary attributes like `uid`, `mail`, `displayName`, etc.

## 🐳 Docker Deployment

### Basic Deployment

```bash
docker-compose up -d
```

### With Demo LDAP Server

```bash
docker-compose --profile demo up -d
```

### With Redis (Recommended for Production)

```bash
docker-compose --profile redis up -d
```

## 📋 Usage

### Authentication Flow

1. **User Access**: User accesses the bridge service
2. **SAML Authentication**: Redirected to Shibboleth IdP
3. **MFA (Optional)**: Multi-factor authentication via eduMFA
4. **Credential Generation**: Temporary LDAP credentials created
5. **Application Access**: User can access LDAP-based applications

### Using Temporary Credentials

After authentication, users receive temporary LDAP credentials:

```bash
# Connection details
LDAP Server: ldap://your-server:389
Bind DN: uid=username,ou=people,dc=example,dc=com
Password: [temporary-password]
```

### API Integration

Validate credentials programmatically:

```bash
curl -X POST https://your-domain.com/api/validate \
  -H "Content-Type: application/json" \
  -d '{"username": "user", "password": "temp-password"}'
```

## 🧪 Testing

### Interactive Demo

```bash
python demo_main.py interactive
```

### Automated Testing

```bash
python demo_main.py auto
```

### Web Demo Interface

Visit https://localhost:5000/demo for a web-based testing interface.

## 🔧 Development

### Project Structure

```
saml-ldap-bridge/
├── app.py                 # Main application entry point
├── config.py             # Configuration management
├── token_validator.py    # SAML token validation
├── auth_initiator.py     # Authentication initiation
├── credential_generator.py # Temporary credential management
├── main.py               # Workflow orchestrator
├── web_interface.py      # Web interface
├── demo_ldap.py          # Demo LDAP server/client
├── demo_main.py          # Command-line demo
├── demo_interface.py     # Demo web interface
├── setup.py              # Setup and installation
├── requirements.txt      # Python dependencies
├── Dockerfile            # Docker container
├── docker-compose.yml    # Docker Compose configuration
└── .env.example          # Environment template
```

### Running in Development

```bash
# Install dependencies
pip install -r requirements.txt

# Set development environment
export DEBUG=True
export FLASK_ENV=development

# Run application
python app.py
```

## 🔒 Security Considerations

### Production Deployment

- **SSL/TLS**: Use proper SSL certificates (not self-signed)
- **Secret Keys**: Generate secure secret keys
- **Firewall**: Restrict access to necessary ports only
- **Credential Expiry**: Configure appropriate credential timeout
- **Logging**: Monitor authentication attempts and failures

### SAML Security

- **Signature Validation**: Ensure SAML response signatures are validated
- **Certificate Management**: Keep IdP certificates up to date
- **Attribute Mapping**: Only request necessary user attributes
- **Session Management**: Implement proper session timeout

### LDAP Security

- **Credential Isolation**: Temporary credentials are isolated per user
- **Automatic Cleanup**: Expired credentials are automatically removed
- **Access Control**: Implement proper LDAP access controls
- **Audit Logging**: Log all credential generation and usage

## 🛠️ Integration Examples

### GitLab LDAP Configuration

```ruby
gitlab_rails['ldap_enabled'] = true
gitlab_rails['ldap_servers'] = {
  'main' => {
    'label' => 'SAML-LDAP Bridge',
    'host' =>  'your-bridge-server.com',
    'port' => 389,
    'uid' => 'uid',
    'bind_dn' => 'uid=%{username},ou=people,dc=example,dc=com',
    'base' => 'dc=example,dc=com',
    'user_filter' => '',
  }
}
```

### Python Application Integration

```python
from ldap3 import Server, Connection

def authenticate_user(username, password):
    server = Server('your-bridge-server.com', port=389)
    user_dn = f'uid={username},ou=people,dc=example,dc=com'

    try:
        with Connection(server, user_dn, password, auto_bind=True) as conn:
            # User authenticated successfully
            return True
    except:
        return False
```

## 📊 Monitoring

### Health Checks

- **Application Health**: GET /health
- **System Status**: GET /status
- **Active Credentials**: GET /demo/credentials

### Logging

Logs are written to `saml_ldap_bridge.log` and include:

- Authentication attempts
- Credential generation/expiry
- SAML validation results
- System errors and warnings

## 🆘 Troubleshooting

### Common Issues

**SAML Validation Fails**

- Check IdP certificate configuration
- Verify SP metadata is registered with IdP
- Check clock synchronization between systems

**Credential Generation Fails**

- Verify LDAP base DN configuration
- Check credential expiry settings
- Review user attribute mapping

**Connection Timeouts**

- Check firewall settings
- Verify network connectivity
- Review SSL/TLS configuration

### Debug Mode

Enable debug logging:

```bash
export DEBUG=True
export FLASK_ENV=development
python app.py
```

## 📝 License

This project is licensed under the MIT License. See LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## 📞 Support

For support and questions:

- Check the troubleshooting section
- Review the demo interface for testing
- Open an issue on GitHub
- Check system logs for error details

## 🔄 Version History

- **v1.0.0**: Initial release with core SAML-LDAP bridge functionality
  - SAML token validation
  - Temporary credential generation
  - Web interface
  - Demo and testing tools
  - Docker support
