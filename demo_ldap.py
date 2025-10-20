"""
Demo LDAP Server
Simple LDAP server for testing the bridge functionality
"""
import logging
import threading
import socket
import time
from ldap3 import Server, Connection, ALL, SUBTREE, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPException
from main import get_orchestrator
from config import Config

logger = logging.getLogger(__name__)

class DemoLDAPServer:
    def __init__(self, host='localhost', port=3389):
        self.host = host
        self.port = port
        self.running = False
        self.server_thread = None
        self.orchestrator = get_orchestrator()
        
    def start(self):
        """Start the demo LDAP server"""
        try:
            self.running = True
            self.server_thread = threading.Thread(target=self._run_server, daemon=True)
            self.server_thread.start()
            logger.info(f"Demo LDAP server started on {self.host}:{self.port}")
            return True
        except Exception as e:
            logger.error(f"Failed to start demo LDAP server: {str(e)}")
            return False
    
    def stop(self):
        """Stop the demo LDAP server"""
        self.running = False
        if self.server_thread:
            self.server_thread.join(timeout=5)
        logger.info("Demo LDAP server stopped")
    
    def _run_server(self):
        """Run the LDAP server (simplified implementation)"""
        # This is a simplified LDAP server implementation
        # In a real scenario, you would use a full LDAP server library
        # For demo purposes, we'll create a simple socket server
        
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        
        try:
            server_socket.bind((self.host, self.port))
            server_socket.listen(5)
            server_socket.settimeout(1.0)  # Allow periodic checks
            
            logger.info(f"Demo LDAP server listening on {self.host}:{self.port}")
            
            while self.running:
                try:
                    client_socket, address = server_socket.accept()
                    # Handle client connection in a separate thread
                    client_thread = threading.Thread(
                        target=self._handle_client,
                        args=(client_socket, address),
                        daemon=True
                    )
                    client_thread.start()
                except socket.timeout:
                    continue  # Check if we should continue running
                except Exception as e:
                    if self.running:
                        logger.error(f"Error accepting connection: {str(e)}")
                        
        except Exception as e:
            logger.error(f"Demo LDAP server error: {str(e)}")
        finally:
            server_socket.close()
    
    def _handle_client(self, client_socket, address):
        """Handle LDAP client connection (simplified)"""
        logger.info(f"LDAP client connected from {address}")
        
        try:
            # This is a very simplified LDAP protocol handler
            # In practice, you would need to implement the full LDAP protocol
            
            # Read client request
            data = client_socket.recv(1024)
            if data:
                logger.info(f"Received LDAP request from {address}: {len(data)} bytes")
                
                # Send a simple response (this is not real LDAP protocol)
                response = b"Demo LDAP Server Response"
                client_socket.send(response)
                
        except Exception as e:
            logger.error(f"Error handling LDAP client {address}: {str(e)}")
        finally:
            client_socket.close()
            logger.info(f"LDAP client {address} disconnected")


class DemoLDAPClient:
    """Demo LDAP client for testing connections"""
    
    def __init__(self):
        self.orchestrator = get_orchestrator()
    
    def test_connection(self, username, password, ldap_host=None, ldap_port=None):
        """
        Test LDAP connection with temporary credentials
        
        Args:
            username: Username for LDAP bind
            password: Password for LDAP bind
            ldap_host: LDAP server host (optional)
            ldap_port: LDAP server port (optional)
            
        Returns:
            dict: Connection test result
        """
        try:
            # Validate credentials through our orchestrator first
            validation_result = self.orchestrator.validate_ldap_credentials(username, password)
            
            if not validation_result.get('success') or not validation_result.get('valid'):
                return {
                    'success': False,
                    'error': 'Invalid credentials',
                    'details': validation_result.get('error', 'Credential validation failed')
                }
            
            # Get user info and attributes
            user_info = validation_result.get('user_info', {})
            user_dn = validation_result.get('user_dn', '')
            attributes = validation_result.get('attributes', {})
            
            # Test actual LDAP connection (if real LDAP server is available)
            ldap_host = ldap_host or Config.LDAP_HOST
            ldap_port = ldap_port or Config.LDAP_PORT
            
            connection_result = self._test_ldap_connection(
                ldap_host, ldap_port, user_dn, password, attributes
            )
            
            return {
                'success': True,
                'credentials_valid': True,
                'user_info': user_info,
                'user_dn': user_dn,
                'attributes': attributes,
                'ldap_connection': connection_result,
                'message': f'Authentication successful for user: {username}'
            }
            
        except Exception as e:
            logger.error(f"LDAP connection test error: {str(e)}")
            return {
                'success': False,
                'error': 'Connection test failed',
                'details': str(e)
            }
    
    def _test_ldap_connection(self, host, port, bind_dn, password, expected_attributes):
        """
        Test connection to actual LDAP server
        
        Args:
            host: LDAP server host
            port: LDAP server port
            bind_dn: DN for binding
            password: Password for binding
            expected_attributes: Expected user attributes
            
        Returns:
            dict: Connection test result
        """
        try:
            # Create server connection
            server = Server(host, port=port, get_info=ALL)
            
            # Try to bind with provided credentials
            with Connection(server, bind_dn, password, auto_bind=True) as conn:
                logger.info(f"Successfully connected to LDAP server {host}:{port}")
                
                # Try to search for user entry
                search_result = conn.search(
                    bind_dn, 
                    '(objectclass=*)', 
                    SUBTREE, 
                    attributes=['*']
                )
                
                if search_result and conn.entries:
                    entry = conn.entries[0]
                    actual_attributes = dict(entry)
                    
                    return {
                        'success': True,
                        'server_info': str(server.info) if server.info else 'No server info',
                        'bind_successful': True,
                        'search_successful': True,
                        'entry_dn': str(entry.entry_dn),
                        'attributes_found': len(actual_attributes),
                        'sample_attributes': {
                            k: str(v) for k, v in list(actual_attributes.items())[:5]
                        }
                    }
                else:
                    return {
                        'success': True,
                        'server_info': str(server.info) if server.info else 'No server info',
                        'bind_successful': True,
                        'search_successful': False,
                        'message': 'Bind successful but no entries found'
                    }
                    
        except LDAPException as e:
            logger.warning(f"LDAP connection failed (expected for demo): {str(e)}")
            return {
                'success': False,
                'error': 'LDAP server connection failed',
                'details': str(e),
                'note': 'This is expected if no real LDAP server is running'
            }
        except Exception as e:
            logger.error(f"Unexpected error testing LDAP connection: {str(e)}")
            return {
                'success': False,
                'error': 'Connection test failed',
                'details': str(e)
            }
    
    def search_user(self, username, password, search_base=None, search_filter=None):
        """
        Search for user in LDAP directory
        
        Args:
            username: Username for binding
            password: Password for binding
            search_base: Base DN for search (optional)
            search_filter: LDAP search filter (optional)
            
        Returns:
            dict: Search result
        """
        try:
            # First validate credentials
            validation_result = self.orchestrator.validate_ldap_credentials(username, password)
            
            if not validation_result.get('success') or not validation_result.get('valid'):
                return {
                    'success': False,
                    'error': 'Invalid credentials for search'
                }
            
            user_dn = validation_result.get('user_dn', '')
            search_base = search_base or Config.LDAP_BASE_DN
            search_filter = search_filter or f'(uid={username})'
            
            # Attempt search (will likely fail without real LDAP server)
            try:
                server = Server(Config.LDAP_HOST, port=Config.LDAP_PORT)
                with Connection(server, user_dn, password, auto_bind=True) as conn:
                    search_result = conn.search(
                        search_base,
                        search_filter,
                        SUBTREE,
                        attributes=['*']
                    )
                    
                    entries = []
                    for entry in conn.entries:
                        entries.append({
                            'dn': str(entry.entry_dn),
                            'attributes': dict(entry)
                        })
                    
                    return {
                        'success': True,
                        'entries_found': len(entries),
                        'entries': entries,
                        'search_base': search_base,
                        'search_filter': search_filter
                    }
                    
            except Exception as ldap_e:
                # Return simulated search result based on our temporary credentials
                user_info = validation_result.get('user_info', {})
                attributes = validation_result.get('attributes', {})
                
                return {
                    'success': True,
                    'simulated': True,
                    'entries_found': 1,
                    'entries': [{
                        'dn': user_dn,
                        'attributes': attributes
                    }],
                    'note': 'Simulated result - no real LDAP server available',
                    'ldap_error': str(ldap_e)
                }
                
        except Exception as e:
            logger.error(f"LDAP search error: {str(e)}")
            return {
                'success': False,
                'error': 'Search failed',
                'details': str(e)
            }
    
    def get_connection_examples(self, username):
        """
        Get example connection strings for various LDAP clients
        
        Args:
            username: Username for examples
            
        Returns:
            dict: Connection examples
        """
        try:
            # Get user info from temporary credentials
            current_creds = None
            cred_gen = self.orchestrator.credential_generator
            
            for cred_id, cred_data in cred_gen.temp_credentials.items():
                if cred_data['username'] == username:
                    current_time = time.time()
                    if cred_data['expires_at'] > current_time:
                        current_creds = cred_data
                        break
            
            if not current_creds:
                return {
                    'success': False,
                    'error': 'No valid credentials found for user'
                }
            
            user_dn = current_creds['user_dn']
            password = current_creds['password']
            
            examples = {
                'ldapsearch': f'ldapsearch -H ldap://{Config.LDAP_HOST}:{Config.LDAP_PORT} -D "{user_dn}" -W -b "{Config.LDAP_BASE_DN}"',
                'ldapwhoami': f'ldapwhoami -H ldap://{Config.LDAP_HOST}:{Config.LDAP_PORT} -D "{user_dn}" -W',
                'python_ldap3': f'''from ldap3 import Server, Connection
server = Server('{Config.LDAP_HOST}', port={Config.LDAP_PORT})
conn = Connection(server, '{user_dn}', '{password}')
conn.bind()''',
                'curl_rest': f'curl -X POST http://localhost:5000/api/validate -H "Content-Type: application/json" -d \'{{"username": "{username}", "password": "{password}"}}\'',
                'gitlab_ldap_config': f'''gitlab_rails['ldap_enabled'] = true
gitlab_rails['ldap_servers'] = {{
  'main' => {{
    'label' => 'SAML-LDAP Bridge',
    'host' =>  '{Config.LDAP_HOST}',
    'port' => {Config.LDAP_PORT},
    'uid' => 'uid',
    'bind_dn' => '{user_dn}',
    'password' => '{password}',
    'encryption' => 'plain',
    'base' => '{Config.LDAP_BASE_DN}',
    'user_filter' => '',
  }}
}}'''
            }
            
            return {
                'success': True,
                'examples': examples,
                'user_dn': user_dn,
                'base_dn': Config.LDAP_BASE_DN,
                'host': Config.LDAP_HOST,
                'port': Config.LDAP_PORT
            }
            
        except Exception as e:
            logger.error(f"Error generating connection examples: {str(e)}")
            return {
                'success': False,
                'error': 'Failed to generate examples',
                'details': str(e)
            }


# Global instances
demo_server = DemoLDAPServer()
demo_client = DemoLDAPClient()

def get_demo_server():
    """Get the demo LDAP server instance"""
    return demo_server

def get_demo_client():
    """Get the demo LDAP client instance"""
    return demo_client