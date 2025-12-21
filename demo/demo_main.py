"""
Demo Application Main Module
Demonstrates LDAP connection using temporary credentials
"""
import logging
import sys
import time
from demo_ldap import get_demo_client, get_demo_server
from main import get_orchestrator
from config import Config

logger = logging.getLogger(__name__)

class DemoApplication:
    def __init__(self):
        self.demo_client = get_demo_client()
        self.demo_server = get_demo_server()
        self.orchestrator = get_orchestrator()
    
    def run_interactive_demo(self):
        """Run interactive demo session"""
        print("=" * 60)
        print("SAML-LDAP Bridge - Interactive Demo")
        print("=" * 60)
        print()
        
        print("This demo will test LDAP connectivity using temporary credentials")
        print("generated from SAML authentication.")
        print()
        
        # Get credentials from user
        username = input("Enter username: ").strip()
        password = input("Enter password: ").strip()
        
        if not username or not password:
            print("Username and password are required!")
            return
        
        print("\nTesting credentials...")
        
        # Test the connection
        result = self.demo_client.test_connection(username, password)
        
        if result.get('success'):
            self._display_success_result(result)
            
            # Offer additional tests
            self._run_additional_tests(username, password)
        else:
            self._display_error_result(result)
    
    def run_automated_demo(self, username=None, password=None):
        """Run automated demo with provided or generated credentials"""
        print("=" * 60)
        print("SAML-LDAP Bridge - Automated Demo")
        print("=" * 60)
        print()
        
        if not username or not password:
            print("No credentials provided. Checking for active temporary credentials...")
            
            # Try to find active credentials
            creds_info = self.orchestrator.credential_generator.list_active_credentials()
            
            if creds_info.get('success') and creds_info.get('credentials'):
                first_cred = creds_info['credentials'][0]
                username = first_cred['username']
                print(f"Found active credentials for user: {username}")
                
                # Get the actual password from the credential store
                for cred_id, cred_data in self.orchestrator.credential_generator.temp_credentials.items():
                    if cred_data['username'] == username:
                        password = cred_data['password']
                        break
                
                if not password:
                    print("Could not retrieve password for active credentials")
                    return
            else:
                print("No active credentials found. Please authenticate first via web interface.")
                return
        
        print(f"Testing connection for user: {username}")
        
        # Run comprehensive test
        self._run_comprehensive_test(username, password)
    
    def _display_success_result(self, result):
        """Display successful test result"""
        print("\n" + "=" * 40)
        print("✅ CONNECTION TEST SUCCESSFUL")
        print("=" * 40)
        
        user_info = result.get('user_info', {})
        print(f"User: {user_info.get('username', 'Unknown')}")
        print(f"Display Name: {user_info.get('display_name', 'N/A')}")
        print(f"Email: {user_info.get('email', 'N/A')}")
        print(f"DN: {result.get('user_dn', 'N/A')}")
        
        # Show LDAP connection details
        ldap_conn = result.get('ldap_connection', {})
        if ldap_conn.get('success'):
            print("\n🔗 LDAP Connection Details:")
            print(f"  Server Info: {ldap_conn.get('server_info', 'N/A')[:100]}...")
            print(f"  Bind Successful: {ldap_conn.get('bind_successful', False)}")
            print(f"  Search Successful: {ldap_conn.get('search_successful', False)}")
        else:
            print(f"\n⚠️  LDAP Server Connection: {ldap_conn.get('error', 'Failed')}")
            if ldap_conn.get('note'):
                print(f"  Note: {ldap_conn.get('note')}")
        
        # Show attributes
        attributes = result.get('attributes', {})
        if attributes:
            print(f"\n📋 User Attributes ({len(attributes)} total):")
            for key, value in list(attributes.items())[:5]:
                if isinstance(value, list):
                    value = ', '.join(str(v) for v in value[:2])
                print(f"  {key}: {str(value)[:50]}{'...' if len(str(value)) > 50 else ''}")
            if len(attributes) > 5:
                print(f"  ... and {len(attributes) - 5} more attributes")
    
    def _display_error_result(self, result):
        """Display error result"""
        print("\n" + "=" * 40)
        print("❌ CONNECTION TEST FAILED")
        print("=" * 40)
        
        print(f"Error: {result.get('error', 'Unknown error')}")
        if result.get('details'):
            print(f"Details: {result.get('details')}")
        
        print("\nTroubleshooting:")
        print("1. Ensure you have authenticated via the web interface first")
        print("2. Check that your credentials haven't expired")
        print("3. Verify LDAP server configuration")
    
    def _run_additional_tests(self, username, password):
        """Run additional LDAP tests"""
        print("\n" + "=" * 40)
        print("Additional Tests Available")
        print("=" * 40)
        
        while True:
            print("\nOptions:")
            print("1. Search LDAP directory")
            print("2. Show connection examples")
            print("3. Test with different parameters")
            print("4. Exit")
            
            choice = input("\nSelect option (1-4): ").strip()
            
            if choice == '1':
                self._test_ldap_search(username, password)
            elif choice == '2':
                self._show_connection_examples(username)
            elif choice == '3':
                self._test_custom_parameters(username, password)
            elif choice == '4':
                break
            else:
                print("Invalid option. Please choose 1-4.")
    
    def _test_ldap_search(self, username, password):
        """Test LDAP directory search"""
        print("\n🔍 Testing LDAP Search...")
        
        result = self.demo_client.search_user(username, password)
        
        if result.get('success'):
            print(f"✅ Search successful: {result.get('entries_found', 0)} entries found")
            
            if result.get('simulated'):
                print("⚠️  This is a simulated result (no real LDAP server)")
            
            for entry in result.get('entries', [])[:3]:  # Show first 3 entries
                print(f"\nEntry DN: {entry.get('dn')}")
                attrs = entry.get('attributes', {})
                for key, value in list(attrs.items())[:3]:
                    print(f"  {key}: {str(value)[:50]}...")
        else:
            print(f"❌ Search failed: {result.get('error')}")
    
    def _show_connection_examples(self, username):
        """Show connection examples for various tools"""
        print("\n📖 Connection Examples")
        print("=" * 40)
        
        result = self.demo_client.get_connection_examples(username)
        
        if result.get('success'):
            examples = result.get('examples', {})
            
            print("\n1. Command Line (ldapsearch):")
            print(f"   {examples.get('ldapsearch', 'N/A')}")
            
            print("\n2. Python ldap3 library:")
            print("   " + examples.get('python_ldap3', 'N/A').replace('\n', '\n   '))
            
            print("\n3. REST API validation:")
            print(f"   {examples.get('curl_rest', 'N/A')}")
            
            print("\n4. GitLab LDAP configuration:")
            print("   " + examples.get('gitlab_ldap_config', 'N/A').replace('\n', '\n   '))
        else:
            print(f"❌ Failed to generate examples: {result.get('error')}")
    
    def _test_custom_parameters(self, username, password):
        """Test with custom LDAP parameters"""
        print("\n⚙️  Custom LDAP Test")
        print("=" * 20)
        
        host = input(f"LDAP Host [{Config.LDAP_HOST}]: ").strip() or Config.LDAP_HOST
        port = input(f"LDAP Port [{Config.LDAP_PORT}]: ").strip()
        port = int(port) if port.isdigit() else Config.LDAP_PORT
        
        print(f"\nTesting connection to {host}:{port}...")
        
        result = self.demo_client.test_connection(username, password, host, port)
        
        if result.get('success'):
            self._display_success_result(result)
        else:
            self._display_error_result(result)
    
    def _run_comprehensive_test(self, username, password):
        """Run comprehensive automated test"""
        tests = [
            ("Basic Connection Test", lambda: self.demo_client.test_connection(username, password)),
            ("LDAP Search Test", lambda: self.demo_client.search_user(username, password)),
            ("Connection Examples", lambda: self.demo_client.get_connection_examples(username))
        ]
        
        results = []
        
        for test_name, test_func in tests:
            print(f"\n🧪 Running: {test_name}")
            print("-" * 30)
            
            try:
                result = test_func()
                results.append((test_name, result))
                
                if result.get('success'):
                    print(f"✅ {test_name}: PASSED")
                    
                    # Show brief summary
                    if 'user_info' in result:
                        user = result['user_info'].get('username', 'Unknown')
                        print(f"   User: {user}")
                    
                    if 'entries_found' in result:
                        print(f"   Entries found: {result['entries_found']}")
                    
                    if 'examples' in result:
                        print(f"   Examples generated: {len(result['examples'])}")
                        
                else:
                    print(f"❌ {test_name}: FAILED - {result.get('error', 'Unknown error')}")
                    
            except Exception as e:
                print(f"❌ {test_name}: ERROR - {str(e)}")
                results.append((test_name, {'success': False, 'error': str(e)}))
        
        # Summary
        print("\n" + "=" * 50)
        print("TEST SUMMARY")
        print("=" * 50)
        
        passed = sum(1 for _, result in results if result.get('success'))
        total = len(results)
        
        print(f"Tests Passed: {passed}/{total}")
        
        if passed == total:
            print("🎉 All tests passed! The SAML-LDAP bridge is working correctly.")
        else:
            print("⚠️  Some tests failed. Check the configuration and try again.")
        
        return results
    
    def show_status(self):
        """Show current system status"""
        print("\n📊 System Status")
        print("=" * 20)
        
        status = self.orchestrator.get_system_status()
        
        if status.get('success'):
            print(f"Status: {status.get('status', 'Unknown')}")
            print(f"Active Credentials: {status.get('active_credentials', 0)}")
            
            config = status.get('configuration', {})
            print(f"SAML IdP: {config.get('saml_idp_entity_id', 'Not configured')}")
            print(f"eduMFA: {'Enabled' if config.get('edumfa_configured') else 'Disabled'}")
            print(f"LDAP: {config.get('ldap_host', 'Unknown')}:{config.get('ldap_port', 'Unknown')}")
        else:
            print(f"❌ Failed to get status: {status.get('error')}")


def main():
    """Main entry point"""
    demo = DemoApplication()
    
    if len(sys.argv) > 1:
        if sys.argv[1] == 'status':
            demo.show_status()
        elif sys.argv[1] == 'auto':
            demo.run_automated_demo()
        elif sys.argv[1] == 'interactive':
            demo.run_interactive_demo()
        else:
            print("Usage: python demo_main.py [status|auto|interactive]")
    else:
        # Default to interactive mode
        demo.run_interactive_demo()


if __name__ == '__main__':
    main()