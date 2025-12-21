class AuthHandler:
    def check_session(self, flask_session):
        if 'user_id' in flask_session and 'ldap_credentials' in flask_session:
            return {
                'logged_in': True,
                'user_info': flask_session.get('user_info', {}),
                'ldap_credentials': flask_session['ldap_credentials']
            }
        return {'logged_in': False}

    def store_ldap_credentials(self, flask_session, credentials):
        flask_session['ldap_credentials'] = credentials
