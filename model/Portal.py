# -*- coding: utf-8 -*-
import os
import config
from entropy.const import *
etpConst['entropygid'] = config.DEFAULT_WEB_GID
from entropy.services.skel import Authenticator as DistributionAuthInterface
from entropy.services.skel import RemoteDatabase as RemoteDbSkelInterface
from Authenticator import Authenticator
from Forum import Forum
import entropy.exceptions as etp_exceptions
try:
    from entropy.services.exceptions import ServiceConnectionError
except ImportError:
    ServiceConnectionError = Exception
import entropy.tools as entropy_tools

class Portal(DistributionAuthInterface, RemoteDbSkelInterface):

    SQL_TABLES = {
        'registration_validation': """
            CREATE TABLE registration_validation (
                registration_validation_id INT NOT NULL AUTO_INCREMENT,
                user_id INT NOT NULL,
                confirmation_code VARCHAR(64),
                PRIMARY KEY (registration_validation_id)
            ) CHARACTER SET utf8 COLLATE utf8_bin;
        """,
        'email_update_validation': """
            CREATE TABLE email_update_validation (
                email_update_validation_id INT NOT NULL AUTO_INCREMENT,
                user_id INT NOT NULL,
                confirmation_code VARCHAR(64),
                email VARCHAR(200),
                PRIMARY KEY (email_update_validation_id)
            ) CHARACTER SET utf8 COLLATE utf8_bin;
        """,
        'password_update_validation': """
            CREATE TABLE password_update_validation (
                password_update_validation_id INT NOT NULL AUTO_INCREMENT,
                user_id INT NOT NULL,
                confirmation_code VARCHAR(64),
                password_hash VARCHAR(40),
                PRIMARY KEY (password_update_validation_id)
            ) CHARACTER SET utf8 COLLATE utf8_bin;
        """,
    }

    def __init__(self, do_init = False):
        import entropy.tools as entropyTools
        self.authenticator = Authenticator
        DistributionAuthInterface.__init__(self)
        RemoteDbSkelInterface.__init__(self)
        self.set_connection_data(config.portal_connection_data)
        self.connect()
        if do_init:
            self.initialize_tables()
        self.dbconn.set_character_set('utf8')

    def __del__(self):
        if hasattr(self,'disconnect'):
            try:
                self.disconnect()
            except ServiceConnectionError:
                pass

    def check_connection(self):
        pass

    def initialize_tables(self):
        notable = False
        for table in self.SQL_TABLES:
            if self.table_exists(table):
                continue
            notable = True
            self.execute_script(self.SQL_TABLES[table])
        if notable:
            self.commit()

    def _get_unique_id(self):
        import md5
        m = md5.new()
        m2 = md5.new()
        rnd = str(abs(hash(os.urandom(20))))
        rnd2 = str(abs(hash(os.urandom(20))))
        m.update(rnd)
        m2.update(rnd2)
        m.update(rnd2)
        m2.update(rnd)
        x = m.hexdigest() + m2.hexdigest()
        del m, m2
        return x

    def get_user_profile_data(self, user_id):
        auth = self.authenticator()
        self.do_fake_authenticator_login(auth, user_id)
        profile_data = auth.get_user_data()
        for key in profile_data.keys():
            if isinstance(profile_data.get(key), basestring):
                try:
                    profile_data[key] = unicode(profile_data[key],'raw_unicode_escape')
                except UnicodeDecodeError:
                    continue

        profile_data['groups'] = auth.get_user_groups()
        profile_data['group'] = auth.get_user_group()
        auth.disconnect()
        del auth
        return profile_data

    def update_user_id_profile(self, user_id, profile_data):
        auth = self.authenticator()
        self.do_fake_authenticator_login(auth, user_id)
        status, err_msg = auth.update_user_id_profile(profile_data)
        auth.disconnect()
        del auth
        return status, err_msg

    def get_user_birthday(self, user_id):
        auth = self.authenticator()
        self.do_fake_authenticator_login(auth, user_id)
        user_birthday = auth.get_user_birthday()
        auth.disconnect()
        del auth
        return user_birthday

    def create_new_email_update_validation_id(self, user_id, email):

        confirmation_code = self._get_unique_id()
        self.clear_email_update_validation(user_id)
        self.execute_query('INSERT INTO email_update_validation VALUES (%s,%s,%s,%s)',(None,user_id,confirmation_code,email,))
        email_update_validation_id = self.lastrowid()
        self.commit()
        return email_update_validation_id, confirmation_code

    def create_new_password_update_validation_id(self, user_id, password):
        # generate hash
        auth = self.authenticator()
        password_hash = auth._get_password_hash(password.encode('utf-8'))
        auth.disconnect()
        del auth

        confirmation_code = self._get_unique_id()
        self.clear_password_update_validation(user_id)
        self.execute_query('INSERT INTO password_update_validation VALUES (%s,%s,%s,%s)',(None,user_id,confirmation_code,password_hash,))
        password_update_validation_id = self.lastrowid()
        self.commit()
        return password_update_validation_id, confirmation_code

    def create_new_registration_validation_id(self, user_id):

        confirmation_code = self._get_unique_id()
        self.clear_registration_validation(user_id)
        self.execute_query('INSERT INTO registration_validation VALUES (%s,%s,%s)',(None,user_id,confirmation_code,))
        registration_validation_id = self.lastrowid()
        self.commit()
        return registration_validation_id, confirmation_code

    def registration_validation_check(self, registration_validation_id, user_id, confirmation_code):

        self.execute_query('SELECT registration_validation_id FROM registration_validation WHERE `registration_validation_id` = %s AND `user_id` = %s AND `confirmation_code` = %s',(registration_validation_id,user_id,confirmation_code,))
        data = self.fetchone()
        if not data: return False
        if not isinstance(data,dict): return False
        if not data.has_key('registration_validation_id'): return False
        return True

    def email_update_validation_check(self, email_update_validation_id, user_id, confirmation_code):

        self.execute_query('SELECT email FROM email_update_validation WHERE `email_update_validation_id` = %s AND `user_id` = %s AND `confirmation_code` = %s',(email_update_validation_id,user_id,confirmation_code,))
        data = self.fetchone()
        if not data: return False
        if not isinstance(data,dict): return False
        if not data.has_key('email'): return False
        return data['email']

    def password_update_validation_check(self, password_update_validation_id, user_id, confirmation_code):

        self.execute_query('SELECT password_hash FROM password_update_validation WHERE `password_update_validation_id` = %s AND `user_id` = %s AND `confirmation_code` = %s',(password_update_validation_id,user_id,confirmation_code,))
        data = self.fetchone()
        if not data: return False
        if not isinstance(data,dict): return False
        if not data.has_key('password_hash'): return False
        return data['password_hash']

    def clear_share_validation(self, pinboard_shares_validation_id):
        self.execute_query('DELETE FROM pinboard_shares_validation WHERE `pinboard_shares_validation_id` = %s',(pinboard_shares_validation_id,))

    def clear_registration_validation(self, user_id):
        self.execute_query('DELETE FROM registration_validation WHERE `user_id` = %s',(user_id,))

    def clear_email_update_validation(self, user_id):
        self.execute_query('DELETE FROM email_update_validation WHERE `user_id` = %s',(user_id,))

    def clear_password_update_validation(self, user_id):
        self.execute_query('DELETE FROM password_update_validation WHERE `user_id` = %s',(user_id,))

    def update_user_email(self, user_id, email):
        auth = self.authenticator()
        self.do_fake_authenticator_login(auth, user_id)
        valid = auth.update_email(email)
        auth.disconnect()
        del auth
        return valid

    def get_user_email(self, user_id):
        auth = self.authenticator()
        self.do_fake_authenticator_login(auth, user_id)
        email = auth.get_email()
        auth.disconnect()
        del auth
        return email

    def update_user_password_hash(self, user_id, password_hash):
        auth = self.authenticator()
        self.do_fake_authenticator_login(auth, user_id)
        valid = auth.update_password_hash(password_hash)
        auth.disconnect()
        del auth
        return valid

    def do_fake_authenticator_login(self, authenticator, user_id):
        data = {
            'user_id': user_id,
            'username': '###fake###',
            'password': '###fake###'
        }
        authenticator.set_login_data(data)
        authenticator.logged_in = True

    def check_admin(self, user_id):
        auth = self.authenticator()
        self.do_fake_authenticator_login(auth, user_id)
        valid = auth.is_administrator()
        auth.disconnect()
        del auth
        return valid

    def check_moderator(self, user_id):
        auth = self.authenticator()
        self.do_fake_authenticator_login(auth, user_id)
        valid = auth.is_moderator()
        auth.disconnect()
        del auth
        return valid

    def check_user(self, user_id):
        auth = self.authenticator()
        self.do_fake_authenticator_login(auth, user_id)
        valid = auth.is_user()
        auth.disconnect()
        del auth
        return valid

    def check_user_credentials(self, username, password):

        login_data = {
            'username': username,
            'password': password.encode('utf-8')
        }

        myauth = self.authenticator()
        myauth.set_login_data(login_data)
        try:
            logged = myauth.login()
        except etp_exceptions.PermissionDenied, e:
            logged = False
        myauth.disconnect()
        del myauth
        return logged

    def get_username(self, user_id):

        self.execute_query('SELECT '+config.PHPBB_DBNAME+'.phpbb_users.username as username FROM '+config.PHPBB_DBNAME+'.phpbb_users WHERE '+config.PHPBB_DBNAME+'.phpbb_users.user_id = %s', (user_id,))
        username = 'Anonymous'
        data = self.fetchone()
        if isinstance(data,dict):
            if data.has_key('username'):
                username = data.get('username')
        return username

    def get_user_id(self, username):

        self.execute_query('SELECT '+config.PHPBB_DBNAME+'.phpbb_users.user_id as user_id FROM '+config.PHPBB_DBNAME+'.phpbb_users WHERE '+config.PHPBB_DBNAME+'.phpbb_users.username = %s', (username,))
        data = self.fetchone()
        user_id = 0
        if isinstance(data,dict):
            if data.has_key('user_id'):
                user_id = data.get('user_id')
        return user_id

    def _remove_html_tags(self, data):
        import re
        p = re.compile(r'<.*?>')
        return p.sub('', data)

    def _get_ts(self):
        from datetime import datetime
        import time
        return datetime.fromtimestamp(time.time())

    def search_users(self, search):

        results = []
        forum = Forum()

        # email?
        email = self._validate_email(search)
        if email:
            results.extend(forum.search_email(search))
            return results

        try:
            user_id = int(search)
            user_id_rslts = forum.search_user_id(user_id)
            if user_id_rslts:
                results.extend(user_id_rslts)
                return results
        except ValueError:
            pass

        results.extend(forum.search_username(search))

        forum.disconnect()
        del forum
        return results

    def count_users(self):

        forum = Forum()
        users_count = forum.count_users()
        forum.disconnect()
        del forum
        return users_count

    def _validate_email(self, email):
        # ascii test
        try:
            email = str(email)
        except:
            return False
        return entropy_tools.is_valid_email(email)

# initialize portal, will be commented out
#myportal = Portal(do_init = True)
#myportal.commit()
#del myportal
