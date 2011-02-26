# -*- coding: utf-8 -*-
import os
import config
from entropy.const import *
etpConst['entropygid'] = config.DEFAULT_WEB_GID
from entropy.services.skel import RemoteDatabase as RemoteDbSkelInterface
from entropy.services.skel import Authenticator as DistributionAuthInterface
from Authenticator import Authenticator
try:
    from entropy.services.exceptions import ServiceConnectionError
except ImportError:
    ServiceConnectionError = Exception

class Portal(DistributionAuthInterface, RemoteDbSkelInterface):

    def __init__(self):
        self.authenticator = Authenticator
	RemoteDbSkelInterface.__init__(self)
        DistributionAuthInterface.__init__(self)
        self.set_connection_data(config.portal_connection_data)
        self.connect()
        self.dbconn.set_character_set('utf8')

    def __del__(self):
        if hasattr(self,'disconnect'):
            try:
                self.disconnect()
            except ServiceConnectionError:
                pass

    def check_connection(self):
        pass

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
