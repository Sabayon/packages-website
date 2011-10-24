# -*- coding: utf-8 -*-
import os
import config
from entropy.const import *
etpConst['entropygid'] = config.DEFAULT_WEB_GID
from www.lib.phpbb import Authenticator as DistributionAuthInterface
from Authenticator import Authenticator
try:
    from entropy.services.exceptions import ServiceConnectionError
except ImportError:
    ServiceConnectionError = Exception

class Portal(DistributionAuthInterface):

    def __init__(self):
        self.authenticator = Authenticator
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

    def check_admin(self, user_id):
        auth = self.authenticator()
        valid = auth.is_administrator(user_id)
        auth.disconnect()
        del auth
        return valid

    def check_moderator(self, user_id):
        auth = self.authenticator()
        valid = auth.is_moderator(user_id)
        auth.disconnect()
        del auth
        return valid

    def check_user(self, user_id):
        auth = self.authenticator()
        valid = auth.is_user(user_id)
        auth.disconnect()
        del auth
        return valid
