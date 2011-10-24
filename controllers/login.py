# -*- coding: utf-8 -*-
import logging
from www.lib.base import *
from www.lib.website import *
from pylons.i18n import _
log = logging.getLogger(__name__)

class LoginController(BaseController, WebsiteController):

    def __init__(self):
        BaseController.__init__(self)
        WebsiteController.__init__(self)
        import www.model.Authenticator
        self.Authenticator = www.model.Authenticator.Authenticator
        import www.model.Portal
        self.Portal = www.model.Portal.Portal
        import entropy.exceptions as etp_exceptions
        self.etp_exceptions = etp_exceptions

    def submit(self):

        model.config.setup_internal(model, c, session, request) 
        login_data = {
            'username': request.params.get('username'),
            'password': request.params.get('password')
        }
        if login_data['password']:
            login_data['password'] = login_data['password'].encode('utf-8')

        myauth = self.Authenticator()
        error = None
        try:
            user_id = myauth.login(login_data['username'], login_data['password'])
        except (self.etp_exceptions.PermissionDenied, UnicodeEncodeError,) as e:
            user_id = None
            c.login_error = e
        except AttributeError as e:
            user_id = None
            c.login_error = e

        if user_id is not None:
            myauth._update_session_table(user_id, request.environ['REMOTE_ADDR'])
            session['entropy'] = {}
            session['entropy']['entropy_user'] = login_data['username']
            session['logged_in'] = True
            session['entropy']['password_hash'] = model.config.hash_string(login_data['password'])
            session['entropy']['entropy_user_id'] = user_id
            model.config.setup_login_data(model, c, session)
            session.save()

        myauth.disconnect()
        del myauth
        return redirect(url("/", protocol=model.config.get_http_protocol(request)))

    def logout(self):
        if 'entropy' in session:
            del session['entropy']
        if 'logged_in' in session:
            del session['logged_in']
        session.save()

        model.config.setup_internal(model, c, session, request)
        return redirect(url('/', protocol=model.config.get_http_protocol(request)))

