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

        model.config.setup_all(model, c, session, request)
        login_data = {
            'username': request.params.get('username'),
            'password': request.params.get('password')
        }
        if login_data['password']:
            login_data['password'] = login_data['password'].encode('utf-8')

        myauth = self.Authenticator()
        myauth.set_login_data(login_data)
        error = None
        try:
            logged = myauth.login()
        except (self.etp_exceptions.PermissionDenied, UnicodeEncodeError,), e:
            logged = False
            c.login_error = e

        if logged:
            myauth._update_session_table(myauth.login_data['user_id'], request.environ['REMOTE_ADDR'])
            session['entropy'] = {}
            session['entropy']['entropy_user'] = login_data['username']
            session['logged_in'] = True
            session['entropy']['password_hash'] = model.config.hash_string(login_data['password'])
            session['entropy']['entropy_user_id'] = myauth.login_data['user_id']
            model.config.setup_login_data(model, c, session)
            session.save()

        myauth.disconnect()
        del myauth

        login_redirect = self._get_redirect()
        if logged and login_redirect:
            if model.config.get_http_protocol(request) == "https":
                return redirect(url(login_redirect.replace("http://", "https://")))
            else:
                return redirect(url(login_redirect))
        return redirect(url("/", protocol=model.config.get_http_protocol(request)))

    def logout(self):
        if 'entropy' in session:
            del session['entropy']
        if 'logged_in' in session:
            del session['logged_in']
        session.save()

        model.config.setup_all(model, c, session, request)
        return redirect(url('/', protocol=model.config.get_http_protocol(request)))

