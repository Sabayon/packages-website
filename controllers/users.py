# -*- coding: utf-8 -*-
import logging
from www.lib.base import *
from www.lib.website import *
from pylons.i18n import _
log = logging.getLogger(__name__)

class UsersController(BaseController,WebsiteController):

    def __init__(self):
        BaseController.__init__(self)
        WebsiteController.__init__(self)
        import www.model.Portal
        self.Portal = www.model.Portal.Portal

    def index(self):
        return redirect(url('/'))

    def users_profile(self, user = None):
        if not user: return self.index()

        portal = self.Portal()
        user_id = portal.get_user_id(user)
        if not user_id:
            portal.disconnect()
            del portal
            return self.index()

        model.config.setup_internal(model, c, session, request)
        import www.model.UGC
        ugc = www.model.UGC.UGC()

        c.username = user
        c.user_id = user_id
        c.profile_data = portal.get_user_profile_data(user_id)
        c.user_age = _("N/A")
        bd = c.profile_data.get('user_birthday')
        if len(bd) == 10:
            try:
                from datetime import datetime
                bd_o = datetime(int(bd[6:]),int(bd[3:5]),int(bd[:2]))
                now = datetime.now()
                td = now - bd_o
                c.user_age = "%s" % (td.days/365,)
            except:
                pass
        c.ugc_stats = ugc.get_user_stats(user_id)
        if not c.ugc_stats:
            c.ugc_stats = {}
        self._set_user_perms(user_id, portal)
        portal.disconnect()
        ugc.disconnect()
        del portal, ugc
        c.page_title = '%s: %s' % (_("Public Profile"),
            c.profile_data.get('username_clean'),)
        return render_mako('/community/users/public_profile.html')
