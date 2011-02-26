# -*- coding: utf-8 -*-
from pylons import tmpl_context as c
from pylons import app_globals as g
from pylons import cache, config, request, response, session, url
from pylons.controllers import WSGIController
from pylons.controllers.util import abort, etag_cache, redirect
from pylons.decorators import jsonify, validate
from pylons.i18n import _, ungettext, N_
from pylons.templating import render

from paste.request import construct_url

import os
import time
import www.lib.helpers as h
import www.model as model
from htmlentitydefs import name2codepoint
from entropy.const import *
etpConst['entropygid'] = model.config.DEFAULT_WEB_GID
etpConst['repositoriesconf'] = model.config.REPOSITORIES_CONF_PATH
etpConst['dumpstoragedir'] = model.config.WEBSITE_REPO_CACHE_DIR

class WebsiteController:

    def __init__(self):

        c.ugc_doctypes = etpConst['ugc_doctypes'].copy()
        # disabled
        disabled_types = [c.ugc_doctypes.get('bbcode_doc')]
        del c.ugc_doctypes['bbcode_doc']
        c.default_ugc_doctype = etpConst['ugc_doctypes'].get('comments')
        c.ugc_doctypes_desc_singular = etpConst['ugc_doctypes_description_singular'].copy()
        c.ugc_doctypes_desc_plural = etpConst['ugc_doctypes_description'].copy()
        for mytype in disabled_types:
            del c.ugc_doctypes_desc_singular[mytype]
            del c.ugc_doctypes_desc_plural[mytype]
        self.small_img_dirname = 'small'
        self.VIRUS_CHECK_EXEC = model.config.VIRUS_CHECK_EXEC
        self.VIRUS_CHECK_ARGS = model.config.VIRUS_CHECK_ARGS
        import www.model.Portal
        self.Portal = www.model.Portal.Portal

    def _get_logged_user_id(self):
        if session.get('logged_in') and session.get('entropy'):
            try:
                return int(session['entropy'].get('entropy_user_id'))
            except (ValueError,TypeError,):
                pass

    def _get_logged_username(self):
        if session.get('logged_in') and session.get('entropy'):
            try:
                return session['entropy'].get('entropy_user')
            except (TypeError,ValueError,):
                pass

    def _set_user_perms(self, user_id, portal):
        c.my_role = _("User")
        c.is_admin = False
        c.is_moderator = False
        if portal.check_admin(user_id):
            c.is_admin = True
            c.my_role = _("Administrator")
        elif portal.check_moderator(user_id):
            c.is_moderator = True
            c.my_role = _("Moderator")

    def _htmldecode(self, text):
        import re
        charrefpat = re.compile(r'&(#(\d+|x[\da-fA-F]+)|[\w.:-]+);?')
        """Decode HTML entities in the given text."""
        if type(text) is unicode:
            uchr = unichr
        else:
            uchr = lambda value: value > 127 and unichr(value) or chr(value)
        def entitydecode(match, uchr=uchr):
            entity = match.group(1)
            if entity.startswith('#x'):
                return uchr(int(entity[2:], 16))
            elif entity.startswith('#'):
                return uchr(int(entity[1:]))
            elif entity in name2codepoint:
                return uchr(name2codepoint[entity])
            else:
                return match.group(0)
        return charrefpat.sub(entitydecode, text)

    def _htmlencode(self, text):
        return model.config.htmlencode(text)
