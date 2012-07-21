# -*- coding: utf-8 -*-
from pylons import tmpl_context as c
from pylons import app_globals as g
from pylons import cache, config, request, response, session, url
from pylons.controllers import WSGIController
from pylons.controllers.util import abort, etag_cache, redirect
from pylons.decorators import jsonify, validate
from pylons.i18n import _, ungettext, N_

from paste.request import construct_url

import re
import os
import time

# Imaging
import Image

import www.lib.helpers as h
import www.model as model
import www.model.Portal as Portal
import www.model.Authenticator as Authenticator

from htmlentitydefs import name2codepoint
from entropy.const import etpConst
etpConst['entropygid'] = model.config.DEFAULT_WEB_GID
etpConst['repositoriesconf'] = model.config.REPOSITORIES_CONF_PATH
etpConst['dumpstoragedir'] = model.config.WEBSITE_REPO_CACHE_DIR

from entropy.client.services.interfaces import Document

import entropy.tools

class WebsiteController:

    def __init__(self):

        # backward compatibility
        c.ugc_doctypes = {
            'comments': Document.COMMENT_TYPE_ID,
            'image': Document.IMAGE_TYPE_ID,
            'generic_file': Document.FILE_TYPE_ID,
            'youtube_video': Document.VIDEO_TYPE_ID,
            'icon': Document.ICON_TYPE_ID,
        }
        c.default_ugc_doctype = Document.COMMENT_TYPE_ID
        c.ugc_doctypes_desc_singular = Document.DESCRIPTION_SINGULAR.copy()
        c.ugc_doctypes_desc_plural = Document.DESCRIPTION_PLURAL.copy()
        self.small_img_dirname = 'small'
        self.VIRUS_CHECK_EXEC = model.config.VIRUS_CHECK_EXEC
        self.VIRUS_CHECK_ARGS = model.config.VIRUS_CHECK_ARGS
        self.Portal = Portal.Portal
        self.Authenticator = Authenticator.Authenticator

    def _resize_icon(self, image_path):
        """
        Resize file at image_path (validate file type) if it's larger than
        128x128 pixels.
        """
        if not entropy.tools.is_supported_image_file(image_path):
            raise AttributeError("Unsupported Image Type")

        pix_size = 128
        size = pix_size, pix_size
        try:
            im = Image.open(image_path)
            w, h = im.size
            if w > pix_size or h > pix_size:
                im.thumbnail(size)
                im.save(image_path, "PNG")
        except IOError as err:
            raise AttributeError("Unsupported Icon Type")

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

    def _get_ip_address(self, request):
        ip_addr = request.environ.get('REMOTE_ADDR')
        if ip_addr == "127.0.0.1":
            # not useful
            ip_proxy_addr = request.environ.get('HTTP_X_FORWARDED_FOR')
            if ip_proxy_addr:
                return ip_proxy_addr
        return ip_addr

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

    def _is_valid_email(self, email):
        """
        Return whether passed string is contains a valid email address.

        @param email: string to test
        @type email: string
        @return: True if string is a valid email
        @rtype: bool
        """
        monster = "(?:[a-z0-9!#$%&'*+/=?^_{|}~-]+(?:.[a-z0-9!#$%" + \
            "&'*+/=?^_{|}~-]+)*|\"(?:" + \
            "[\x01-\x08\x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]" + \
            "|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*\")@(?:(?:[a-z0-9]" + \
            "(?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?" + \
            "|\[(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.)" + \
            "{3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?" + \
            "|[a-z0-9-]*[a-z0-9]:(?:" + \
            "[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]"  + \
            "|\\[\x01-\x09\x0b\x0c\x0e-\x7f])+)\])"
        evil = re.compile(monster)
        if evil.match(email):
            return True
        return False
