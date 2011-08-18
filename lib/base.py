"""The base Controller API

Provides the BaseController class for subclassing, and other objects
utilized by Controllers.
"""
import os
from pylons import tmpl_context as c
from pylons import app_globals as g
from pylons import cache, config, request, response, session, url
from pylons.controllers import WSGIController
from pylons.controllers.util import abort, etag_cache, redirect
from pylons.decorators import jsonify, validate
from pylons.i18n import _, ungettext, N_, set_lang, add_fallback
from pylons.i18n.translation import LanguageError

import www.lib.helpers as h
import www.model as model

def is_valid_string(mystr):
    lower = xrange(0, 32)
    upper = xrange(128, 256)
    for s in mystr:
        if ord(s) in lower:
            return False
        if ord(s) in upper:
            return False
    return True

class BaseController(WSGIController):

    def __init__(self):

        lang = request.params.get('lang')
        if lang:
            if is_valid_string(lang):
                try:
                    set_lang(os.path.basename(lang))
                except LanguageError:
                    pass
        else:
            for lang in request.languages:
                if is_valid_string(lang):
                    try:
                        set_lang(lang)
                    except LanguageError:
                        continue
        try:
            add_fallback('en')
        except LanguageError:
            pass

        self.PREFIXES = {
            'mime': "m:",
            'group': "g:",
            'category': "c:",
            'license': "l:",
            'useflag': "u:",
            'library': "so:",
            'provided_library': "sop:",
        }

    def _generate_html_metadata(self):
        c.generic_icon_url_64 = "/images/packages/generic-64x64.png"
        c.generic_icon_url_48 = "/images/packages/generic-48x48.png"
        c.generic_icon_url_22 = "/images/packages/generic-22x22.png"
        c.group_icon_url_64 = "/images/packages/groups/64x64"
        c.group_icon_url_48 = "/images/packages/groups/48x48"
        c.meta_list_url = "/images/packages/metalist"
        c.base_package_show_url = model.config.PACKAGE_SHOW_URL
        c.base_search_url = model.config.PACKAGE_SEARCH_URL
        c.base_group_url = model.config.GROUP_SHOW_URL
        c.base_catetory_url = model.config.CATEGORY_SHOW_URL
        c.base_switch_arch_url = model.config.PACKAGE_SWITCH_ARCH_URL
        c.base_switch_view_url = model.config.PACKAGE_SWITCH_VIEW_URL
        c.base_switch_updates_url = model.config.PACKAGE_SWITCH_UPDATES_URL
        c.base_switch_updates_type_url = model.config.PACKAGE_SWITCH_UPDATES_TYPE_URL
        c.base_switch_sortby_url = model.config.PACKAGE_SWITCH_SORTBY_URL
        c.base_install_app_mirror_url = model.config.PACKAGE_INSTALL_GET_ETP
        c.default_sorting = model.config.default_sorting
        c.search_prefixes = self.PREFIXES
        c.search_form_max_length = model.config.SEARCH_FORM_MAX_LENGTH
        c.available_arches_selector = model.config.available_arches.copy()
        c.available_arches_selector['all'] = _("All")
        c.available_sortby_selector = model.config.available_sortings.copy()
        try:
            user_agent = request.environ['HTTP_USER_AGENT']
        except (AttributeError, KeyError):
            user_agent = None
        c.user_agent = user_agent
        model.config.setup_internal(model, c, session, request)

    def _generate_login_metadata(self):
        model.config.setup_permission_data(model, c, session)

    def __call__(self, environ, start_response):
        """Invoke the Controller"""
        # WSGIController.__call__ dispatches to the Controller method
        # the request is routed to. This routing information is
        # available in environ['pylons.routes_dict']
        return WSGIController.__call__(self, environ, start_response)

# Include the '_' function in the public names
__all__ = [__name for __name in locals().keys() if not __name.startswith('_') \
           or __name == '_']
