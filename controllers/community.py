# -*- coding: utf-8 -*-
import logging
from www.lib.base import *
from www.lib.website import *
from pylons.i18n import _
log = logging.getLogger(__name__)

class CommunityController(BaseController,WebsiteController):

    profile_items = {
        'user_icq': {
            'title': _("ICQ UIN"),
            'subtitle': _("Very much '96..."),
            'type': "input",
            'maxlength': 15,
            'size': 45,
        },
        'user_yim': {
            'title': _("Yahoo IM"),
            'subtitle': _("Yaho0o0o0o0 !"),
            'type': "input",
            'maxlength': 255,
            'size': 45,
        },
        'user_msnm': {
            'title': _("MSN Messenger"),
            'subtitle': _("Microsoft see, we're friend"),
            'type': "input",
            'maxlength': 255,
            'size': 45,
        },
        'user_jabber': {
            'title': _("Jabber ID"),
            'subtitle': _("The Jabber.org Open Source Protocol"),
            'type': "input",
            'maxlength': 255,
            'size': 45,
        },
        'user_website': {
            'title': _("Website"),
            'subtitle': _("Do you have a website?"),
            'type': "input",
            'maxlength': 200,
            'size': 45,
        },
        'user_from': {
            'title': _("Location"),
            'subtitle': _("Where do you live?"),
            'type': "input",
            'maxlength': 100,
            'size': 45,
        },
        'user_interests': {
            'title': _("Interests"),
            'subtitle': _("What do you like most?"),
            'type': "textarea",
            'maxlength': 0,
            'size': (5,20,375,70,),
        },
        'user_occ': {
            'title': _("Occupation"),
            'subtitle': _("What's your job?"),
            'type': "textarea",
            'maxlength': 0,
            'size': (5,20,375,70,),
        },
        'user_sig': {
            'title': _("Signature"),
            'subtitle': _("Your Community signature"),
            'type': "textarea",
            'maxlength': 16777215,
            'size': (5,20,375,70,),
        },
        'user_email': {
            'title': _("E-mail"),
            'subtitle': _("Your current e-mail"),
            'type': "input",
            'maxlength': 100,
            'size': 45,
        },
        'user_birthday': {
            'title': _("Birthday"),
            'subtitle': _("When is your birthday? Hey, wanna get tha present?! DD-MM-YYYY"),
            'type': "input",
            'maxlength': 10,
            'size': 45,
        },
        'group': {
            'title': _("Master User Group"),
            'subtitle': _("Your default User Group"),
            'type': "input",
            'maxlength': 100,
            'size': 45,
            'locked': True,
        },
        'groups': {
            'title': _("User Groups"),
            'subtitle': _("You are also in these User Groups"),
            'type': "input",
            'maxlength': 100,
            'size': 45,
            'locked': True,
        },
    }
    profile_items_order = [
        "user_icq","user_yim","user_msnm",
        "user_jabber","user_website","user_from",
        "user_interests","user_occ","user_birthday",
        "user_sig","group","groups"
    ]

    def __init__(self):
        BaseController.__init__(self)
        WebsiteController.__init__(self)
        self.communuty_my_dispatch_routes = {
            'ugc': self.community_my_ugc,
            'ugc_stats': self.community_my_ugc_stats,
            'dashboard': self.community_my_dashboard,
            'save_profile': self.community_my_save_profile,
            'get_page_info': self.community_my_get_page_info,
        }
        import www.model.UGC
        self.UGC = www.model.UGC.UGC
        import www.model.Portal
        self.Portal = www.model.Portal.Portal
        self.USERS_RANKING_ELEMENTS_PER_PAGE = 20

    def index(self):
        model.config.setup_internal(model, c, session, request)
        c.page_title = _("Sabayon Linux Community Area")
        c.html_title = c.page_title
        return render_mako('/community/index.html')

    def users(self):
        model.config.setup_internal(model, c, session, request)
        portal = self.Portal()
        c.users_count = portal.count_users()
        portal.disconnect(); del portal
        return render_mako('/community/users.html')

    def ranking(self):
        model.config.setup_internal(model, c, session, request)
        my_offset = request.params.get('offset')
        try:
            my_offset = int(my_offset)
        except (ValueError,TypeError,):
            my_offset = 0

        ugc = self.UGC()
        portal = self.Portal()

        c.found_users, c.users = ugc.get_users_score_ranking(offset = my_offset, count = self.USERS_RANKING_ELEMENTS_PER_PAGE)
        mycount = 0
        for item in c.users:
            mycount += 1
            item['username'] = portal.get_username(item['userid'])
            item['ranking'] = my_offset+mycount
        ugc.disconnect()
        portal.disconnect()
        del ugc, portal
        c.offset = my_offset
        c.results_per_page = self.USERS_RANKING_ELEMENTS_PER_PAGE
        c.rand_names = [_("the fabulous"), _("Maximus V"), _("King Sun XIV"),
            _("the one"), _("you name it")]
        return render_mako('/community/ranking.html')

    def links(self):
        model.config.setup_internal(model, c, session, request)
        return render_mako('/community/links.html')

    def my_dispatcher(self, item = None):
        # check if user is logged in
        user_id = self._get_logged_user_id()
        if user_id == None: return self.index()

        func = self.communuty_my_dispatch_routes.get(item)
        if func == None: return self.index()
        model.config.setup_internal(model, c, session, request)
        return func()

    def community_my_ugc(self):
        user_id = self._get_logged_user_id()
        ugc = self.UGC()
        my_ugc_data = ugc.get_user_alldocs(user_id)
        mydata = {}
        for item in my_ugc_data:
            self._expand_ugc_doc_info(ugc, item)
            dtype = item['iddoctype']
            if not mydata.has_key(dtype):
                mydata[dtype] = {}
            dkey = item['key']
            if not mydata[dtype].has_key(dkey):
                mydata[dtype][dkey] = []
            mydata[dtype][dkey].append(item)
        c.my_ugc_data = mydata
        ugc.disconnect()
        del ugc
        c.page_title = _('My User Generated Content')
        return render_mako('/community/my/ugc.html')

    def community_my_ugc_stats(self):
        user_id = self._get_logged_user_id()
        portal = self.Portal()
        ugc = self.UGC()

        self._set_user_perms(user_id, portal)

        stats = ugc.get_user_stats(user_id)
        c.votes = stats['votes']
        c.vote_avg = stats['votes_avg']
        c.total_docs = stats['total_docs']
        c.total_comments = stats['comments']
        c.total_images = stats['images']
        c.total_files = stats['files']
        c.total_videos = stats['yt_videos']
        c.my_ranking = stats['ranking']
        c.score = stats['score']
        c.docs_weight = ugc.DOCS_SCORE_WEIGHT
        c.comments_weight = ugc.COMMENTS_SCORE_WEIGHT
        c.votes_weight = ugc.VOTES_SCORE_WEIGHT

        ugc.disconnect()
        portal.disconnect()
        del ugc, portal
        c.page_title = _('My Statistics')
        return render_mako('/community/my/stats.html')

    def community_my_dashboard(self):
        user_id = self._get_logged_user_id()

        portal = self.Portal()
        self._set_user_perms(user_id, portal)

        c.user_profile = portal.get_user_profile_data(user_id)
        c.pinboard = portal.get_user_id_pinboards(user_id)
        c.pinboard_data_status = portal.PINBOARDS_DATA_STATUS
        c.pinboard_data_status_desc = portal.PINBOARDS_DATA_STATUS_DESC
        c.pinboard_share_status = portal.PINBOARD_SHARES_STATUS
        c.pinboard_share_status_desc = portal.PINBOARD_SHARES_STATUS_DESC

        if c.is_admin:
            c.pages = {}
            c.mirrors = {}
            # News / Pages
            self.setup_pages_data(portal)
            status, pages = portal.get_pages(count = None)
            c.polls = portal.get_polls_data()
            c.poll_votes = portal.get_poll_votes()
            # group by pages_id,page_num
            c.pages_id_order = []
            if status: c.pages, c.pages_id_order = self._format_pages_result(pages)
            # Mirrors
            status, mirrors = portal.get_mirrors()
            if status: c.mirrors = self._format_mirrors_result(mirrors)
            c.shots = self._generate_screenshots_data()
            c.show_shots_edit = True

        portal.disconnect(); del portal
        c.page_title = _('My Sabayon Dashboard')
        c.profile_items = CommunityController.profile_items
        c.profile_items_order = CommunityController.profile_items_order
        return render_mako('/community/my/dashboard.html')



    def community_my_get_page_info(self):
        user_id = self._get_logged_user_id()

        pages_id = request.params.get('pages_id')
        try:
            pages_id = int(pages_id)
            if pages_id < 1:
                raise ValueError
        except ValueError:
            return "%s: %s" % (_("Error"), _("invalid pages_id"),)

        portal = self.Portal()
        self._set_user_perms(user_id, portal)
        if not c.is_admin:
            portal.disconnect(); del portal
            return "%s: %s" % (_("Error"), _("permission denied"),)

        self.setup_pages_data(portal)
        pages = portal.get_generic_pages(pages_id)
        c.pages, c.pages_id_order = self._format_pages_result(pages)
        c.pages_id = pages_id
        portal.disconnect(); del portal
        return render_mako('/community/my/dashboard_pages_page_navigation.html')

    def community_my_save_profile(self):
        if request.method != "POST":
            return "%s: %s" % (_("Error"), _("invalid HTTP method"),)
        user_id = self._get_logged_user_id()
        if not user_id:
            return "%s: %s" % (_("Error"), _("not logged in"),)
        portal = self.Portal()

        status, err_msg = portal.update_user_id_profile(user_id, request.params.copy())

        portal.disconnect(); del portal
        if not status:
            return '%s: %s !' % (
                _("Error"), err_msg,)
        return "%s: %s" % (_("Success"), _('profile updated successfully !'),)

    def search_users(self):

        if request.method != "POST":
            return "%s: %s" % (_("Error"), _("invalid HTTP method"),)

        search = request.params.get('search')
        show_select_cb = request.params.get('show_select_cb')
        select_cb_name = request.params.get('select_cb_name')
        try:
            search = unicode(search) # you never know users' crap
        except (UnicodeEncodeError,UnicodeDecodeError,):
            return "%s: %s" % (_("Error"), _("wrong search request"),)

        model.config.setup_internal(model, c, session, request)
        import random
        portal = self.Portal()
        ugc = self.UGC()
        results = portal.search_users(search)
        for item in results:
            item['ugc_stats'] = ugc.get_user_stats(item['user_id'])
        ugc.disconnect(); portal.disconnect(); del portal, ugc
        c.results = results
        c.myrand = random.randint(1000,9999)
        c.show_select_cb = show_select_cb
        c.select_cb_name = select_cb_name
        c.rand_names = [_("the fabulous"), _("Maximus V"), _("King Sun XIV"),
            _("the one"), _("you name it")]
        return render_mako('/community/users/search_results.html')

    def setup_pages_data(self, portal):
        c.page_types_desc = portal.PAGE_TYPES_DESC
        c.page_types = portal.PAGE_TYPES
        c.page_states = portal.PAGE_STATES
        c.page_states_desc = portal.PAGE_STATES_DESC
        c.mirror_speeds = portal.get_mirror_speeds_dict()
        c.mirror_countries = portal.get_mirror_countries_dict()
