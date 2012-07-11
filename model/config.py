# -*- coding: utf-8 -*-
import hashlib
import os
import gc
import sys
import signal
import datetime, random, os, urllib
from pylons.i18n import _, N_
ugc_connection_data = {}
phpbb_connection_data = {}
try:
    from private import *
except ImportError:
    from www.private import *
from paste.request import construct_url

gc.set_debug(gc.DEBUG_STATS)
# Run gc.collect() with stats to stderr on SIGUSR2
def _gc_collect(signum, frame):
    # shows all the memleak info and stores
    # uncollectable objects to gc.garbage
    gc.set_debug(gc.DEBUG_LEAK)
    gc.collect()
    sys.stderr.write("Uncollectable objects:\n")
    sys.stderr.write("%s\n" % (gc.garbage,))
    sys.stderr.write("\n---\n")
    gc.set_debug(gc.DEBUG_STATS)
    # now clear for real
    del gc.garbage[:]
    gc.collect()

signal.signal(signal.SIGUSR2, _gc_collect)

SITE_URI = 'http://www.sabayon.org'
SITE_URI_SSL = 'https://www.sabayon.org'
FORUM_URI = "http://forum.sabayon.org"
FORUM_URI_SSL = 'https://forum.sabayon.org'
WIKI_URI = "http://wiki.sabayon.org"
WIKI_URI_SSL = "https://wiki.sabayon.org"

VIRUS_CHECK_EXEC = '/usr/bin/clamscan'
VIRUS_CHECK_ARGS = []
DEFAULT_CHMOD_DIR = 0775
DEFAULT_CHMOD_FILE = 0664
DEFAULT_WEB_USER = "entropy"
DEFAULT_WEB_UID = 1000
DEFAULT_WEB_GROUP = "entropy"
DEFAULT_WEB_GID = 1000
GLSA_URI = "http://www.gentoo.org/rdf/en/glsa-index.rdf"
MY_ETP_DIR = "/home/entropy/"
ETP_PATH = '/sabayon/www/packages.sabayon.org/www/entropy/lib'
WEBSITE_TMP_DIR = '/sabayon/www/packages.sabayon.org/temp'
WEBSITE_CACHE_DIR = '/sabayon/www/packages.sabayon.org/cache'
WEBSITE_REPO_CACHE_DIR = WEBSITE_CACHE_DIR + "/_repos"
COMMUNITY_REPOS_DIR = "/sabayon/www/community.sabayon.org/repos/"
REPOSITORIES_CONF_PATH = ETP_PATH + "/../conf/repositories.conf.example"
# new method also!
os.environ['ETP_REPOSITORIES_CONF'] = REPOSITORIES_CONF_PATH
EXCLUDED_MIRROR_NAMES = ["pkg.sabayon.org", "ftp.fsn.hu", "ftp.rnl.ist.utl.pt",
    "mirror.dun.nu", "ftp.cc.uoc.gr", "mirrors.cs.wmich.edu",
    "riksun.riken.go.jp"]
PHPBB_DBNAME = "phpbb3"
PORTAL_DBNAME = "portal"
UGC_MAX_UPLOAD_FILE_SIZE = 20 * 1024000 # 20 mb
LOGIN_URI = '/login'
ETP_REPOSITORY = "sabayonlinux.org"
MY_ETP_DBDIR = "database"
MY_ETP_PKGDIR = "packages"

WEBSITE_CACHING = True

# packages.* options
# XXX hacky thing to support old URLs
default_branch = "5"
default_product = "standard"
default_arch = "amd64"
available_products = {
    "standard": _("Sabayon Linux Standard"),
}
available_arches = {
    "amd64": "amd64",
    "x86": "x86",
    "armv7l": "armv7l",
    "arch": _("Source"),
}
available_sortings = {
    "relevance": _("Relevance"),
    "alphabet": _("Alphabet"),
    "downloads": _("Downloads"),
    "votes": _("Votes"),
}
default_sorting = "relevance"

disabled_repositories = [
    "itsme",
    "community0",
    "community1",
    "jenna",
]
source_repositories = ["portage"]

# UGC #
community_repos_ugc_connection_data = {}

ugc_store_path = "/sabayon/www/community.sabayon.org/ugc"
ugc_store_url = "https://community.sabayon.org/ugc"
ugc_args = [ugc_connection_data,ugc_store_path,ugc_store_url]

GROUP_SHOW_URL = "/group"
CATEGORY_SHOW_URL = "/category"
PACKAGE_SHOW_URL = "/show"
PACKAGE_INSTALL_GET_ETP = "/getinstall"
PACKAGE_SHOW_LICENSE_URL = "/license"
PACKAGE_SHOW_CATEGORY_URL = "/category"
PACKAGE_SHOW_USEFLAG_URL = "/useflag"
PACKAGE_SEARCH_URL = "/quicksearch"
PACKAGE_SWITCH_ARCH_URL = "/archswitch"
PACKAGE_SWITCH_VIEW_URL = "/viewswitch"
PACKAGE_SWITCH_UPDATES_URL = "/updateswitch"
PACKAGE_SWITCH_UPDATES_TYPE_URL = "/updatetype"
PACKAGE_SWITCH_SORTBY_URL = "/sortswitch"
SEARCH_FORM_MAX_LENGTH = 64

def is_https(request):
    if "HTTPS" in request.headers:
        return True
    proto = request.headers.get("X-Forwarded-Proto", "http")
    if proto.lower() == "https":
        return True
    return False

def get_http_protocol(request):
    if is_https(request):
        return "https"
    return "http"

def setup_internal(model, c, session, request):
    setup_session(session)
    setup_misc_vars(c, request)
    setup_login_data(model, c, session)
    session.save()

def setup_login_data(model, c, session):
    import www.model.UGC as ugc
    myugc = ugc.UGC()
    try:
        if session.get('logged_in') and session.get('entropy'):
            if session['entropy'].get('entropy_user_id'):
                c.front_page_user_stats = myugc.get_user_stats(
                    session['entropy']['entropy_user_id'])
    finally:
        myugc.disconnect()
        del myugc

def setup_permission_data(model, c, session):
    if session.get('entropy') and session.get('logged_in'):
        if session['entropy'].get('entropy_user_id'):
            import www.model.Portal
            portal = www.model.Portal.Portal()
            try:
                c.is_user_administrator = portal.check_admin(
                    session['entropy']['entropy_user_id'])
                c.is_user_moderator = portal.check_moderator(
                    session['entropy']['entropy_user_id'])
            finally:
                portal.disconnect()
                del portal

def setup_session(session):
    session.cookie_expires = False
    session.cookie_domain = '.sabayon.org'

def setup_misc_vars(c, request):

    c.HTTP_PROTOCOL = get_http_protocol(request)
    if is_https(request):
        c.site_uri = SITE_URI_SSL
        c.forum_uri = FORUM_URI_SSL
    else:
        c.site_uri = SITE_URI
        c.forum_uri = FORUM_URI

    c.login_uri = LOGIN_URI

    c.www_current_url = construct_url(request.environ)

    c.this_uri = request.environ.get('PATH_INFO')
    if request.environ.get('QUERY_STRING'):
        c.this_uri += '?' + request.environ['QUERY_STRING']
    c.this_uri_full = SITE_URI + c.this_uri
    c.this_uri_full_quoted = urllib.quote(htmlencode(c.this_uri_full))

def hash_string(s):
    m = hashlib.md5()
    m.update(s)
    return m.hexdigest()

def get_current_date():
    import time
    my = time.gmtime()
    return "%s/%s/%s" % (my[2],my[1],my[0],)

def get_current_day_month():
    import time
    my = time.gmtime()
    return "%s%s" % (my[2],my[1],)

def remove_html_tags(data):
    import re
    p = re.compile(r'<.*?>')
    return p.sub('', data)

def remove_phpbb_tags(data):
    import re
    p = re.compile(r'\[.*?\]')
    return p.sub('', data)

def digitalize_ip(user_ip):
    try:
        myip = int(user_ip.replace(".",""))
    except (ValueError,TypeError,):
        myip = None
    return myip

def htmlencode(text):
    """Use HTML entities to encode special characters in the given text."""
    text = text.replace('&', '&amp;')
    text = text.replace('"', '&quot;')
    text = text.replace('<', '&lt;')
    text = text.replace('>', '&gt;')
    return text
