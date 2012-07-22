# -*- coding: utf-8 -*-
import hashlib
import time
import re
import os
import datetime, random, os, urllib
from pylons.i18n import _, N_
ugc_connection_data = {}
phpbb_connection_data = {}
try:
    from private import *
except ImportError:
    from www.private import *
from paste.request import construct_url

from www.lib.exceptions import ServiceConnectionError

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
http_ugc_store_url = "http://community.sabayon.org/ugc"

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

def hash_string(s):
    m = hashlib.md5()
    m.update(s)
    return m.hexdigest()

def get_current_date():
    my = time.gmtime()
    return "%s/%s/%s" % (my[2],my[1],my[0],)

def get_current_day_month():
    my = time.gmtime()
    return "%s%s" % (my[2],my[1],)

def remove_html_tags(data):
    p = re.compile(r'<.*?>')
    return p.sub('', data)

def remove_phpbb_tags(data):
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
