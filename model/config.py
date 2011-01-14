# -*- coding: utf-8 -*-
import hashlib
import datetime, random, os, urllib
from pylons.i18n import _, N_
from www.private import *
from paste.request import construct_url

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
MY_ETP_DIR = "/home/sabayonlinux/public_html/rsync.sabayonlinux.org/entropy/"
ETP_PATH = '/home/sabayonlinux/public_html/packages.sabayon.org/www/entropy/libraries'
WEBSITE_TMP_DIR = '/home/sabayonlinux/public_html/packages.sabayon.org/temp'
COMMUNITY_REPOS_DIR = "/home/sabayonlinux/public_html/community.sabayon.org/repos/"
PHPBB_DBNAME = "phpbb3"
PORTAL_DBNAME = "portal"
UGC_MAX_UPLOAD_FILE_SIZE = 20 * 1024000 # 20 mb
PASTEBIN_MAX_UPLOAD_FILE_SIZE = 5 * 1024000 # 5mb
PASTEBIN_TEXT_LENGTH = 512000
REGISTER_URI = '/login/register'
LOGIN_URI = '/login'
PROFILE_URI = '/users/profile'
ETP_REPOSITORY = "sabayonlinux.org"
ETP_REPOSITORY_DOWNLOAD_MIRRORS = [
    "ftp://ftp.nluug.nl/pub/os/Linux/distr/sabayonlinux/entropy/",
    "ftp://ftp.cc.uoc.gr/mirrors/linux/SabayonLinux/entropy/",
    "ftp://ftp.fsn.hu/pub/linux/distributions/sabayon/entropy/",
    "ftp://mirror.internode.on.net/pub/sabayonlinux/entropy/"
]
MY_ETP_DBDIR = "database"
MY_ETP_PKGDIR = "packages"

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
}
disabled_repositories = [
    "itsme",
    "community0",
    "community1",
    "jenna",
]

# UGC #
community_repos_ugc_connection_data = {}

ugc_store_path = "/home/sabayonlinux/public_html/community.sabayon.org/ugc"
ugc_store_url = "http://community.sabayon.org/ugc"
ugc_args = [ugc_connection_data,ugc_store_path,ugc_store_url]

# UGC #

random_yt_vids = [
    "zbKV4nhYeJE",
    "_i3fQUu_wQE",
    "AEqH78DC7Zw"
]
random_welcome_messages = [
    _("how are you doing?"),
    _("how is it going?"),
    _("welcome back my friend"),
    _("w00t, you are back!")
]
random_encouraging_sentences = [
    _("You are gold for us, do it"),
    _("We love you already, just the last step now"),
    _("It's so nice helping people registering"),
    _("Our hearths belong to you"),
    _("All the best from our crew")
]

repository_feeds_uri = "http://pkg.sabayon.org/"
uri_path = "/"

registration_agreement_text = _(u"""
You agree not to post any abusive, obscene, vulgar, slanderous, hateful, threatening, sexually-orientated or any other material that may violate any laws be it of your country, the country where “www.sabayon.org” is hosted or International Law. Doing so may lead to you being immediately and permanently banned, with notification of your Internet Service Provider if deemed required by us. The IP address of all posts are recorded to aid in enforcing these conditions. You agree that “www.sabayon.org” have the right to remove, edit, move or close any topic at any time should we see fit. As a user you agree to any information you have entered to being stored in a database. While this information will not be disclosed to any third party without your consent, neither “www.sabayon.org” nor phpBB shall be held responsible for any hacking attempt that may lead to the data being compromised. This website has COPPA (Child's Online Privacy Protection Act) compliancy. This means that you must, on the current time and date, be 13 years of age or older in order to participate in any functions of this website (registering, posting, etc.). By clicking the button below, you agree that you are at least 13 years old.""")

registration_mail_text = _("""Welcome to the Sabayon Linux Community world ! A warm hug from all us!

Please keep this e-mail for your records. Your account information is as
follows:

----------------------------
Username: --username--
Password: --password--

Website URL: --website_url--
----------------------------

Your account is currently inactive. You cannot use it until you visit the
following link:


--activation_url--

Please do not forget your password as it has been encrypted in our database
and we cannot retrieve it for you. However, should you forget your password
you can request a new one which will be activated in the same way as this
account.

Thank you for registering.

--
Thanks, the Sabayon Linux Project
""")

email_update_mail_text = _("""Sabayon Linux Community - E-mail update notification

Here is a brief summary:

----------------------------
Old e-mail: --old_email--
New e-mail: --new_email--

Website URL: --website_url--
----------------------------

Your change is currently inactive. You cannot use it until you visit the
following link:

--activation_url--

--
Thanks, the Sabayon Linux Project
""")

password_update_mail_text = _("""Sabayon Linux Community - Password update notification

Here is a brief summary:

----------------------------
New password: --new_password--

Website URL: --website_url--
----------------------------

Your change is currently inactive. You cannot use it until you visit the
following link:

--activation_url--

--
Thanks, the Sabayon Linux Project
""")

pinboard_share_invite_text = _("""Sabayon Linux Community - Pinboard share request

--request_username-- wants to share with you a Pinboard. This feature is available
on our Website through your personal Dashboard under the "Pinboard" tab.

Here is a brief summary:

----------------------------
Pinboard title: --pinboard_title--

Pinboard description: --pinboard_description--
----------------------------

Obviously, we are not morons, to accept the offer, you just have to click the link below:

--activation_url--

--
Thanks, the Sabayon Linux Project
""")

registration_mail_subject = _("Sabayon Linux Community Registration Confirmation")
email_update_mail_subject = _("Sabayon Linux Community E-mail Update Confirmation")
password_update_mail_subject = _("Sabayon Linux Community Password Update Confirmation")
registration_mail = 'website@sabayon.org'
registration_activation_required = True
registration_activation_uri = os.path.join(SITE_URI,'login/activate/')
email_update_activation_uri = os.path.join(SITE_URI,'login/email_activate/')
password_update_activation_uri = os.path.join(SITE_URI,'login/password_activate/')
smtp_host = 'localhost'
smtp_port = 25

def is_https(request):
    return "HTTPS" in request.headers

def get_http_protocol(request):
    if is_https(request):
        return "https"
    return "http"

def setup_all(model, c, session, request):
    setup_session(session)
    setup_misc_vars(c, request)
    setup_login_data(model, c, session)
    setup_permission_data(model, c, session)
    session.save()

def setup_internal(model, c, session, request):
    setup_session(session)
    setup_misc_vars(c, request)
    setup_login_data(model, c, session)
    setup_permission_data(model, c, session)
    session.save()

def setup_login_data(model, c, session):
    import www.model.UGC as ugc
    myugc = ugc.UGC()
    c.front_page_distro_stats = myugc.get_distribution_stats()
    if session.get('logged_in') and session.get('entropy'):
        session['entropy']['random_welcome_message'] = random_welcome_messages[int(random.random()*100%len(random_welcome_messages))]
        if session['entropy'].get('entropy_user_id'):
            c.front_page_user_stats = myugc.get_user_stats(session['entropy']['entropy_user_id'])
    myugc.disconnect()
    del myugc

def setup_permission_data(model, c, session):
    if session.get('entropy') and session.get('logged_in'):
        if session['entropy'].get('entropy_user_id'):
            import www.model.Portal
            portal = www.model.Portal.Portal()
            c.is_user_administrator = portal.check_admin(session['entropy']['entropy_user_id'])
            c.is_user_moderator = portal.check_moderator(session['entropy']['entropy_user_id'])
            user_birthday = portal.get_user_birthday(session['entropy']['entropy_user_id'])
            user_birthday = [x.strip() for x in user_birthday.split("-")]
            if len(user_birthday) > 1:
                try:
                    user_birthday = '%s%s' % (int(user_birthday[0]), int(user_birthday[1]),)
                except (ValueError, TypeError,):
                    user_birthday = 'never'
            else:
                user_birthday = 'never'
            # is user_birthday?
            if user_birthday == get_current_day_month():
                if not session['site_messages'].get('birthday'):
                    birthday_txt = "<div align='center'><span style='color: red; font-size: 1.3em'>%s<br/> %s<br/> %s</span><br/>%s.</div>" % (
                        _("Happy <b>birthday</b> to you!"), _("Happy <b>birthday</b> to youuu!"), _("And the cake to <b>USSSSS</b>!"), _("...from the Sabayon Linux crew"),)
                    session['site_messages']['birthday'] = birthday_txt
            elif session['site_messages'].get('birthday'):
                del session['site_messages']['birthday']
            portal.disconnect()
            del portal

def setup_session(session):
    if session.get('site_messages') == None:
        session['site_messages'] = {}
    #cookie_timer = datetime.timedelta(30)
    session.cookie_expires = False
    #session.timeout = 604800*3 # 3 weeks
    session.cookie_domain = '.sabayon.org'

def setup_misc_vars(c, request):
    c.registration_agreement_text = registration_agreement_text
    c.encouraging_sentence = random_encouraging_sentences[int(random.random()*100%len(random_encouraging_sentences))]
    if is_https(request):
        c.site_uri = SITE_URI_SSL
        c.forum_uri = FORUM_URI_SSL
    else:
        c.site_uri = SITE_URI
        c.forum_uri = FORUM_URI

    c.register_uri = REGISTER_URI
    c.profile_uri = PROFILE_URI
    c.login_uri = LOGIN_URI

    c.www_current_url = construct_url(request.environ)
    try:
        c.browser_user_agent = request.environ['HTTP_USER_AGENT']
    except KeyError:
        pass

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
