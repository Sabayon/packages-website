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
import urllib2
import www.lib.helpers as h
import www.model as model
import entropy.exceptions as etp_exceptions
from htmlentitydefs import name2codepoint
from entropy.const import *
etpConst['entropygid'] = model.config.DEFAULT_WEB_GID
import entropy.tools as entropy_tools

class WebsiteController:

    USER_AGENT_BLACKLIST = []

    def __init__(self):

        try:
            user_agent = request.environ['HTTP_USER_AGENT']
        except (AttributeError, KeyError):
            user_agent = None
        if user_agent in WebsiteController.USER_AGENT_BLACKLIST:
            abort(503)

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

    def _store_vote_in_session(self, pages_id, session):
        session['poll_vote_%s' % (pages_id,)] = True
        session.save()

    def _digitalize_ip(self, user_ip):
        return model.config.digitalize_ip(user_ip)

    def _get_remote_ip(self):
        return request.environ.get('REMOTE_ADDR')

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

    def _get_user_id_from_request(self):
        try:
            user_id = int(request.params.get('user_id'))
        except (KeyError, ValueError, TypeError,):
            user_id = 0
        return user_id

    def _get_random(self):
        return abs(hash(os.urandom(2)))

    def _get_file_size(self, file_path):
        mystat = os.lstat(file_path)
        return int(mystat.st_size)

    def _validate_redirect(self, redirect_url):
        """ Validate HTTP redirect request through whitelist """

        if redirect_url.startswith("/"):
            return redirect_url
        if redirect_url == construct_url(request.environ):
            return redirect_url
        if redirect_url.startswith(model.config.SITE_URI):
            return redirect_url
        if redirect_url.startswith(model.config.FORUM_URI):
            return redirect_url
        if redirect_url.startswith(model.config.WIKI_URI):
            return redirect_url

        return None

    def _get_redirect(self):
        """
        Properly get the redirect URL by reading HTTP request redirect
        element. Validates the value and return it, if validation fails
        return None.
        """
        redirect_url = request.params.get('redirect')
        if redirect_url:
            redirect_url = redirect_url.encode('utf-8')
            redirect_url = self._validate_redirect(redirect_url)
        return redirect_url

    def _expand_ugc_doc_info(self, ugc, mydoc):
        if mydoc.get('userid'):
            mydoc['score'] = ugc.get_user_score(mydoc['userid'])
        if mydoc.get('size'):
            mydoc['size'] = entropy_tools.bytes_into_human(mydoc.get('size'))

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

    def _get_generic_activation_parameters(self):
        error = False
        try:
            user_id = int(request.params.get('u'))
        except (ValueError,TypeError,):
            user_id = 0
            error = True
        try:
            validation_id = int(request.params.get('r'))
        except (ValueError,TypeError,):
            validation_id = 0
            error = True
        try:
            confirmation_code = str(request.params.get('c'))
        except:
            confirmation_code = '0'
            error = True

        return error, user_id, validation_id, confirmation_code

    def _load_pages_id(self, pages_id, page_num):
        pages = self.Portal()
        found = False
        if pages._is_pages_id_page_num_available(pages_id, page_num):
            c.pages_id = pages_id
            c.page_num = page_num
            c.page_types = pages.PAGE_TYPES
            c.page_data = pages.get_generic_page(pages_id, page_num)
            c_status, comments_data = pages.get_comments(pages_id, comment_state = pages.COMMENT_STATES['enabled'])
            if c_status: c.comments = comments_data
            if pages._is_pages_id_a_poll(pages_id):
                c.poll = pages.get_poll(pages_id)
            found = True
        pages.disconnect()
        del pages
        return found

    def _format_mirrors_result(self, m_data):
        mirrors_grouped = {}
        for mirror in m_data:
            mirror['note_clear'] = model.config.remove_html_tags(mirror['note'])
            m_c = mirror['country_name']
            m_n = mirror['mirror_name']
            if not mirrors_grouped.has_key(m_c):
                mirrors_grouped[m_c] = {}
            if not mirrors_grouped[m_c].has_key(m_n):
                mirrors_grouped[m_c][m_n] = []
            mirrors_grouped[m_c][m_n].append(mirror)
        return mirrors_grouped

    def _format_pages_result(self, pages):
        data = {}
        order = []
        for item in pages:
            item['intro_clear'] = model.config.remove_html_tags(item['intro'])
            item['intro_encoded'] = self._htmlencode(item['intro'])
            item['text_encoded'] = self._htmlencode(item['text'])
            if item['pages_id'] not in order:
                order.append(item['pages_id'])
            if not data.has_key(item['pages_id']):
                data[item['pages_id']] = {}
            data[item['pages_id']][item['page_num']] = item
        return data, order

    def _validate_email(self, email):
        # ascii test
        try:
            email = str(email)
        except:
            return False
        return entropy_tools.is_valid_email(email)

    def _send_text_email(self, recipients, subject, message):
        from entropy.misc import EmailSender
        sender = EmailSender()
        sender.smtphost = model.config.smtp_host
        sender.smtpport = model.config.smtp_port
        sender.send_text_email(model.config.registration_mail, recipients,
            subject, message)

    def _uncompress_zip(self, file_path, extract_path):

        if not os.path.isfile(file_path):
            raise etp_exceptions.FileNotFound("FileNotFound: %s" % (_('archive does not exist'),))

        import zipfile

        fh = open(file_path, 'rb')
        z = zipfile.ZipFile(fh)
        for name in z.namelist():
            dest_file = os.path.join(extract_path,name)
            out_file = open(dest_file, 'wb')
            out_file.write(z.read(name))
            out_file.close()
        fh.close()

        return 0

    def _uncompress_tar(self, file_path, extract_path, catch_empty = False):

        if not os.path.isfile(file_path):
            raise etp_exceptions.FileNotFound("FileNotFound: %s" % (_('archive does not exist'),))

        import tarfile

        try:
            tar = tarfile.open(file_path,"r")
        except tarfile.ReadError:
            if catch_empty:
                return 0
            raise
        except EOFError:
            return -1

        try:

            def mymf(tarinfo):
                if tarinfo.isdir():
                    # Extract directory with a safe mode, so that
                    # all files below can be extracted as well.
                    try: os.makedirs(os.path.join(extract_path.encode('utf-8'), tarinfo.name), 0777)
                    except EnvironmentError: pass
                    return tarinfo
                tar.extract(tarinfo, extract_path.encode('utf-8'))
                del tar.members[:]
                return 0

            def mycmp(a,b):
                return cmp(a.name,b.name)

            directories = sorted([x for x in map(mymf,tar) if type(x) != int], mycmp, reverse = True)

            # Set correct owner, mtime and filemode on directories.
            def mymf2(tarinfo):
                epath = os.path.join(extract_path, tarinfo.name)
                try:
                    tar.chown(tarinfo, epath)
                    tar.utime(tarinfo, epath)
                    tar.chmod(tarinfo, epath)
                except tarfile.ExtractError:
                    if tar.errorlevel > 1:
                        raise
            done = map(mymf2,directories)
            del done

        except EOFError:
            return -1

        finally:
            tar.close()

        if os.listdir(extract_path):
            return 0
        return -1

    def _set_default_dir_permissions(self, mydir):
        for currentdir,subdirs,files in os.walk(mydir):
            try:
                cur_gid = os.stat(currentdir)[stat.ST_GID]
                if cur_gid != model.config.DEFAULT_WEB_GID:
                    os.chown(currentdir,model.config.DEFAULT_WEB_UID,model.config.DEFAULT_WEB_GID)
                cur_mod = self._get_chmod(currentdir)
                if cur_mod != oct(model.config.DEFAULT_CHMOD_DIR):
                    os.chmod(currentdir,model.config.DEFAULT_CHMOD_DIR)
            except OSError:
                pass
            for item in files:
                item = os.path.join(currentdir,item)
                try:
                    self._setup_file_permissions(
                        item, model.config.DEFAULT_WEB_UID,
                        model.config.DEFAULT_WEB_GID, model.config.DEFAULT_CHMOD_FILE
                    )
                except OSError:
                    pass

    def _setup_file_permissions(self, myfile, uid, gid, chmod):
        cur_gid = os.stat(myfile)[stat.ST_GID]
        if cur_gid != gid:
            os.chown(myfile,uid,gid)
        cur_mod = self._get_chmod(myfile)
        if cur_mod != oct(chmod):
            os.chmod(myfile,chmod)

    # you need to convert to int
    def _get_chmod(self, item):
        st = os.stat(item)[stat.ST_MODE]
        return oct(st & 0777)

    def _remove_dir(self, mydir):
        import shutil
        if os.path.isdir(mydir):
            shutil.rmtree(mydir, True)
        if os.path.isdir(mydir):
            try:
                os.rmdir(mydir)
            except OSError:
                pass


    def _resize_image(self, image_path, dest_image_path, width = None, height = None, percent = None):
        import subprocess
        if not (percent or width or height):
            return -1
        cmd = ["convert",image_path,'-resize']
        if percent:
            cmd.extend([str(percent)+"%"])
        elif (width or height):
            size_s = ''
            if width: size_s += str(width)
            size_s += "x"
            if height: size_s += str(height)
            cmd.extend([size_s])
        cmd.append(dest_image_path)
        f = open("/dev/null","w")
        p = subprocess.Popen(cmd, stdout = f, stderr = f)
        rc = p.wait()
        f.close()
        return rc

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

    def _get_random_md5(self):
        myrnd = os.urandom(2)
        import hashlib
        m = hashlib.md5()
        m.update(myrnd)
        return m.hexdigest()

    def _scan_file_for_viruses(self, filepath):

        if not os.access(filepath,os.R_OK):
            return False

        args = [self.VIRUS_CHECK_EXEC]
        args += self.VIRUS_CHECK_ARGS
        args += [filepath]
        rc = os.system(' '.join(args)+" &> /dev/null")
        if rc == 1:
            return True
        return False

    def _get_recaptcha(self):
        try:
            from recaptcha.client import captcha
            return captcha
        except ImportError:
            return None

    def _new_captcha(self):
        captcha = self._get_recaptcha()
        if captcha == None: return
        myhtml = captcha.displayhtml(model.config.recaptcha_public_key)
        c.recaptcha_html = myhtml
        return myhtml

    def _validate_captcha_submit(self):
        challenge = request.params.get('recaptcha_challenge_field')
        response = request.params.get('recaptcha_response_field')
        remoteip = request.environ.get('REMOTE_ADDR')
        captcha = self._get_recaptcha()
        if captcha == None: return True
        tries = 10
        valid_response = False
        while tries:
            tries -= 1
            try:
                captcha_response = captcha.submit(challenge, response, model.config.recaptcha_private_key, remoteip)
            except urllib2.URLError:
                time.sleep(2)
                continue
            valid_response = captcha_response.is_valid
            break
        if valid_response:
            return True
        return False
