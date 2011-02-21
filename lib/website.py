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
etpConst['repositoriesconf'] = model.config.REPOSITORIES_CONF_PATH
from entropy.exceptions import SystemDatabaseError
try:
    from entropy.db.exceptions import ProgrammingError, OperationalError, \
        DatabaseError
except ImportError:
    from sqlite3.dbapi2 import ProgrammingError, OperationalError, \
        DatabaseError

import entropy.tools as entropy_tools

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
