# -*- coding: utf-8 -*-
import logging
import json
from cStringIO import StringIO
log = logging.getLogger(__name__)

from www.lib.base import *
from www.lib.website import *
from www.lib.apibase import ApibaseController
from www.lib.dict2xml import dict_to_xml

from entropy.const import *
from entropy.exceptions import SystemDatabaseError
try:
    from entropy.db.exceptions import ProgrammingError, OperationalError, \
        DatabaseError
except ImportError:
    from sqlite3.dbapi2 import ProgrammingError, OperationalError, \
        DatabaseError
import entropy.tools as entropy_tools
import entropy.dump as entropy_dump
import entropy.dep as entropy_dep

import shutil, os, time

class PackagesController(BaseController, WebsiteController, ApibaseController):

    def __init__(self):
        BaseController.__init__(self)
        WebsiteController.__init__(self)
        ApibaseController.__init__(self)

    def _render(self, page, renderer = None):
        rendering_map = {
            'json': self._render_json,
            'html': self._render_mako,
            'jsonp': self._render_jsonp,
            # broken
            #'xml': self._render_xml,
        }
        if renderer is None:
            try:
                renderer = request.params.get('render')
            except AttributeError:
                renderer = None
        return rendering_map.get(renderer, self._render_mako)(page)

    def _render_mako(self, page):
        return render_mako(page)

    def _get_renderer_public_data_map(self):
        json_public_map = {}
        for release in c.search_data['misc']['releases']:
            obj = json_public_map.setdefault(release, [])
            for atom in c.search_data['atoms'][release]:
                obj.append(c.search_data['data'][release][atom])
        misc_dict = {}
        for k, v in c.search_data['misc'].items():
            if isinstance(v, set):
                v = list(v)
            misc_dict[k] = v
        json_public_map['__misc__'] = misc_dict
        return json_public_map

    def _render_json(self, page):
        if not c.search_data:
            return ''
        if not isinstance(c.search_data, dict):
            return ''

        try:
            json_public_map = self._get_renderer_public_data_map()
        except KeyError:
            return ''

        return json.dumps(json_public_map)

    def _render_jsonp(self, page):
        callback = "callback"
        try:
            callback = request.params.get('callback') or callback
        except AttributeError:
            callback = "callback"

        json_str = self._render_json(page)
        return callback + "(" + json_str + ");"

    def _render_xml(self, page):
        try:
            json_public_map = self._get_renderer_public_data_map()
        except KeyError:
            return ''

        s = StringIO()
        dict_to_xml(json_public_map, 'entropy', s)
        return s.getvalue()

    def search(self):
        """
        Public API for searching, answering to: http://host/search
        GET parameters:
        q=<query>: search keyword [mandatory]
        a=<arch>: architecture [default: amd64]
        t=<type>: search type (pkg, match, desc, file. lib) [default: pkg]
        r=<repo>: repository id [default: sabayonlinux.org]
        b=<branch>: repository branch [default: 5]
        p=<product>: product [default: standard]
        o=<order by>: order packages by (alphabet, vote, downloads)
        """
        q = request.params.get('q')
        if not q:
            return self.index()

        model.config.setup_internal(model, c, session, request)
        search_types = {
            'pkg': "0",
            'match': "1",
            'desc': "2",
            'lib': "4",
            'file': "3",
        }

        r, a, b, p, o = self._api_get_params()
        if r is None:
            return self.index()
        if a is None:
            return self.index()
        if b is None:
            return self.index()
        if p is None:
            return self.index()

        # search type
        t = request.params.get('t') or "pkg"
        t = search_types.get(t, search_types.get("pkg"))

        return self._do_query_pkg(r, q, p, a, b, t, o)

    def quicksearch(self):

        q = request.params.get('q')
        if not q:
            return self.index()
        if len(q) > 32:
            return self.index()
        elif len(q) < 3:
            return self.index()

        max_results = 50
        # TODO: validate q using regexp


        c.quick_search_string = q
        self._generate_metadata()
        entropy = self._entropy()

        search_map = {
            'default': self._api_search_pkg,
            'description': self._api_search_desc,
            'library': self._api_search_lib,
            'path': self._api_search_path,
            'match': self._api_search_match,
            'sets': self._api_search_sets,
            'mime': self._api_search_mime,
        }
        default_searches = ["match", "default", "description"]

        # try to understand string
        if q.startswith("/"):
            default_searches = ["path"]
        elif q.find(".so") != -1:
            default_searches = ["library"]
        elif q.startswith("@"):
            default_searches = ["sets"]
        elif q.startswith("application/"):
            default_searches = ["mime"]

        results = []
        for search in default_searches:
            results.extend([x for x in search_map.get(search)(entropy, q) \
                if x not in results])
            if len(results) > max_results:
                break
        c.search_pkgs = results

        ugc = self._ugc()
        try:
            data_map = self._get_packages_base_metadata(entropy, ugc,
                results)
        finally:
            ugc.disconnect()
            del ugc

        c.packages_data = data_map
        return self._render('/packages/index.html')

    def index(self):
        self._generate_metadata()
        entropy = self._entropy()

        search_pkgs = []
        search_pkgs += self._get_latest_binary_packages(entropy)
        search_pkgs += self._get_latest_source_packages(entropy)
        c.search_pkgs = search_pkgs

        ugc = self._ugc()
        try:
            data_map = self._get_packages_base_metadata(entropy, ugc,
                search_pkgs)
        finally:
            ugc.disconnect()
            del ugc
        c.packages_data = data_map

        return self._render('/packages/index.html')

    def __atom_match_official_repo(self, dep, product, arch, branch):
        entropy = self._entropy()
        repoid = model.config.ETP_REPOSITORY

        dbconn = self._api_get_repo(entropy, repoid, arch, branch, product)
        if dbconn is None:
            return -1, None

        match_id = dbconn.atomMatch(dep)[0]
        dbconn.close()
        return match_id, repoid

    def _get_ugc_info(self, repoid, pkgkey, ugc = None):

        our_repoid = model.config.ETP_REPOSITORY
        if our_repoid == repoid:
            c_data = model.config.ugc_connection_data
        else:
            c_data = model.config.community_repos_ugc_connection_data.get(repoid)
        if not c_data:
            return None
        close_ugc = False
        if ugc == None:
            close_ugc = True
            ugc = self._ugc()
        mydata = {
            'vote': ugc.get_ugc_vote(pkgkey),
            'downloads': ugc.get_ugc_downloads(pkgkey),
            'docs': ugc.get_ugc_metadata_doctypes(pkgkey, [ugc.DOC_TYPES[x] for x in ugc.DOC_TYPES]),
        }
        for mydoc in mydata['docs']:
            self._expand_ugc_doc_info(ugc, mydoc)

        if close_ugc:
            ugc.disconnect()
            del ugc
        return mydata

    def _search_ugc_content(self, searchstring, doctypes, orderby, results_offset, results_limit):
        ugc = self._ugc()
        results, found_rows = ugc.search_content_items(searchstring,
            iddoctypes = doctypes, results_offset = results_offset,
            results_limit = results_limit, order_by = orderby)
        for item in results:
            ugc._get_ugc_extra_metadata(item)
        ugc.disconnect()
        del ugc
        return results, found_rows

    def _search_ugc_keyword(self, searchstring, doctypes, orderby, results_offset, results_limit):
        ugc = self._ugc()
        results, found_rows = ugc.search_keyword_items(searchstring,
            iddoctypes = doctypes, results_offset = results_offset,
            results_limit = results_limit, order_by = orderby)
        for item in results:
            ugc._get_ugc_extra_metadata(item)
        ugc.disconnect()
        del ugc
        return results, found_rows

    def _search_ugc_username(self, searchstring, doctypes, orderby, results_offset, results_limit):
        ugc = self._ugc()
        results, found_rows = ugc.search_username_items(searchstring,
            iddoctypes = doctypes, results_offset = results_offset,
            results_limit = results_limit, order_by = orderby)
        for item in results:
            ugc._get_ugc_extra_metadata(item)
        ugc.disconnect()
        del ugc
        return results, found_rows

    def _search_ugc_pkgname(self, searchstring, doctypes, orderby, results_offset, results_limit):
        ugc = self._ugc()
        results, found_rows = ugc.search_pkgkey_items(searchstring,
            iddoctypes = doctypes, results_offset = results_offset,
            results_limit = results_limit, order_by = orderby)
        for item in results:
            ugc._get_ugc_extra_metadata(item)
        ugc.disconnect()
        del ugc
        return results, found_rows

    def _search_ugc_iddoc(self, searchstring, doctypes, orderby, results_offset, results_limit):
        ugc = self._ugc()
        results, found_rows = ugc.search_iddoc_item(searchstring,
            iddoctypes = doctypes, results_offset = results_offset,
            results_limit = results_limit, order_by = orderby)
        for item in results:
            ugc._get_ugc_extra_metadata(item)
        ugc.disconnect()
        del ugc
        return results, found_rows

    def _generate_metadata(self):
        c.generic_icon_url_64 = "/images/packages/generic-64x64.png"
        c.generic_icon_url_48 = "/images/packages/generic-48x48.png"
        c.generic_icon_url_22 = "/images/packages/generic-22x22.png"
        c.group_icon_url_64 = "/images/packages/groups/64x64"
        c.group_icon_url_48 = "/images/packages/groups/48x48"
        c.meta_list_url = "/images/packages/metalist"
        c.base_package_show_url = model.config.PACKAGE_SHOW_URL
        model.config.setup_internal(model, c, session, request)

    def _get_post_get_idpackage_product_arch_branch(self, entropy):

        not_found = False
        # idpackage, product, arch, branch
        try:
            idpackage = int(request.params.get('idpackage'))
        except (ValueError,TypeError,):
            idpackage = 0
            not_found = True

        repoid = request.params.get('repo')
        arch = request.params.get('arch')
        product = request.params.get('product')
        branch = request.params.get('branch')
        if not (repoid and product and branch and arch):
            not_found = True

        if not not_found:
            if product not in model.config.available_products:
                not_found = True

        if not not_found:
            repos = self._get_available_repositories(entropy, product, arch)
            if repoid not in repos:
                not_found = True

        if not not_found:
            arches = self._get_available_arches(entropy, repoid, product)
            if arch not in arches:
                not_found = True

        if not not_found:
            avail_branches = []
            avail_branches = entropy._get_branches(repoid, arch, product)
            if branch not in avail_branches:
                not_found = True

        return not_found, idpackage, product, repoid, arch, branch

    def show_ugc_add(self):
        model.config.setup_internal(model, c, session, request)

        error = False
        try:
            ugc_doctype = int(request.params.get('ugc_doctype'))
            if ugc_doctype not in c.ugc_doctypes_desc_singular:
                error = True
        except (ValueError,TypeError,):
            error = True

        c.title = request.params.get('title')
        c.keywords = request.params.get('keywords')
        c.description = request.params.get('description')
        if c.description == "undefined":
            c.description = ''
        pkgkey = request.params.get('pkgkey')
        atom = request.params.get('atom')
        repoid = request.params.get('repoid')
        if not (pkgkey and atom and repoid):
            error = True

        product = request.params.get('product')
        arch = request.params.get('arch')
        if product not in model.config.available_products:
            error = True

        entropy = self._entropy()
        if not error:
            arches = self._get_available_arches(entropy, repoid, product)
            if arch not in arches:
                error = True

        if error:
            return ''
        c.ugc_doctype = ugc_doctype
        c.repoid = repoid
        c.arch = arch
        c.product = product
        c.branch = model.config.default_branch
        c.atom = atom
        c.pkgkey = pkgkey

        return self._render('/packages/do_document_page.html')

    def ugc_delete(self):
        model.config.setup_internal(model, c, session, request)

        user_id = self._get_logged_user_id()
        if not user_id:
            return "%s: %s" % (_("Error"), _("not logged in"),)

        try:
            iddoc = int(request.params.get('iddoc'))
        except (ValueError,TypeError,):
            return "%s: %s" % (_("Error"), _("invalid document"),)

        ugc = self._ugc()
        iddoc_user_id = ugc.get_iddoc_userid(iddoc)
        if iddoc_user_id == None:
            ugc.disconnect()
            del ugc
            return "%s: %s" % (_("Error"), _("invalid document specified"),)
        elif (iddoc_user_id != user_id) and not (c.is_user_administrator or c.is_user_moderator):
            ugc.disconnect()
            del ugc
            return "%s: %s" % (_("Error"), _("permission denied, you suck!"),)

        try:
            doctype = int(ugc.get_iddoctype(iddoc))
        except (ValueError,TypeError,):
            doctype = -1
        if doctype == -1:
            ugc.disconnect()
            del ugc
            return "%s: %s" % (_("Error"), _("WTF? invalid document type!"),)

        status, err_msg = ugc.remove_document_autosense(iddoc, doctype)
        ugc.disconnect()
        del ugc
        if status == None:
            return "%s: %s" % (_("Error"), _("you know what? I cannot handle this document"),)
        if not status: return '%s: %s' % (
            _("Error"), err_msg,)

        return _('Document removed successfully, sigh :\'-(')


    def ugc_add(self):

        model.config.setup_internal(model, c, session, request)

        try:
            user_id = int(request.params.get('user_id'))
        except:
            return "%s: %s" % (_("Error"), _("wrong username"),)

        if user_id != self._get_logged_user_id():
            return "%s: %s" % (_("Error"), _("wrong username"),)

        username = self._get_logged_username()
        if not username:
            return '%s %s' % (
                "%s: %s" % (_("Error"), _("no document specified"),), session,)

        try:
            doctype = int(request.params.get('doctype'))
            if doctype not in c.ugc_doctypes_desc_singular:
                raise ValueError
        except (ValueError,TypeError,):
            return "%s: %s" % (_("Error"), _("invalid document type"),)

        pkgkey = request.params.get('pkgkey')
        if not isinstance(pkgkey,basestring):
            return '%s %s' % (
                "%s: %s" % (_("Error"), _("invalid package key"),), pkgkey,)
        if not pkgkey or (len(pkgkey.split("/")) != 2):
            return "%s: %s" % (_("Error"), _("invalid package string"),)
        if pkgkey: pkgkey = self._htmlencode(pkgkey)

        title = request.params.get('title')
        if not title or len(title) < 5:
            return "%s: %s" % (_("Error"), _("title too short"),)
        if title: title = self._htmlencode(title)

        description = request.params.get('description')
        if (not description) and (doctype != c.ugc_doctypes['comments']):
            return "%s: %s" % (_("Error"), _("description too short"),)

        keywords = request.params.get('keywords')
        if not isinstance(keywords,basestring):
            keywords = ''

        comment_text = request.params.get('text')
        if not isinstance(comment_text,basestring):
            comment_text = ''
        if (len(comment_text) < 5) and (doctype == c.ugc_doctypes['comments']):
            return "%s: %s" % (_("Error"), _("comment text too short"),)
        if comment_text: comment_text = self._htmlencode(comment_text)

        tmp_file = None
        orig_filename = None
        file_name = None
        docfile = request.params.get('docfile')
        docfile_avail = True
        if not hasattr(docfile,'filename'):
            docfile_avail = False
        if (not docfile_avail) and (doctype != c.ugc_doctypes['comments']):
            return "%s: %s" % (_("Error"), _("no file? no party!"),)
        elif docfile_avail and (doctype != c.ugc_doctypes['comments']):
            # fetch tha file
            try:
                orig_filename = os.path.basename(docfile.filename.lstrip(os.sep)) # two is better than lstrip :P
            except AttributeError:
                return '%s: %s' % (
                    _("Error"), request.POST,)
            myrand = "_%s_" % (self._get_random(),)
            tmp_file = os.path.join(model.config.WEBSITE_TMP_DIR,str(user_id)+myrand+orig_filename)
            while os.path.lexists(tmp_file):
                tmp_file = os.path.join(model.config.WEBSITE_TMP_DIR,str(user_id)+myrand+orig_filename)
            tmp_f = open(tmp_file,"wb")
            shutil.copyfileobj(docfile.file, tmp_f)
            docfile.file.close()
            tmp_f.flush()
            tmp_f.close()
            fsize = self._get_file_size(tmp_file)
            if fsize > model.config.UGC_MAX_UPLOAD_FILE_SIZE: # we already check this server side, in middleware.py, two is better than none
                os.remove(tmp_file)
                return "%s: %s" % (_("Error"), _("file too big"),)
            file_name = os.path.join(pkgkey,orig_filename)

        # now handle the UGC add
        ugc = self._ugc()
        status, iddoc = ugc.insert_document_autosense(pkgkey, doctype, user_id, username, comment_text, tmp_file, file_name, orig_filename, title, description, keywords)
        if not status:
            ugc.disconnect()
            del ugc
            return '%s: %s' % (
                _("Error"), iddoc,)
        if not isinstance(iddoc, int):
            ugc.disconnect()
            del ugc
            return '%s %s' % (
                "%s: %s" % (_("Error"), _("document added but couldn't determine 'iddoc' correctly"),), iddoc,)

        c.ugc_doc = {}
        ugc_data = ugc.get_ugc_metadata_by_identifiers([iddoc])
        if ugc_data: c.ugc_doc = ugc_data[0]
        self._expand_ugc_doc_info(ugc, c.ugc_doc)
        ugc.disconnect()
        del ugc
        return self._render('/packages/ugc_show_doc.html')

    def vote(self):

        error = False
        err_msg = None

        # check if we're logged in
        user_id = self._get_logged_user_id()
        if not user_id:
            error = True
            err_msg = _('user not authenticated')

        if not error:
            vote = request.params.get('vote')
            pkgkey = request.params.get('pkgkey')
            try:
                vote = int(vote)
            except (ValueError,TypeError,):
                err_msg = _('invalid vote')
                error = True
            if not pkgkey:
                err_msg = _('invalid package')
                error = True

            if not error:
                ugc = self._ugc()
                if vote not in ugc.VOTE_RANGE:
                    err_msg = _('vote not in range')
                    error = True
                else:
                    voted = ugc.do_vote(pkgkey, user_id, vote, do_commit = True)
                    if not voted:
                        err_msg = _('you already voted this')
                        error = True
                    else:
                        c.new_vote = ugc.get_ugc_vote(pkgkey)
                ugc.disconnect()
                del ugc

        c.error = error
        c.err_msg = err_msg
        return self._render('/packages/voted.html')

    def depends(self):

        entropy = self._entropy()
        not_found, idpackage, product, repo, arch, branch = \
            self._get_post_get_idpackage_product_arch_branch(entropy)
        c.repoid = repo

        c.miscinfo = {}
        c.miscinfo['arch'] = arch
        c.miscinfo['product'] = product
        c.miscinfo['repo'] = repo
        c.miscinfo['branch'] = branch
        c.idpackages = {}

        if not not_found:

            dbconn = self._api_get_repo(entropy, repo, arch, branch, product)
            if dbconn is not None:
                if hasattr(dbconn, 'retrieveDepends'):
                    # backward compatibility
                    mydepends = dbconn.retrieveDepends(idpackage)
                else:
                    mydepends = dbconn.retrieveReverseDependencies(idpackage)
                for mydepend in mydepends:
                    c.idpackages[mydepend] = dbconn.retrieveAtom(mydepend)
                dbconn.close()

        return self._render('/packages/depends.html')

    def content(self):

        entropy = self._entropy()

        not_found, idpackage, product, repo, arch, branch = \
            self._get_post_get_idpackage_product_arch_branch(entropy)
        c.repoid = repo

        c.miscinfo = {}
        c.miscinfo['arch'] = arch
        c.miscinfo['product'] = product
        c.miscinfo['repo'] = repo
        c.miscinfo['branch'] = branch
        c.idpackages = {}
        c.files = []
        c.idpackage = idpackage
        c.branch = branch

        if not not_found:

            dbconn = self._api_get_repo(entropy, repo, arch, branch, product)
            if dbconn is not None:
                c.files = dbconn.retrieveContent(idpackage, order_by = 'file')
                dbconn.close()

        return self._render('/packages/content.html')

    def getadvisory(self):

        entropy = self._entropy()

        atom = request.params.get('atom')
        if not atom:
            return ''

        repo = request.params.get('atom')
        if not repo:
            return ''
        c.repoid = repo

        key = entropy_dep.dep_getkey(atom)
        if not key: return ''

        name = key.split("/")[1]
        import feedparser
        feed = feedparser.parse(model.config.GLSA_URI)
        entries = 2000 # infinite
        strip = None
        # now filter good ones
        myfeed = {}
        myfeed['entries'] = []
        for item in feed['entries']:
            if item['title'].find(name) != -1:
                myfeed['entries'].append(item.copy())

        c.strip = strip
        c.entries = entries
        c.feed = myfeed
        return self._render('/packages/feed.html')

