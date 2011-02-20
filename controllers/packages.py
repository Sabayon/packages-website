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
from entropy.cache import EntropyCacher

import shutil, os, time
import hashlib

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
        json_public_map = []
        if c.search_pkgs:
            for pkg_tuple in c.search_pkgs:
                pkg_data = c.packages_data.get(pkg_tuple)
                if pkg_data is not None:
                    json_public_map.append(pkg_data)
        return json_public_map

    def _render_json(self, page):
        json_public_map = self._get_renderer_public_data_map()
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
        json_public_map = self._get_renderer_public_data_map()
        s = StringIO()
        dict_to_xml(json_public_map, 'entropy', s)
        return s.getvalue()

    def _parse_hash_id(self, hash_id):
        decoded_data = self._api_human_decode_package(hash_id)
        if decoded_data is None:
            return

        name, package_id, repository_id, arch, branch, product = decoded_data
        # name is ignored
        if package_id < 1:
            return
        if product not in model.config.available_products:
            return
        if arch not in model.config.available_arches:
            return

        return decoded_data

    def show(self, hash_id):
        """
        Show package details.
        """
        decoded_data = self._parse_hash_id(hash_id)
        if decoded_data is None:
            return redirect(url("/"))
        name, package_id, repository_id, arch, branch, product = decoded_data

        entropy = self._entropy()

        avail_repos = self._get_available_repositories(entropy, product, arch)
        # repository_id
        if repository_id not in avail_repos:
            return redirect(url("/"))

        avail_branches = self._get_available_branches(entropy, repository_id,
            product)
        # branch
        if branch not in avail_branches:
            return redirect(url("/"))

        self._generate_metadata()
        results = [(package_id, repository_id, arch, branch, product)]
        c.search_pkgs = results

        ugc = self._ugc()
        try:
            data_map = self._get_packages_extended_metadata(entropy, ugc,
                results)
        finally:
            ugc.disconnect()
            del ugc
        c.packages_data = data_map

        c.show_detailed_view = True

        return self._render('/packages/index.html')

    def _show_similar(self, hash_id):
        decoded_data = self._parse_hash_id(hash_id)
        if decoded_data is None:
            return redirect(url("/"))
        name, package_id, repository_id, arch, branch, product = decoded_data

        entropy = self._entropy()
        repo = self._api_get_repo(entropy, repository_id, arch, branch, product)
        provided_mime = None
        try:
            if repo is not None:
                provided_mime = sorted(repo.retrieveProvidedMime(package_id))
        finally:
            if repo is not None:
                repo.close()

        if provided_mime is None:
            return self.show(hash_id)

        query = "mime:" + " ".join(provided_mime)
        return self.quicksearch(q = query)

    def show_what(self, hash_id, what):
        """
        Show package details, and given metadatum (what).
        """

        what_map = {
            "similar": self._show_similar,
            "__fallback__": self.show,
        }

        func = what_map.get(what, what_map.get("__fallback__"))
        return func(hash_id)

    def quicksearch(self, q = None):
        """
        Search packages in repositories.
        """

        if q is None:
            q = request.params.get('q')
        if not q:
            return redirect(url("/"))
        if len(q) > 64:
            return redirect(url("/"))
        elif len(q) < 2:
            return redirect(url("/"))

        from_pkg = request.params.get('from') or 0
        if from_pkg:
            try:
                from_pkg = int(from_pkg)
            except ValueError:
                from_pkg = 0

        # max results in a page !
        max_results = 20
        c.max_results = max_results
        c.quick_search_string = q
        self._generate_metadata()
        entropy = self._entropy()

        # caching
        sha = hashlib.sha1()
        sha.update(const_convert_to_rawstring(q))
        mtime_hash = self._get_valid_repositories_mtime_hash(entropy)
        sha.update(mtime_hash)
        cache_key = "quicksearch_" + sha.hexdigest()
        cacher = EntropyCacher()
        results = cacher.pop(cache_key,
            cache_dir = model.config.WEBSITE_CACHE_DIR)

        if results is None:
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
            searching_default = True

            # try to understand string
            if q.startswith("/"):
                default_searches = ["path"]
                searching_default = False
            elif q.find(".so") != -1:
                default_searches = ["library"]
                searching_default = False
            elif q.startswith("@"):
                default_searches = ["sets"]
                searching_default = False
            elif q.startswith("application/"):
                default_searches = ["mime"]
                searching_default = False
            elif q.startswith("mime:") and len(q) > 8:
                default_searches = ["mime"]
                searching_default = False
                q = q[5:]

            results = []
            for search in default_searches:
                for q_split in q.split():
                    results.extend([x for x in search_map.get(search)(entropy,
                        q_split) if x not in results])

            # caching
            # NOTE: EntropyCacher is not started, so cannot use push()
            cacher.save(cache_key,
                results, cache_dir = model.config.WEBSITE_CACHE_DIR)

        results_len = len(results)
        if from_pkg > results_len:
            # invalid !
            return redirect(url("/"))

        if results_len > max_results:
            results = results[from_pkg:]
            results = results[:max_results]
            search_there_is_more = results_len - max_results - from_pkg
            if search_there_is_more > 0:
                c.search_there_is_more = search_there_is_more
                c.search_there_is_more_total = results_len
                c.from_pkg = from_pkg

        c.search_pkgs = results
        c.total_search_results = results_len

        if results:
            ugc = self._ugc()
            try:
                data_map = self._get_packages_base_metadata(entropy, ugc,
                    results)
            finally:
                ugc.disconnect()
                del ugc
            c.packages_data = data_map
        elif searching_default:
            results = self._api_get_similar_packages(entropy, q)
            if results:
                if results_len > max_results:
                    results = results[:max_results]
                ugc = self._ugc()
                try:
                    data_map = self._get_packages_base_metadata(entropy, ugc,
                        results)
                finally:
                    ugc.disconnect()
                    del ugc
                c.search_pkgs = results
                c.packages_data = data_map
                c.did_you_mean = True
            else:
                c.search_nothing_found = True
        else:
            c.search_nothing_found = True

        if request.params.get('more'):
            return self._render('/search_results_area.html')
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
        c.base_search_url = "/quicksearch"
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

