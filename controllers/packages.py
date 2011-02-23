# -*- coding: utf-8 -*-
import os
import json
import time
from datetime import datetime
from cStringIO import StringIO
import shutil, os, time
import hashlib
import tempfile

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
import entropy.dump as entropy_dump
import entropy.dep as entropy_dep

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

    def _set_search_time(self, end_t, start_t):
        c.packages_search_time = round(abs(end_t - start_t), 4)

    def _get_renderer_public_data_map(self):

        if request.params.get("api") == "0":
            # THIS IS THE OLD PUBLIC API !!
            # support Ian stuff (the irc bot was using the old API)
            entropy = self._entropy()

            idproduct = request.params.get("p") or model.config.default_product
            if idproduct not in model.config.available_products:
                idproduct = model.config.default_product
            product = model.config.available_products.get(idproduct)
            arch = request.params.get("a") or model.config.default_arch
            if arch not in model.config.available_arches:
                arch = model.config.default_arch
            releases = set()
            old_data_format = {}
            ugc_cache = {}
            ugc = self._ugc()
            try:
                for pkg_tuple in c.search_pkgs:
                    p_id, r, a, b, p = pkg_tuple
                    pkg_data = c.packages_data.get(pkg_tuple)
                    if pkg_data:
                        releases.add(b)
                        obj = old_data_format.setdefault(b, [])
                        key = pkg_data['key']
                        if key not in ugc_cache:
                            ugc_data = self._get_ugc_base_metadata(entropy,
                                ugc, r, key)
                            ugc_cache[key] = ugc_data

                        item = {
                            "category": pkg_data['category'],
                            "description": pkg_data['description'],
                            'spm_repo': pkg_data['spm_repo'],
                            'name': pkg_data['name'],
                            'branch': b,
                            'atom': pkg_data['atom'],
                            'idpackage': pkg_data['package_id'],
                            'homepage': pkg_data['homepage'],
                            'revision': pkg_data['revision'],
                            'download': pkg_data['download'],
                            'digest': pkg_data.get("digest", ""),
                            'size': pkg_data.get("size", ""),
                            'ugc': ugc_cache[key],
                        }
                        obj.append(item)
            finally:
                ugc.disconnect()
                del ugc
                ugc_cache.clear()
                del ugc_cache

            if c.search_there_is_more:
                is_more = True
            else:
                is_more = False
            if c.search_there_is_more_total:
                total = c.search_there_is_more_total
            else:
                total = len(c.search_pkgs)
            from_pkg = c.from_pkg or 0
            misc_data = {
                "product": product,
                "arch": arch,
                "idproduct": idproduct,
                "releases": sorted(releases, reverse = True),
                'more': is_more,
                'total': total,
                'from': from_pkg,
            }
            json_public_map = {
                "__misc__": misc_data,
            }
            json_public_map.update(old_data_format)
        else:
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

        # validate repository_id
        if not self._repo_re.match(repository_id):
            return

        return decoded_data

    def show(self, hash_id):
        """
        Show package details.
        """
        start_t = time.clock()

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

        self._generate_html_metadata()
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
        try:
            data_obj = data_map[results[0]]
            c.html_title = data_obj['atom'] + " on " + data_obj['product'] + \
                ", " + data_obj['repository_id'] + ", " + data_obj['arch'] + \
                ", " + data_obj['branch']
            c.html_description = data_obj['description']
        except (IndexError, KeyError):
            pass

        c.show_detailed_view = True
        self._set_search_time(time.clock(), start_t)

        return self._render('/index.html', renderer = "html")

    def _show_similar(self, hash_id):
        decoded_data = self._parse_hash_id(hash_id)
        if decoded_data is None:
            return redirect(url("/"))
        name, package_id, repository_id, arch, branch, product = decoded_data

        entropy = self._entropy()
        repo = self._api_get_repo(entropy, repository_id, arch, branch, product)
        provided_mime = None
        category = None
        try:
            if repo is not None:
                provided_mime = repo.retrieveProvidedMime(package_id)
                category = repo.retrieveCategory(package_id)
        finally:
            if repo is not None:
                repo.close()

        if provided_mime is None:
            return self.show(hash_id)

        mime_str = ""
        max_len = model.config.SEARCH_FORM_MAX_LENGTH
        for mime in sorted(provided_mime):
            if (len(mime_str) + 1 + len(mime)) > max_len:
                # reached the end
                break
            mime_str += " " + mime
        query = self.PREFIXES['mime'] + mime_str
        return self.quicksearch(q = query, filter_str = "category",
            filter_data = category, override_query_length_checks = True)

    def _show_changelog(self, hash_id):
        decoded_data = self._parse_hash_id(hash_id)
        if decoded_data is None:
            return redirect(url("/"))
        name, package_id, repository_id, arch, branch, product = decoded_data

        show_what_data = {
            'what': "changelog",
            'data': None,
        }

        entropy = self._entropy()
        repo = self._api_get_repo(entropy, repository_id, arch, branch, product)
        changelog = None
        try:
            if repo is not None:
                changelog = repo.retrieveChangelog(package_id)
        finally:
            if repo is not None:
                repo.close()

        if (changelog is not None) and (changelog != "None"):
            # fixup bug (!= "None")
            show_what_data['data'] = changelog
        c.package_show_what = show_what_data

        return self.show(hash_id)

    def _show_dependencies(self, hash_id):
        decoded_data = self._parse_hash_id(hash_id)
        if decoded_data is None:
            return redirect(url("/"))
        name, package_id, repository_id, arch, branch, product = decoded_data

        show_what_data = {
            'what': "dependencies",
            'data': None,
        }

        entropy = self._entropy()
        repo = self._api_get_repo(entropy, repository_id, arch, branch, product)
        dependencies = None
        try:
            if repo is not None:
                dependencies = repo.retrieveDependencies(package_id,
                    extended = True)
        finally:
            if repo is not None:
                repo.close()

        if dependencies is not None:
            data = {}
            data['build_deps'] = [x for x, y in dependencies \
                if y == etpConst['dependency_type_ids']['bdepend_id']]
            data['run_deps'] = [x for x, y in dependencies if \
                y == etpConst['dependency_type_ids']['rdepend_id']]
            data['post_deps'] = [x for x, y in dependencies if \
                y == etpConst['dependency_type_ids']['pdepend_id']]
            data['manual_deps'] = [x for x, y in dependencies if \
                y == etpConst['dependency_type_ids']['mdepend_id']]
            key_sorter = lambda x: entropy_dep.dep_getkey(x)
            for k, v in data.items():
                v.sort(key = key_sorter)
            show_what_data['data'] = data

        c.package_show_what = show_what_data

        return self.show(hash_id)

    def _show_reverse_dependencies(self, hash_id):
        decoded_data = self._parse_hash_id(hash_id)
        if decoded_data is None:
            return redirect(url("/"))
        name, package_id, repository_id, arch, branch, product = decoded_data

        show_what_data = {
            'what': "reverse_dependencies",
            'data': None,
        }

        entropy = self._entropy()

        # caching
        revdep_cache = None

        if model.config.WEBSITE_CACHING:
            sha = hashlib.sha1()
            hash_str = "%s|%s|%s|%s|%s" % (
                repository_id, arch, branch, product,
                self._get_valid_repositories_mtime_hash(entropy))
            sha.update(hash_str)
            cache_key = "_show_reverse_dependencies_" + sha.hexdigest()
            # whacky thing !!
            revdep_cache = self._cacher.pop(cache_key,
                cache_dir = model.config.WEBSITE_CACHE_DIR)

        revdep_meta = []
        repo = self._api_get_repo(entropy, repository_id, arch, branch,
            product)
        try:
            if repo is not None:
                if revdep_cache is not None:
                    repo._setLiveCache("reverseDependenciesMetadata",
                        revdep_cache)
                pkg_ids = repo.retrieveReverseDependencies(package_id)
                if revdep_cache is None:
                    revdep_cache = repo._getLiveCache(
                        "reverseDependenciesMetadata")

                def key_sorter(x):
                    atom = repo.retrieveAtom(x)
                    if atom:
                        return entropy_dep.dep_getkey(atom)
                    else:
                        return "0"

                for pkg_id in sorted(pkg_ids, key = key_sorter):
                    pkg_hash_id = self._api_human_encode_package(
                        repo.retrieveName(pkg_id), pkg_id, repository_id, arch,
                        branch, product)

                    revdep_meta.append({
                        'hash_id': pkg_hash_id,
                        'atom': repo.retrieveAtom(pkg_id),
                    })

        finally:
            if repo is not None:
                repo.close()

        if model.config.WEBSITE_CACHING:
            if revdep_cache is not None:
                self._cacher.save(cache_key,
                    revdep_cache, cache_dir = model.config.WEBSITE_CACHE_DIR)

        if revdep_meta:
            show_what_data['data'] = revdep_meta
        c.package_show_what = show_what_data

        return self.show(hash_id)

    def _show_security(self, hash_id):
        decoded_data = self._parse_hash_id(hash_id)
        if decoded_data is None:
            return redirect(url("/"))
        name, package_id, repository_id, arch, branch, product = decoded_data

        show_what_data = {
            'what': "security",
            'data': None,
        }
        try:
            import feedparser
        except ImportError:
            feedparser = None

        if feedparser is not None:

            feed = None
            now = datetime.now()
            cache_key = "_show_security_" + str(now.year) + \
                str(now.month) + str(now.day)

            if model.config.WEBSITE_CACHING:
                feed = self._cacher.pop(cache_key,
                    cache_dir = model.config.WEBSITE_CACHE_DIR)

            if feed is None:
                feed = feedparser.parse(model.config.GLSA_URI)
                if model.config.WEBSITE_CACHING:
                    if isinstance(feed, dict):
                        self._cacher.save(cache_key,
                            feed, cache_dir = model.config.WEBSITE_CACHE_DIR)

            results = []
            for item in feed['entries']:
                if item.get("title", "").find(name) != -1:
                    results.append(item)
            results.sort(key = lambda x: x['title'])
            results.reverse()
            show_what_data['data'] = results

        c.package_show_what = show_what_data

        return self.show(hash_id)

    def _show_mime(self, hash_id):
        decoded_data = self._parse_hash_id(hash_id)
        if decoded_data is None:
            return redirect(url("/"))
        name, package_id, repository_id, arch, branch, product = decoded_data

        show_what_data = {
            'what': "mime",
            'data': None,
        }

        entropy = self._entropy()
        repo = self._api_get_repo(entropy, repository_id, arch, branch, product)
        provided_mime = None
        try:
            if repo is not None:
                provided_mime = repo.retrieveProvidedMime(package_id)
        finally:
            if repo is not None:
                repo.close()

        show_what_data['data'] = provided_mime
        c.package_show_what = show_what_data

        return self.show(hash_id)

    def _show_provided_libs(self, hash_id):
        decoded_data = self._parse_hash_id(hash_id)
        if decoded_data is None:
            return redirect(url("/"))
        name, package_id, repository_id, arch, branch, product = decoded_data

        show_what_data = {
            'what': "provided_libs",
            'data': None,
        }

        entropy = self._entropy()
        repo = self._api_get_repo(entropy, repository_id, arch, branch, product)
        provided_libs = None
        try:
            if repo is not None:
                provided_libs = repo.retrieveProvidedLibraries(package_id)
        finally:
            if repo is not None:
                repo.close()

        show_what_data['data'] = {
            'provided_libs': provided_libs,
            'arch': arch,
            'branch': branch,
            'product': product,
        }
        c.package_show_what = show_what_data

        return self.show(hash_id)

    def _show_needed_libs(self, hash_id):
        decoded_data = self._parse_hash_id(hash_id)
        if decoded_data is None:
            return redirect(url("/"))
        name, package_id, repository_id, arch, branch, product = decoded_data

        show_what_data = {
            'what': "needed_libs",
            'data': None,
        }

        entropy = self._entropy()
        repo = self._api_get_repo(entropy, repository_id, arch, branch, product)
        needed_libs = None
        try:
            if repo is not None:
                needed_libs = repo.retrieveNeeded(package_id)
        finally:
            if repo is not None:
                repo.close()

        show_what_data['data'] = {
            'needed_libs': needed_libs,
            'arch': arch,
            'branch': branch,
            'product': product,
        }
        c.package_show_what = show_what_data

        return self.show(hash_id)

    def _show_content(self, hash_id):
        decoded_data = self._parse_hash_id(hash_id)
        if decoded_data is None:
            return redirect(url("/"))
        name, package_id, repository_id, arch, branch, product = decoded_data

        show_what_data = {
            'what': "content",
            'data': None,
        }

        entropy = self._entropy()
        repo = self._api_get_repo(entropy, repository_id, arch, branch, product)
        content = None
        try:
            if repo is not None:
                content = repo.retrieveContent(package_id,
                    order_by = "file")
        finally:
            if repo is not None:
                repo.close()

        show_what_data['data'] = content
        c.package_show_what = show_what_data

        return self.show(hash_id)

    def _show_download(self, hash_id):
        decoded_data = self._parse_hash_id(hash_id)
        if decoded_data is None:
            return redirect(url("/"))
        name, package_id, repository_id, arch, branch, product = decoded_data

        entropy = self._entropy()
        settings = entropy.Settings()
        show_what_data = {
            'what': "download",
            'data': settings['repositories'].get('available', {}).get(repository_id),
            'excluded': model.config.EXCLUDED_MIRROR_NAMES,
        }
        c.package_show_what = show_what_data

        return self.show(hash_id)

    def _show_sources(self, hash_id):
        decoded_data = self._parse_hash_id(hash_id)
        if decoded_data is None:
            return redirect(url("/"))
        name, package_id, repository_id, arch, branch, product = decoded_data

        show_what_data = {
            'what': "sources",
            'data': None,
        }

        entropy = self._entropy()
        repo = self._api_get_repo(entropy, repository_id, arch, branch, product)
        sources = None
        try:
            if repo is not None:
                sources = repo.retrieveSources(package_id,
                    extended = True)
        finally:
            if repo is not None:
                repo.close()

        show_what_data['data'] = sources
        c.package_show_what = show_what_data

        return self.show(hash_id)

    def _show_ugc(self, hash_id):
        decoded_data = self._parse_hash_id(hash_id)
        if decoded_data is None:
            return redirect(url("/"))
        name, package_id, repository_id, arch, branch, product = decoded_data

        show_what_data = {
            'what': "ugc",
            'data': None,
        }

        entropy = self._entropy()
        repo = self._api_get_repo(entropy, repository_id, arch, branch, product)
        ugc = self._ugc()
        metadata = None
        try:
            if repo is not None:
                atom = repo.retrieveAtom(package_id)
                if atom is not None:
                    key = entropy_dep.dep_getkey(atom)
                    metadata = self._get_ugc_extended_metadata(ugc, key)
        finally:
            ugc.disconnect()
            del ugc
            if repo is not None:
                repo.close()

        show_what_data['data'] = metadata
        c.package_show_what = show_what_data

        self._generate_login_metadata()
        return self.show(hash_id)

    def show_what(self, hash_id, what):
        """
        Show package details, and given metadatum (what).
        """
        what_map = {
            "similar": self._show_similar,
            "__fallback__": self.show,
            "changelog": self._show_changelog,
            "dependencies": self._show_dependencies,
            "reverse_dependencies": self._show_reverse_dependencies,
            "security": self._show_security,
            "mime": self._show_mime,
            "provided_libs": self._show_provided_libs,
            "needed_libs": self._show_needed_libs,
            "content": self._show_content,
            "download": self._show_download,
            "sources": self._show_sources,
            "ugc": self._show_ugc,
        }

        func = what_map.get(what, what_map.get("__fallback__"))
        return func(hash_id)

    def group(self, group):
        """
        Show packages in group, using quicksearch
        """
        query = self.PREFIXES['group'] + group
        return self.quicksearch(q = query)

    def category(self, category):
        """
        Show packages in category, using quicksearch
        """
        query = self.PREFIXES['category'] + category
        return self.quicksearch(q = query)

    def license(self, license):
        """
        Show packages providing license, using quicksearch
        """
        query = self.PREFIXES['license'] + license
        return self.quicksearch(q = query)

    def useflag(self, useflag):
        """
        Show packages providing useflag, using quicksearch
        """
        query = self.PREFIXES['useflag'] + useflag
        return self.quicksearch(q = query)

    def _get_request_search_filter_params(self, filter_str = None,
        filter_data = None):
        """
        Given the current request.params object in context, return the
        associated _api_search_* filter function if found and valid, otherwise
        return None. The signature of the filtering function is declared inside
        apibase module, under any _api_search_* method. It's:
            bool filter_cb(entropy_repository, package_id)
        """
        if filter_str is None:
            filter_str = request.params.get("filter")
        if not filter_str:
            return None
        if not filter_str.strip():
            return None
        if filter_data is None:
            filter_data = request.params.get("filter_data")
        if not filter_data:
            return None
        if not filter_data.strip():
            return None

        filter_data_list = filter_data.split()
        c.search_filter_str = filter_str
        c.search_filter_data = filter_data

        def _filter_category(repo, pkg_id):
            cat = repo.retrieveCategory(pkg_id)
            return cat in filter_data_list

        def _filter_category_startswith(repo, pkg_id):
            cat = repo.retrieveCategory(pkg_id)
            for filter_cat in filter_data_list:
                if cat.startswith(filter_cat):
                    return True
            return False

        supported_filters = {
            "category": _filter_category,
            "category_startswith": _filter_category_startswith,
        }
        return supported_filters.get(filter_str, None)

    def archswitch(self, arch):
        """
        Function that switches the quicksearch default arch.
        """
        if arch in model.config.available_arches:
            session['selected_arch'] = arch
            session.save()
        elif arch == "all":
            if 'selected_arch' in session:
                del session['selected_arch']
                session.save()

        q = request.params.get("q")
        filter_func = request.params.get("filter")
        filter_data = request.params.get("filter_data")

        q_str = model.config.PACKAGE_SEARCH_URL
        if q:
            q_str += "?q=" + q
        if filter_func:
            q_str += "&filter=" + filter_func
        if filter_data:
            q_str += "&filter_data=" + filter_data

        return redirect(url(const_convert_to_rawstring(q_str)))

    def viewswitch(self, view):
        """
        Function that switches the quicksearch default view.
        """
        if view in ("default", "compact"):
            session['selected_view'] = view
            session.save()

        q = request.params.get("q")
        filter_func = request.params.get("filter")
        filter_data = request.params.get("filter_data")

        q_str = model.config.PACKAGE_SEARCH_URL
        if q:
            q_str += "?q=" + q
        if filter_func:
            q_str += "&filter=" + filter_func
        if filter_data:
            q_str += "&filter_data=" + filter_data

        return redirect(url(const_convert_to_rawstring(q_str)))

    def quicksearch(self, q = None, filter_str = None, filter_data = None,
        override_query_length_checks = False):
        """
        Search packages in repositories.
        Public API for searching, answering to: http://host/search
        GET parameters:
        q=<query>: search keyword [mandatory]
        a=<arch>: architecture [default: amd64]
        t=<type>: search type (pkg, match, desc, file. lib) [default: pkg]
        r=<repo>: repository id [default: sabayonlinux.org]
        b=<branch>: repository branch [default: 5]
        p=<product>: product [default: standard]
        filter=<filter type>: filter package results using given filter type
            currently supported filters:
                "category"
        filter_data=<filter data>: if a filter is selected, the data that
            should be used for filtering (pattern matching) must be passed
            on the filter_data parameter
        """
        start_t = time.clock()
        def _redirect_to_home():
            if request.params.get('more'):
                return ""
            return redirect(url("/"))

        if q is None:
            q = request.params.get('q')
        if not q:
            return _redirect_to_home()
        if not q.strip():
            return _redirect_to_home()
        if not override_query_length_checks:
            if len(q) > model.config.SEARCH_FORM_MAX_LENGTH:
                return _redirect_to_home()
            elif len(q) < 2:
                return _redirect_to_home()

        # no need to validate them, already validated below
        # use r, a, b, p as filter
        r = request.params.get('r')
        a = request.params.get('a')
        if not a:
            a = session.get('selected_arch')
            if a == "all":
                a = None
        b = request.params.get('b')
        p = request.params.get('p')
        t = request.params.get('t')
        filter_cb = self._get_request_search_filter_params(
            filter_str = filter_str, filter_data = filter_data)

        from_pkg = request.params.get('from') or 0
        if from_pkg:
            try:
                from_pkg = int(from_pkg)
            except ValueError:
                from_pkg = 0

        # max results in a page !
        if request.params.get("api") == "0":
            max_results = 50
        else:
            max_results = 10
        c.max_results = max_results
        c.quick_search_string = q
        self._generate_html_metadata()
        entropy = self._entropy()

        # caching
        results = None
        if model.config.WEBSITE_CACHING:
            sha = hashlib.sha1()
            sha.update(const_convert_to_rawstring(q))
            sha.update(repr(r))
            sha.update(repr(a))
            sha.update(repr(b))
            sha.update(repr(p))
            mtime_hash = self._get_valid_repositories_mtime_hash(entropy)
            sha.update(mtime_hash)
            cache_key = "quicksearch_" + sha.hexdigest()
            results = self._cacher.pop(cache_key,
                cache_dir = model.config.WEBSITE_CACHE_DIR)

        if results is None:
            search_map = {
                'default': self._api_search_pkg,
                'description': self._api_search_desc,
                'library': self._api_search_lib,
                'provided_library': self._api_search_provided_lib,
                'path': self._api_search_path,
                'match': self._api_search_match,
                'sets': self._api_search_sets,
                'mime': self._api_search_mime,
                'group': self._api_search_group,
                'category': self._api_search_category,
                'license': self._api_search_license,
                'useflag': self._api_search_useflag,
            }
            default_searches = ["match", "default"] #, "description"]
            searching_default = True
            # &t support
            if t == "pkg":
                default_searches = ["default"]
                searching_default = False
            elif t == "match":
                default_searches = ["match"]
                searching_default = False
            elif t == "desc":
                default_searches = ["description"]
                searching_default = False
            elif t == "file":
                default_searches = ["path"]
                searching_default = False
            elif t == "lib":
                default_searches = ["library"]
                searching_default = False
            elif t == "prov_lib":
                default_searches = ["provided_library"]
                searching_default = False

            elif not t:
                # try to understand string
                if q.startswith("/"):
                    default_searches = ["path"]
                    searching_default = False
                elif q.startswith("@"):
                    default_searches = ["sets"]
                    searching_default = False
                elif q.startswith("application/"):
                    default_searches = ["mime"]
                    searching_default = False
                elif q.startswith(self.PREFIXES['mime']) and \
                    len(q) > (5+len(self.PREFIXES['mime'])):
                    default_searches = ["mime"]
                    searching_default = False
                    q = q[len(self.PREFIXES['mime']):]
                    if not q.strip():
                        return _redirect_to_home()
                elif q.startswith(self.PREFIXES['group']) and \
                    len(q) > (2+len(self.PREFIXES['group'])):
                    default_searches = ["group"]
                    searching_default = False
                    q = q[len(self.PREFIXES['group']):]
                    if not q.strip():
                        return _redirect_to_home()
                elif q.startswith(self.PREFIXES['category']) and \
                    len(q) > (5+len(self.PREFIXES['category'])):
                    default_searches = ["category"]
                    searching_default = False
                    q = q[len(self.PREFIXES['category']):]
                    if not q.strip():
                        return _redirect_to_home()
                elif q.startswith(self.PREFIXES['license']) and \
                    len(q) > (2+len(self.PREFIXES['license'])):
                    default_searches = ["license"]
                    searching_default = False
                    q = q[len(self.PREFIXES['license']):]
                    if not q.strip():
                        return _redirect_to_home()
                elif q.startswith(self.PREFIXES['useflag']) and \
                    len(q) > (1+len(self.PREFIXES['useflag'])):
                    default_searches = ["useflag"]
                    searching_default = False
                    q = q[len(self.PREFIXES['useflag']):]
                    if not q.strip():
                        return _redirect_to_home()
                elif q.startswith(self.PREFIXES['library']) and \
                    len(q) > (4+len(self.PREFIXES['library'])):
                    default_searches = ["library"]
                    searching_default = False
                    q = q[len(self.PREFIXES['library']):]
                    if not q.strip():
                        return _redirect_to_home()
                elif q.startswith(self.PREFIXES['provided_library']) and \
                    len(q) > (4+len(self.PREFIXES['provided_library'])):
                    default_searches = ["provided_library"]
                    searching_default = False
                    q = q[len(self.PREFIXES['provided_library']):]
                    if not q.strip():
                        return _redirect_to_home()

            results = []
            for search in default_searches:
                for q_split in q.split():
                    results.extend([x for x in search_map.get(search)(entropy,
                        q_split, filter_cb = filter_cb) if x not in results])

            # TODO: this can be done earlier using another kind of filter
            # and speed up the query, but in general, those params are not
            # used
            if r is not None:
                results = [x for x in results if x[1] == r]
                searching_default = False
            if a is not None:
                results = [x for x in results if x[2] == a]
                searching_default = False
            if b is not None:
                results = [x for x in results if x[3] == b]
                searching_default = False
            if p is not None:
                results = [x for x in results if x[4] == p]
                searching_default = False

            # caching
            # NOTE: EntropyCacher is not started, so cannot use push()
            if model.config.WEBSITE_CACHING:
                self._cacher.save(cache_key,
                    results, cache_dir = model.config.WEBSITE_CACHE_DIR)

        results_len = len(results)
        if from_pkg > results_len:
            # invalid !
            return _redirect_to_home()

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
            results = self._api_get_similar_packages(entropy, q,
                filter_cb = filter_cb)
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

        self._set_search_time(time.clock(), start_t)
        if request.params.get('more'):
            return self._render('/search_results_area.html')
        return self._render('/index.html')

    def index(self):
        start_t = time.clock()
        self._generate_html_metadata()
        entropy = self._entropy()

        search_pkgs = []
        search_pkgs += self._get_latest_binary_packages(entropy)
        search_pkgs += self._get_latest_source_packages(entropy)
        c.search_pkgs = search_pkgs
        c.search_showing_latest = True

        ugc = self._ugc()
        try:
            data_map = self._get_packages_base_metadata(entropy, ugc,
                search_pkgs)
        finally:
            ugc.disconnect()
            del ugc
        c.packages_data = data_map

        self._set_search_time(time.clock(), start_t)
        return self._render('/index.html', renderer = "html")

    def groups(self):
        start_t = time.clock()
        self._generate_html_metadata()
        c.show_area = "groups"

        entropy = self._entropy()
        c.groups_data = self._api_get_groups(entropy)

        self._set_search_time(time.clock(), start_t)
        return self._render("/index.html", renderer = "html")

    def categories(self):
        start_t = time.clock()
        self._generate_html_metadata()
        c.show_area = "categories"

        entropy = self._entropy()
        c.categories_data = self._api_get_categories(entropy)

        self._set_search_time(time.clock(), start_t)
        return self._render("/index.html", renderer = "html")

    def show_ugc_add(self):

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

        return self._render('/do_ugc_document.html', renderer = "html")

    def ugc_delete(self):
        self._generate_html_metadata()
        self._generate_login_metadata()

        user_id = self._get_logged_user_id()
        if not user_id:
            return "%s: %s" % (_("Error"), _("not logged in"),)

        try:
            iddoc = int(request.params.get('iddoc'))
        except (ValueError,TypeError,):
            return "%s: %s" % (_("Error"), _("invalid document"),)

        ugc = self._ugc()
        try:
            iddoc_user_id = ugc.get_iddoc_userid(iddoc)
            if iddoc_user_id is None:
                return "%s: %s" % (_("Error"), _("invalid document specified"),)
            elif (iddoc_user_id != user_id) and not \
                (c.is_user_administrator or c.is_user_moderator):
                return "%s: %s" % (_("Error"), _("permission denied!"),)

            try:
                doctype = int(ugc.get_iddoctype(iddoc))
            except (ValueError,TypeError,):
                doctype = -1
            if doctype == -1:
                return "%s: %s" % (_("Error"), _("WTF? invalid document type!"),)

            status, err_msg = ugc.remove_document_autosense(iddoc, doctype)
        finally:
            ugc.disconnect()
            del ugc
        if status is None:
            return "%s: %s" % (_("Error"),
                _("you know what? I cannot handle this document"),)
        if not status: return '%s: %s' % (
            _("Error"), err_msg,)

        return _('Document removed successfully, sigh :\'-(')


    def ugc_add(self):
        self._generate_html_metadata()
        self._generate_login_metadata()

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
                # two is better than lstrip :P
                orig_filename = os.path.basename(docfile.filename.lstrip(os.sep))
            except AttributeError:
                return '%s: %s' % (
                    _("Error"), request.POST,)
            tmp_fd, tmp_file = tempfile.mkstemp(dir = model.config.WEBSITE_TMP_DIR)
            with os.fdopen(tmp_fd, "wb") as tmp_f:
                shutil.copyfileobj(docfile.file, tmp_f)
                docfile.file.close()
                tmp_f.flush()
                fsize = tmp_f.tell()
            # we already check this server side, in
            # middleware.py, two is better than none
            if fsize > model.config.UGC_MAX_UPLOAD_FILE_SIZE:
                os.remove(tmp_file)
                return "%s: %s" % (_("Error"), _("file too big"),)
            file_name = os.path.join(pkgkey,orig_filename)

        # now handle the UGC add
        ugc = self._ugc()
        try:
            status, iddoc = ugc.insert_document_autosense(pkgkey, doctype, user_id,
                username, comment_text, tmp_file, file_name, orig_filename, title,
                description, keywords)
            if not status:
                return '%s: %s' % (_("Error"), iddoc,)
            if not isinstance(iddoc, int):
                return '%s %s' % (
                    "%s: %s" % (_("Error"),
                    _("document added but couldn't determine 'iddoc' correctly"),), iddoc,)

            c.ugc_doc = {}
            ugc_data = ugc.get_ugc_metadata_by_identifiers([iddoc])
            if ugc_data:
                c.ugc_doc = ugc_data[0]
            self._expand_ugc_doc_metadata(ugc, c.ugc_doc)
        finally:
            ugc.disconnect()
            del ugc
        return self._render('/ugc_show_doc.html', renderer = "html")

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
        return self._render('/ugc_voted.html', renderer = "html")
