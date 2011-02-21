# -*- coding: utf-8 -*-
import logging
import json
from datetime import datetime
from cStringIO import StringIO

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

        if request.params.get("api") == "0":
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
            ugc = self._ugc()
            ugc_cache = {}
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

        return self._render('/index.html', renderer = "html")

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

        query = self.PREFIXES['mime'] + " ".join(provided_mime)
        return self.quicksearch(q = query)

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
            key_sorter = lambda x: entropy_tools.dep_getkey(x)
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
        sha = hashlib.sha256()
        hash_str = "%s|%s|%s|%s|%s" % (
            repository_id, arch, branch, product,
            self._get_valid_repositories_mtime_hash(entropy))
        sha.update(hash_str)
        cache_key = "_show_reverse_dependencies_" + sha.hexdigest()
        revdep_cache = None

        if model.config.WEBSITE_CACHING:
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
                        return entropy_tools.dep_getkey(atom)
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
                provided_libs = repo.retrieveNeeded(package_id)
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
            "content": self._show_content,
            "download": self._show_download,
            "sources": self._show_sources,
        }

        func = what_map.get(what, what_map.get("__fallback__"))
        return func(hash_id)

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

    def quicksearch(self, q = None):
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
        """

        if q is None:
            q = request.params.get('q')
        if not q.strip():
            return redirect(url("/"))
        if len(q) > 64:
            return redirect(url("/"))
        elif len(q) < 2:
            return redirect(url("/"))

        # no need to validate them, already validated below
        # use r, a, b, p as filter
        r = request.params.get('r')
        a = request.params.get('a')
        b = request.params.get('b')
        p = request.params.get('p')
        t = request.params.get('t')

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
        sha = hashlib.sha256()
        sha.update(const_convert_to_rawstring(q))
        sha.update(repr(r))
        sha.update(repr(a))
        sha.update(repr(b))
        sha.update(repr(p))
        mtime_hash = self._get_valid_repositories_mtime_hash(entropy)
        sha.update(mtime_hash)
        cache_key = "quicksearch_" + sha.hexdigest()
        results = None
        if model.config.WEBSITE_CACHING:
            results = self._cacher.pop(cache_key,
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
                        return redirect(url("/"))
                elif q.startswith(self.PREFIXES['category']) and \
                    len(q) > (5+len(self.PREFIXES['mime'])):
                    default_searches = ["category"]
                    searching_default = False
                    q = q[len(self.PREFIXES['category']):]
                    if not q.strip():
                        return redirect(url("/"))
                elif q.startswith(self.PREFIXES['license']) and \
                    len(q) > (2+len(self.PREFIXES['license'])):
                    default_searches = ["license"]
                    searching_default = False
                    q = q[len(self.PREFIXES['license']):]
                    if not q.strip():
                        return redirect(url("/"))
                elif q.startswith(self.PREFIXES['useflag']) and \
                    len(q) > (1+len(self.PREFIXES['useflag'])):
                    default_searches = ["useflag"]
                    searching_default = False
                    q = q[len(self.PREFIXES['useflag']):]
                    if not q.strip():
                        return redirect(url("/"))
                elif q.startswith(self.PREFIXES['library']) and \
                    len(q) > (4+len(self.PREFIXES['library'])):
                    default_searches = ["library"]
                    searching_default = False
                    q = q[len(self.PREFIXES['library']):]
                    if not q.strip():
                        return redirect(url("/"))

            results = []
            for search in default_searches:
                for q_split in q.split():
                    results.extend([x for x in search_map.get(search)(entropy,
                        q_split) if x not in results])

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
        return self._render('/index.html')

    def index(self):
        self._generate_html_metadata()
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

        return self._render('/index.html', renderer = "html")

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

        return self._render('/packages/do_document_page.html', renderer = "html")

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
        return self._render('/packages/ugc_show_doc.html', renderer = "html")

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
        return self._render('/packages/voted.html', renderer = "html")
