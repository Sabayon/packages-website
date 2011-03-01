# -*- coding: utf-8 -*-
import base64
import urllib
import hashlib
import os
import re
import time

from pylons import tmpl_context as c
from pylons import app_globals as g
from pylons import cache, config, request, response, session, url
from pylons.controllers import WSGIController
from pylons.controllers.util import abort, etag_cache, redirect
from pylons.decorators import jsonify, validate
from pylons.i18n import _, ungettext, N_
from pylons.templating import render
from paste.request import construct_url

import www.model as model
from entropy.exceptions import SystemDatabaseError
try:
    from entropy.db.exceptions import ProgrammingError, OperationalError, \
        DatabaseError
except ImportError:
    from sqlite3.dbapi2 import ProgrammingError, OperationalError, \
        DatabaseError

from entropy.const import const_convert_to_unicode, \
    const_convert_to_rawstring, ETP_ARCH_MAP
import entropy.tools as entropy_tools
from entropy.cache import EntropyCacher
from entropy.i18n import _LOCALE

GROUP_ICONS_MAP = {
    'accessibility': "preferences-desktop-accessibility.png",
    'development': "applications-development.png",
    'games': "applications-games.png",
    'gnome': "gnome.png",
    'kde': "kde.png",
    'lxde': "lxde.png",
    'multimedia': "applications-multimedia.png",
    'networking': "applications-internet.png",
    'office': "applications-office.png",
    'science': "applications-accessories.png",
    'security': "software-update-urgent.png",
    'system': "preferences-system.png",
    'x11': "x11.png",
    'xfce': "xfce.png",
    '__fallback__': "applications-other.png",
}

class ApibaseController:

    def __init__(self):
        """
        This class will do little to none input validation, make sure
        that your data is properly input validated (using self._*_re
        objects) before calling these methods.
        """
        import www.model.Entropy
        import www.model.UGC
        self._ugc = www.model.UGC.UGC
        self._entropy = www.model.Entropy.Entropy
        self._cacher = EntropyCacher()
        # same as hostname regexp
        # repository_id validation rule
        self._repo_re = re.compile("^(([a-zA-Z]|[a-zA-Z][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z]|[A-Za-z][A-Za-z0-9\-]*[A-Za-z0-9])$", re.IGNORECASE)

    def _get_available_branches(self, entropy, repoid, product):
        arches = self._get_available_arches(entropy, repoid, product)
        branches = set()
        for arch in arches:
            branches |= set(entropy._get_branches(repoid, arch, product))
        return sorted(branches, reverse = True)

    def _get_available_repositories(self, entropy, product, arch):
        return entropy._get_repositories(product, arch)

    def _get_available_arches(self, entropy, repoid, product):
        return entropy._get_arches(repoid, product)

    def _api_get_repo(self, entropy, repository_id, arch, branch, product):
        """
        Internal method, stay away.
        """
        mtime = self._get_valid_repository_mtime(entropy, repository_id,
            arch, branch, product)
        sha = hashlib.sha1()
        hash_str = "%s:%s:%s:%s:%s" % (
            repository_id, arch, branch, product, repr(mtime))
        sha.update(hash_str)
        cache_key = "_api_get_repo_" + sha.hexdigest()
        validated = self._cacher.pop(cache_key,
            cache_dir = model.config.WEBSITE_CACHE_DIR)

        try:
            dbconn = entropy._open_db(repository_id, arch, product, branch)
            if validated is None:
                dbconn.validate()
                self._cacher.save(cache_key, True,
                    cache_dir = model.config.WEBSITE_CACHE_DIR)
            return dbconn
        except (ProgrammingError, OperationalError, SystemDatabaseError):
            try:
                dbconn.close()
            except:
                pass
            return None

    def _api_get_params(self, entropy = None):
        """
        Return a tuple composed by repository, arch, branch, product
        """
        if entropy is None:
            entropy = self._entropy()
        # arch
        a = request.params.get('a') or model.config.default_arch
        if a not in model.config.available_arches:
            a = model.config.default_arch

        # product
        p = request.params.get('p') or model.config.default_product
        if p not in model.config.available_products:
            p = model.config.default_product

        avail_repos = self._get_available_repositories(entropy, p, a)
        # repository
        r = request.params.get('r') or model.config.ETP_REPOSITORY
        if r not in avail_repos:
            r = None

        # validate arch
        if r is not None:
            avail_arches = self._get_available_arches(entropy, r, p)
            if a not in avail_arches:
                a = None

        # validate branch
        b = None
        if r is not None:
            b = request.params.get('b') or model.config.default_branch
            if b not in self._get_available_branches(entropy, r, p):
                b = None

        order_by_types = ["alphabet", "vote", "downloads"]
        # order by
        o = request.params.get('o') or "alphabet"
        if o not in order_by_types:
            o = "alphabet"

        return r, a, b, p, o

    def _api_encode_package(self, package_id, repository_id, a, b, p):
        """
        Encode a full blown package tuple into a serializable string, base64
        is using as encoder.

        @param package_id: package identifier
        @type package_id: int
        @param repository_id: repository identifier
        @type repository_id: string
        @param a: arch string
        @type a: string
        @param b: branch string
        @type b: string
        @param p: product string
        @type p: string
        """
        id_str = " ".join((str(package_id), repository_id, a, b, p))
        return base64.urlsafe_b64encode(id_str)

    def _api_decode_package(self, encoded_id_str):
        """
        Decode a base64 encoded package hash back into a full blown package
        tuple.

        @param encoded_id_str: package hash base64 encoded
        @type: string
        @return: tuple composed by (package_id, repository_id, arch, branch, product)
        @rtype: tuple
        """
        id_str = base64.urlsafe_b64decode(
            const_convert_to_rawstring(encoded_id_str, from_enctype = "utf-8"))
        try:
            package_id, repository_id, a, b, p = id_str.split()
            package_id = int(package_id)
        except ValueError:
            return None
        return package_id, repository_id, a, b, p

    def _api_human_encode_package(self, name, package_id, repository_id, a, b, p):
        """
        Encode a full blown package tuple into a human-readable string.

        @param name: package name
        @type name: string
        @param package_id: package identifier
        @type package_id: int
        @param repository_id: repository identifier
        @type repository_id: string
        @param a: arch string
        @type a: string
        @param b: branch string
        @type b: string
        @param p: product string
        @type p: string
        """
        id_str = ",".join((name, str(package_id), repository_id, a, b, p))
        return id_str

    def _api_human_decode_package(self, encoded_id_str):
        """
        Decode a human-encoded package hash back into a full blown package
        tuple.

        @param encoded_id_str: human-encoded package hash
        @type: string
        @return: tuple composed by (name, package_id, repository_id, arch, branch, product)
        @rtype: tuple
        """
        try:
            name, package_id, repository_id, a, b, p = encoded_id_str.split(",")
            package_id = int(package_id)
        except ValueError:
            return None
        return name, package_id, repository_id, a, b, p

    def _api_get_groups(self, entropy):
        """
        Return Package Groups available.
        """
        spm_class = entropy.Spm_class()
        groups = spm_class.get_package_groups().copy()
        for group_name, group_value in groups.items():
            group_value['icon'] = GROUP_ICONS_MAP.get(group_name,
                GROUP_ICONS_MAP['__fallback__'])
        return groups

    def _api_category_to_group(self, entropy, category):
        """
        Given a package category, it returns the package group from where
        it belongs. Return None if no group is bound to given category.
        """
        spm_class = entropy.Spm_class()
        groups = spm_class.get_package_groups()
        for group, g_data in groups.items():
            for cat in g_data['categories']:
                if category.startswith(cat):
                    return group
                    break
        # if we get here, means there is no group matching
        return None

    def _api_get_categories(self, entropy):
        """
        Return Package Categories available.
        """
        if model.config.WEBSITE_CACHING:
            sha = hashlib.sha1()
            sha.update(self._get_valid_repositories_mtime_hash(entropy))
            cache_key = "_api_get_categories_" + sha.hexdigest()
            data = self._cacher.pop(cache_key,
                cache_dir = model.config.WEBSITE_CACHE_DIR)
            if data is not None:
                return data

        categories = set()
        category_descriptions = {}
        valid_repos = self._api_get_valid_repositories(entropy)
        for repository_id, arch, branch, product in valid_repos:
            repo = self._api_get_repo(entropy, repository_id, arch, branch,
                product)
            try:
                if repo is not None:
                    mycats = repo.listAllCategories()
                    categories.update(mycats)
                    for mycat in mycats:
                        if mycat in category_descriptions:
                            continue
                        cat_desc = None
                        desc_map = repo.retrieveCategoryDescription(mycat)
                        if _LOCALE in desc_map:
                            cat_desc = desc_map[_LOCALE]
                        elif 'en' in desc_map:
                            cat_desc = desc_map['en']
                        if cat_desc is not None:
                            category_descriptions[mycat] = cat_desc

            finally:
                if repo is not None:
                    repo.close()

        categories = sorted(categories)
        data = []
        for category in categories:
            obj = {
                'name': category,
                'icon': self._api_get_category_icon(entropy, category),
                'description': category_descriptions.get(category,
                    _("No description")),
            }
            data.append(obj)

        if model.config.WEBSITE_CACHING:
            self._cacher.save(cache_key, data,
                cache_dir = model.config.WEBSITE_CACHE_DIR)

        return data

    def _api_get_category_icon(self, entropy, category):
        """
        Given a package category, return the icon name associated.
        This method always return a valid icon name. A fallback icon can be used.
        """
        group = self._api_category_to_group(entropy, category)
        if group is None:
            return GROUP_ICONS_MAP['__fallback__']
        return self._api_get_group_icon(group)

    def _api_get_group_icon(self, group):
        """
        Given a package group, return the icon name associated.
        This method always return a valid icon name. A fallback icon can be used.
        """
        return GROUP_ICONS_MAP.get(group, GROUP_ICONS_MAP['__fallback__'])

    def _api_extract_latest_change(self, package_atom, changelog):
        """
        Given a changelog (standard changelog format) extract latest change
        message.
        """
        if not changelog:
            return None
        category, namever = package_atom.split("/", 1)
        in_line = False
        ch_lines = []
        for ch_line in changelog.split("\n"):
            if ch_line.startswith("*%s" % (namever,)) and not in_line:
                in_line = True
                continue
            elif ch_line.startswith("*") and in_line:
                break
            if in_line:
                ch_lines.append(ch_line)

        found_something = False
        go_read = False
        final_lines = []
        for ch_line in ch_lines:
            if ch_line.strip():
                found_something = True
            elif found_something and not ch_line.strip():
                break
            if ch_line.endswith(":"):
                go_read = True
                continue
            if go_read:
                final_lines.append(ch_line.strip())

        if final_lines:
            return ' '.join(final_lines)
        return None

    def _api_get_valid_repositories(self, entropy, validate = False):
        """
        Given supported products and arches (see model.config.py), return
        a list of valid (available) repository tuples
        (repo_id, arch, branch, product). If validate is True, repositories
        will be opened and validation tested.
        """
        products = sorted(model.config.available_products.keys())
        arches = sorted(model.config.available_arches.keys())

        valid_list = []
        for product in products:
            for arch in arches:
                avail_repos = self._get_available_repositories(entropy,
                    product, arch)
                for avail_repo in avail_repos:
                    avail_branches = self._get_available_branches(entropy,
                        avail_repo, product)
                    for avail_branch in avail_branches:
                        valid_list.append((avail_repo, arch, avail_branch,
                            product))

        if not validate:
            return valid_list

        def _repo_filter(item):
            repo_id, arch, branch, product = item
            repo = self._api_get_repo(entropy, repo_id, arch, branch, product)
            try:
                return (repo is not None)
            finally:
                if repo is not None:
                    repo.close()

        return list(filter(_repo_filter, valid_list))

    def _api_search_pkg(self, entropy, q, filter_cb = None):
        """
        Search packages in repositories using given query string.

        @param q: query string
        @type q: string
        @keyword filter_cb: callback used to filter results, the function
            must have this signature:
                bool filter_cb(entropy_repository, package_id)
            and return True if package is valid, False otherwise.
        @type filter_cb: callable
        @return: list of package tuples (pkg_id, repo, arch, branch, product)
        @rtype: list
        """
        data = []
        valid_repos = self._api_get_valid_repositories(entropy)
        for repository_id, arch, branch, product in valid_repos:
            repo = self._api_get_repo(entropy, repository_id, arch, branch,
                product)
            try:
                if repo is not None:
                    pkg_ids = repo.searchPackages(q, order_by = "atom",
                        just_id = True)
                    if filter_cb is not None:
                        pkg_ids = [pkg_id for pkg_id in pkg_ids if \
                            filter_cb(repo, pkg_id)]
                    data.extend((pkg_id, repository_id, arch, branch, product) \
                        for pkg_id in pkg_ids)
            finally:
                if repo is not None:
                    repo.close()
        return data

    def _api_search_desc(self, entropy, q, filter_cb = None):
        """
        Search packages in repositories using given query string
        (description strategy).

        @param q: query string
        @type q: string
        @keyword filter_cb: callback used to filter results, the function
            must have this signature:
                bool filter_cb(entropy_repository, package_id)
            and return True if package is valid, False otherwise.
        @type filter_cb: callable
        @return: list of package tuples (pkg_id, repo, arch, branch, product)
        @rtype: list
        """
        data = []
        valid_repos = self._api_get_valid_repositories(entropy)
        for repository_id, arch, branch, product in valid_repos:
            repo = self._api_get_repo(entropy, repository_id, arch, branch,
                product)
            try:
                if repo is not None:
                    pkg_ids = repo.searchDescription(q, just_id = True)
                    if filter_cb is not None:
                        pkg_ids = [pkg_id for pkg_id in pkg_ids if \
                            filter_cb(repo, pkg_id)]
                    data.extend((pkg_id, repository_id, arch, branch, product) \
                        for pkg_id in pkg_ids)
            finally:
                if repo is not None:
                    repo.close()
        return data

    def _api_search_lib(self, entropy, q, filter_cb = None):
        """
        Search packages in repositories using given query string
        (library strategy).

        @param q: query string
        @type q: string
        @keyword filter_cb: callback used to filter results, the function
            must have this signature:
                bool filter_cb(entropy_repository, package_id)
            and return True if package is valid, False otherwise.
        @type filter_cb: callable
        @return: list of package tuples (pkg_id, repo, arch, branch, product)
        @rtype: list
        """
        # NOTE: cut results to first 10 items, since this can lead to DDoS
        data = []
        valid_repos = self._api_get_valid_repositories(entropy)
        for repository_id, arch, branch, product in valid_repos:
            if self._is_source_repository(repository_id):
                continue
            repo = self._api_get_repo(entropy, repository_id, arch, branch,
                product)
            try:
                if repo is not None:
                    pkg_ids = repo.searchNeeded(q)
                    if filter_cb is not None:
                        pkg_ids = [pkg_id for pkg_id in pkg_ids if \
                            filter_cb(repo, pkg_id)]
                    data.extend((pkg_id, repository_id, arch, branch, product) \
                        for pkg_id in pkg_ids)
            finally:
                if repo is not None:
                    repo.close()
        return data

    def _api_search_provided_lib(self, entropy, q, filter_cb = None):
        """
        Search packages in repositories using given query string
        (provided library strategy).

        @param q: query string
        @type q: string
        @keyword filter_cb: callback used to filter results, the function
            must have this signature:
                bool filter_cb(entropy_repository, package_id)
            and return True if package is valid, False otherwise.
        @type filter_cb: callable
        @return: list of package tuples (pkg_id, repo, arch, branch, product)
        @rtype: list
        """
        # NOTE: cut results to first 10 items, since this can lead to DDoS
        data = []
        valid_repos = self._api_get_valid_repositories(entropy)
        for repository_id, arch, branch, product in valid_repos:
            if self._is_source_repository(repository_id):
                continue
            repo = self._api_get_repo(entropy, repository_id, arch, branch,
                product)
            try:
                if repo is not None:
                    pkg_ids = repo.resolveNeeded(q)
                    if filter_cb is not None:
                        pkg_ids = [pkg_id for pkg_id in pkg_ids if \
                            filter_cb(repo, pkg_id)]
                    data.extend((pkg_id, repository_id, arch, branch, product) \
                        for pkg_id in pkg_ids)
            finally:
                if repo is not None:
                    repo.close()
        return data

    def _api_search_path(self, entropy, q, filter_cb = None):
        """
        Search packages in repositories using given query string
        (content strategy).

        @param q: query string
        @type q: string
        @keyword filter_cb: callback used to filter results, the function
            must have this signature:
                bool filter_cb(entropy_repository, package_id)
            and return True if package is valid, False otherwise.
        @type filter_cb: callable
        @return: list of package tuples (pkg_id, repo, arch, branch, product)
        @rtype: list
        """
        data = []
        valid_repos = self._api_get_valid_repositories(entropy)
        for repository_id, arch, branch, product in valid_repos:
            if self._is_source_repository(repository_id):
                continue
            repo = self._api_get_repo(entropy, repository_id, arch, branch,
                product)
            try:
                if repo is not None:
                    pkg_ids = repo.searchBelongs(q)
                    if filter_cb is not None:
                        pkg_ids = [pkg_id for pkg_id in pkg_ids if \
                            filter_cb(repo, pkg_id)]
                    data.extend((pkg_id, repository_id, arch, branch, product) \
                        for pkg_id in pkg_ids)
            finally:
                if repo is not None:
                    repo.close()
        return data

    def _api_search_sets(self, entropy, q, filter_cb = None):
        """
        Search packages in repositories using given query string
        (sets strategy).

        @param q: query string
        @type q: string
        @keyword filter_cb: callback used to filter results, the function
            must have this signature:
                bool filter_cb(entropy_repository, package_id)
            and return True if package is valid, False otherwise.
        @type filter_cb: callable
        @return: list of package tuples (pkg_id, repo, arch, branch, product)
        @rtype: list
        """
        data = []
        valid_repos = self._api_get_valid_repositories(entropy)
        for repository_id, arch, branch, product in valid_repos:
            if self._is_source_repository(repository_id):
                continue
            repo = self._api_get_repo(entropy, repository_id, arch, branch,
                product)
            try:
                if repo is not None:
                    pkgs = repo.retrievePackageSet(q[1:])
                    pkg_ids = set()
                    for pkg in pkgs:
                        pkg_id, rc = repo.atomMatch(pkg)
                        if pkg_id != -1:
                            pkg_ids.add(pkg_id)
                    if filter_cb is not None:
                        pkg_ids = [pkg_id for pkg_id in pkg_ids if \
                            filter_cb(repo, pkg_id)]
                    data.extend((pkg_id, repository_id, arch, branch, product) \
                        for pkg_id in pkg_ids)
            finally:
                if repo is not None:
                    repo.close()
        return data

    def _api_search_mime(self, entropy, q, filter_cb = None):
        """
        Search packages in repositories using given query string
        (mimetype strategy).

        @param q: query string
        @type q: string
        @keyword filter_cb: callback used to filter results, the function
            must have this signature:
                bool filter_cb(entropy_repository, package_id)
            and return True if package is valid, False otherwise.
        @type filter_cb: callable
        @return: list of package tuples (pkg_id, repo, arch, branch, product)
        @rtype: list
        """
        data = []
        valid_repos = self._api_get_valid_repositories(entropy)
        for repository_id, arch, branch, product in valid_repos:
            if self._is_source_repository(repository_id):
                continue
            repo = self._api_get_repo(entropy, repository_id, arch, branch,
                product)
            try:
                if repo is not None:
                    pkg_ids = repo.searchProvidedMime(q)
                    if filter_cb is not None:
                        pkg_ids = [pkg_id for pkg_id in pkg_ids if \
                            filter_cb(repo, pkg_id)]
                    data.extend((pkg_id, repository_id, arch, branch, product) \
                        for pkg_id in pkg_ids)
            finally:
                if repo is not None:
                    repo.close()
        return data

    def _api_search_category(self, entropy, q, filter_cb = None):
        """
        Search packages in repositories using given query string
        (category strategy).

        @param q: query string
        @type q: string
        @keyword filter_cb: callback used to filter results, the function
            must have this signature:
                bool filter_cb(entropy_repository, package_id)
            and return True if package is valid, False otherwise.
        @type filter_cb: callable
        @return: list of package tuples (pkg_id, repo, arch, branch, product)
        @rtype: list
        """
        data = []
        valid_repos = self._api_get_valid_repositories(entropy)
        for repository_id, arch, branch, product in valid_repos:
            repo = self._api_get_repo(entropy, repository_id, arch, branch,
                product)
            try:
                if repo is not None:
                    pkg_ids = repo.searchCategory(q, just_id = True)
                    if filter_cb is not None:
                        pkg_ids = [pkg_id for pkg_id in pkg_ids if \
                            filter_cb(repo, pkg_id)]
                    data.extend((pkg_id, repository_id, arch, branch, product) \
                        for pkg_id in pkg_ids)
            finally:
                if repo is not None:
                    repo.close()
        return data

    def _api_search_group(self, entropy, q, filter_cb = None):
        """
        Search packages in repositories using given query string
        (group strategy).

        @param q: query string
        @type q: string
        @keyword filter_cb: callback used to filter results, the function
            must have this signature:
                bool filter_cb(entropy_repository, package_id)
            and return True if package is valid, False otherwise.
        @type filter_cb: callable
        @return: list of package tuples (pkg_id, repo, arch, branch, product)
        @rtype: list
        """
        spm_class = entropy.Spm_class()
        groups = spm_class.get_package_groups()
        if q not in groups:
            return []

        group_data = groups[q]
        categories = group_data['categories']

        data = []
        valid_repos = self._api_get_valid_repositories(entropy)
        for repository_id, arch, branch, product in valid_repos:
            repo = self._api_get_repo(entropy, repository_id, arch, branch,
                product)
            try:
                if repo is not None:
                    repo_categories = repo.listAllCategories()
                    expanded_cats = set()
                    for g_cat in categories:
                        expanded_cats.update([x for x in repo_categories if \
                            x.startswith(g_cat)])
                    pkg_ids = set()
                    for cat in sorted(expanded_cats):
                        pkg_ids |= repo.searchCategory(cat, just_id = True)
                    if filter_cb is not None:
                        pkg_ids = [pkg_id for pkg_id in pkg_ids if \
                            filter_cb(repo, pkg_id)]
                    data.extend((pkg_id, repository_id, arch, branch, product) \
                        for pkg_id in pkg_ids)
            finally:
                if repo is not None:
                    repo.close()
        return data

    def _api_search_license(self, entropy, q, filter_cb = None):
        """
        Search packages in repositories using given query string
        (license strategy).

        @param q: query string
        @type q: string
        @keyword filter_cb: callback used to filter results, the function
            must have this signature:
                bool filter_cb(entropy_repository, package_id)
            and return True if package is valid, False otherwise.
        @type filter_cb: callable
        @return: list of package tuples (pkg_id, repo, arch, branch, product)
        @rtype: list
        """
        data = []
        valid_repos = self._api_get_valid_repositories(entropy)
        for repository_id, arch, branch, product in valid_repos:
            repo = self._api_get_repo(entropy, repository_id, arch, branch,
                product)
            try:
                if repo is not None:
                    pkg_ids = repo.searchLicense(q, just_id = True)
                    if filter_cb is not None:
                        pkg_ids = [pkg_id for pkg_id in pkg_ids if \
                            filter_cb(repo, pkg_id)]
                    data.extend((pkg_id, repository_id, arch, branch, product) \
                        for pkg_id in pkg_ids)
            finally:
                if repo is not None:
                    repo.close()
        return data

    def _api_search_useflag(self, entropy, q, filter_cb = None):
        """
        Search packages in repositories using given query string
        (useflag strategy).

        @param q: query string
        @type q: string
        @keyword filter_cb: callback used to filter results, the function
            must have this signature:
                bool filter_cb(entropy_repository, package_id)
            and return True if package is valid, False otherwise.
        @type filter_cb: callable
        @return: list of package tuples (pkg_id, repo, arch, branch, product)
        @rtype: list
        """
        data = []
        valid_repos = self._api_get_valid_repositories(entropy)
        for repository_id, arch, branch, product in valid_repos:
            repo = self._api_get_repo(entropy, repository_id, arch, branch,
                product)
            try:
                if repo is not None:
                    pkg_ids = repo.searchUseflag(q, just_id = True)
                    if filter_cb is not None:
                        pkg_ids = [pkg_id for pkg_id in pkg_ids if \
                            filter_cb(repo, pkg_id)]
                    data.extend((pkg_id, repository_id, arch, branch, product) \
                        for pkg_id in pkg_ids)
            finally:
                if repo is not None:
                    repo.close()
        return data

    def _api_search_match(self, entropy, q, filter_cb = None):
        """
        Search packages in repositories using given query string (match strategy).

        @param q: query string
        @type q: string
        @keyword filter_cb: callback used to filter results, the function
            must have this signature:
                bool filter_cb(entropy_repository, package_id)
            and return True if package is valid, False otherwise.
        @type filter_cb: callable
        @return: list of package tuples (pkg_id, repo, arch, branch, product)
        @rtype: list
        """
        data = []
        valid_repos = self._api_get_valid_repositories(entropy)
        for repository_id, arch, branch, product in valid_repos:
            repo = self._api_get_repo(entropy, repository_id, arch, branch,
                product)
            try:
                if repo is not None:
                    pkg_ids, rc = repo.atomMatch(q, multiMatch = True)
                    if filter_cb is not None:
                        pkg_ids = [pkg_id for pkg_id in pkg_ids if \
                            filter_cb(repo, pkg_id)]
                    data.extend((pkg_id, repository_id, arch, branch, product) \
                        for pkg_id in pkg_ids)
            finally:
                if repo is not None:
                    repo.close()
        return data

    def _api_get_similar_packages(self, entropy, q, filter_cb = None):
        """
        Return a list of similar package tuples given search term "q".

        @param q: query string
        @type q: string
        @keyword filter_cb: callback used to filter results, the function
            must have this signature:
                bool filter_cb(entropy_repository, package_id)
            and return True if package is valid, False otherwise.
        @type filter_cb: callable
        @return: list of package tuples (pkg_id, repo, arch, branch, product)
        @rtype: list
        """
        data = []
        valid_repos = self._api_get_valid_repositories(entropy)
        for repository_id, arch, branch, product in valid_repos:
            repo = self._api_get_repo(entropy, repository_id, arch, branch,
                product)
            try:
                if repo is not None:
                    pkg_ids = [x[0] for x in entropy.get_meant_packages(q,
                            valid_repos = [repo])]
                    if filter_cb is not None:
                        pkg_ids = [pkg_id for pkg_id in pkg_ids if \
                            filter_cb(repo, pkg_id)]
                    data.extend((pkg_id, repository_id, arch, branch, product) \
                        for pkg_id in pkg_ids)
            finally:
                if repo is not None:
                    repo.close()
        return data

    def _is_source_repository(self, repository_id):
        """
        Return whether given repository identifier is belonging to a source-based
        repository.

        @param repository_id: repository identifier
        @type repository_id: string
        """
        return repository_id in model.config.source_repositories

    def _get_ugc_base_metadata(self, entropy, ugc, repository_id, package_key):
        """
        Get basic User Generated Metadata for given package key using given
        UGC interface.
        """
        c_data = model.config.community_repos_ugc_connection_data.get(
            repository_id)
        if c_data is None:
            c_data = model.config.ugc_connection_data
        if c_data is None:
            return None

        data = {
            'vote': ugc.get_ugc_vote(package_key),
            'downloads': int(ugc.get_ugc_downloads(package_key)),
            'icon': ugc.get_ugc_icon(package_key),
            'category_icon': self._api_get_category_icon(entropy,
                package_key.split("/", 1)[0])
        }
        return data

    def _expand_ugc_doc_metadata(self, ugc, doc):
        if doc.get('userid'):
            doc['score'] = ugc.get_user_score(doc['userid'])
        if doc.get('size'):
            doc['size'] = entropy_tools.bytes_into_human(doc.get('size'))

    def _get_ugc_extended_metadata(self, ugc, package_key):
        """
        Get extended User Generated Metadata for given package key using given
        UGC interface.
        """
        data = {
            'vote': ugc.get_ugc_vote(package_key),
            'downloads': ugc.get_ugc_downloads(package_key),
            'docs': ugc.get_ugc_metadata_doctypes(package_key,
                [ugc.DOC_TYPES[x] for x in ugc.DOC_TYPES]),
        }
        for doc in data['docs']:
            self._expand_ugc_doc_metadata(ugc, doc)
        return data

    def _get_valid_repository_mtime(self, entropy, repository_id,
        arch, branch, product):
        """
        Return the mtime of a given repository.
        """
        path = entropy._guess_repo_db_path(repository_id, arch, product,
            branch)
        if path is not None:
            try:
                mtime = os.path.getmtime(path)
            except (OSError, IOError):
                mtime = 0.0
        else:
            mtime = 0.0
        return mtime

    def _get_valid_repositories_mtime_hash(self, entropy):
        """
        Return a hash which is bound to repositories mtime. Whenever a
        repository is updated, the returned data changes. So, this can be used
        for cache validation for those repositories-wide functions.
        """
        valid_repos = self._api_get_valid_repositories(entropy)
        sha = hashlib.sha1()
        sha.update("0.0")
        for avail_repo, arch, branch, product in valid_repos:
            mtime = self._get_valid_repository_mtime(entropy, avail_repo,
                arch, branch, product)
            sha.update(repr(mtime))
        return sha.hexdigest()

    def _get_latest_binary_packages(self, entropy, max_count = 10):
        """
        Get a list of package tuples corresponding to latest binary packages.
        """
        return self._get_latest_repo_type_packages(entropy, False, max_count)

    def _get_latest_source_packages(self, entropy, max_count = 10):
        """
        Get a list of package tuples corresponding to latest source packages.
        """
        return self._get_latest_repo_type_packages(entropy, True, max_count)

    def _get_latest_repo_type_packages(self, entropy, want_source_repo,
        max_count):
        # validate input
        if max_count >= 100:
            max_count = 100

        products = sorted(model.config.available_products.keys())
        arches = sorted(model.config.available_arches.keys())

        # caching
        if model.config.WEBSITE_CACHING:
            sha = hashlib.sha1()
            hash_str = "%s|%s|%s|%s|%s" % (
                want_source_repo,
                max_count,
                products,
                arches,
                self._get_valid_repositories_mtime_hash(entropy),
            )
            sha.update(repr(hash_str))
            cache_key = "_get_latest_repo_type_packages3_" + sha.hexdigest()
            data = self._cacher.pop(cache_key,
                cache_dir = model.config.WEBSITE_CACHE_DIR)
            if data is not None:
                return data

        raw_latest = []
        valid_repos = self._api_get_valid_repositories(entropy)
        for avail_repo, arch, branch, product in valid_repos:
            is_source_repo = self._is_source_repository(avail_repo)
            if want_source_repo and not is_source_repo:
                continue
            if (not want_source_repo) and is_source_repo:
                continue
            raw_latest.extend(self._get_latest_repo_packages(
                entropy, avail_repo, arch, branch,
                product, max_count))

        def key_sorter(x):
            try:
                return float(x[0])
            except (TypeError, ValueError):
                return 0.0

        pkgs = sorted(raw_latest, key = key_sorter, reverse = True)
        if len(pkgs) > max_count:
            pkgs = pkgs[:max_count]
        data = [(p_id, r, a, b, p) for cdate, p_id, r, a, b, p in pkgs]

        if model.config.WEBSITE_CACHING:
            self._cacher.save(cache_key, data,
                cache_dir = model.config.WEBSITE_CACHE_DIR)

        return data

    def _get_latest_repo_packages(self, entropy, repository_id,
        arch, branch, product, count):
        """
        Get a list of latest packages in repository.
        """
        repo = self._api_get_repo(entropy, repository_id, arch, branch, product)
        try:
            if repo is None:
                return []
            pkg_ids = repo.listAllPackageIds(order_by="package_id")[-count:]
            return [(repo.retrieveCreationDate(x), x, repository_id, arch,
                branch, product) for x in pkg_ids]
        except (OperationalError, DatabaseError):
            return []
        finally:
            if repo is not None:
                repo.close()

    def __generate_action_url(self, hash_id, target):
        return "%s/%s/%s" % (model.config.PACKAGE_SHOW_URL, hash_id, target)

    def __get_metadata_install_app_item(self, hash_id):
        return {
            'id': "install",
            'name': _("Install (beta)"),
            'icon': "media-optical.png",
            'url': self.__generate_action_url(hash_id, "install"),
            'alt': _("Install this application"),
            'extra_url_meta': "rel=\"nofollow\"",
        }

    def _setup_metadata_items(self, entropy, package_id, repository_id,
        arch, hash_id, is_source_repo, package_key, entropy_repository,
        short_list = True):
        """
        This cryptic method setups a simple list of links (and their metadata)
        that are shown right below the main package information.
        Example links: Homepage, Bugs, etc.

        @return: list of dictionaries
        @rtype: list
        """
        def _generate_action_url(target):
            return self.__generate_action_url(hash_id, target) + \
                "#package-widget-show-what"

        data = []

        obj = {
            'id': "details",
            'name': _("Details"),
            'icon': "icon_image.png",
            'url': _generate_action_url(""),
            'alt': _("Show package details"),
            'extra_url_meta': "rel=\"nofollow\"",
        }
        data.append(obj)

        # homepage
        homepage = entropy_repository.retrieveHomepage(package_id)
        if homepage:
            obj = {
                'id': "homepage",
                'name': _("Homepage"),
                'icon': "icon_homepage.png",
                'url': homepage,
                'alt': _("Visit package homepage"),
                'extra_url_meta': "rel=\"nofollow\"",
            }
            data.append(obj)

        # dependencies
        obj = {
            'id': "dependencies",
            'name': _("Dependencies"),
            'icon': "icon_folder.png",
            'url': _generate_action_url("dependencies"),
            'alt': _("Show package dependencies"),
            'extra_url_meta': "rel=\"nofollow\"",
        }
        data.append(obj)

        # reverse dependencies
        if not short_list:
            obj = {
                'id': "reverse_dependencies",
                'name': _("Reverse Dependencies"),
                'icon': "icon_folder.png",
                'url': _generate_action_url("reverse_dependencies"),
                'alt': _("Show which package requires this application"),
                'extra_url_meta': "rel=\"nofollow\"",
            }
            data.append(obj)

        # ugc
        obj = {
            'id': "ugc",
            'name': _("Comments and Documents"),
            'icon': "icon_images.png",
            'url': _generate_action_url("ugc"),
            'alt': _("Show user-generated content"),
            'extra_url_meta': "rel=\"nofollow\"",
        }
        data.append(obj)

        if not short_list:

            # similar packages
            provided_mime = entropy_repository.retrieveProvidedMime(package_id)
            if provided_mime:
                obj = {
                    'id': "similar",
                    'name': _("Similar"),
                    'icon': "icon_similar.png",
                    'url': _generate_action_url("similar"),
                    'alt': _("Show similar packages"),
                    'extra_url_meta': "rel=\"nofollow\"",
                }
                data.append(obj)

            obj = {
                'id': "changelog",
                'name': _("ChangeLog"),
                'icon': "icon_changelog.png",
                'url': _generate_action_url("changelog"),
                'alt': _("Package ChangeLog"),
                'extra_url_meta': "rel=\"nofollow\"",
            }
            data.append(obj)

            quoted_key = urllib.quote_plus(package_key)
            if not is_source_repo:
                bug_url = "http://bugs.sabayon.org/buglist.cgi?quicksearch=%s" % (
                    quoted_key,)
                obj = {
                    'id': "bugs",
                    'name': _("Sabayon Bugs"),
                    'icon': "icon_bugs.png",
                    'url': bug_url,
                    'alt': _("Sabayon bugs related to package"),
                    'extra_url_meta': "rel=\"nofollow\"",
                }
                data.append(obj)
            # upstream bug
            upstream_bug_url = "http://bugs.gentoo.org/buglist.cgi?quicksearch=%s" % (
                quoted_key,)
            obj = {
                'id': "upstream_bugs",
                'name': _("Upstream bugs"),
                'icon': "icon_bugs.png",
                'url': upstream_bug_url,
                'alt': _("Gentoo bugs related to package"),
                'extra_url_meta': "rel=\"nofollow\"",
            }
            data.append(obj)

            # security
            obj = {
                'id': "security",
                'name': _("Security advisories"),
                'icon': "icon_tag_purple.png",
                'url': _generate_action_url("security"),
                'alt': _("Show security advisories for package"),
                'extra_url_meta': "rel=\"nofollow\"",
            }
            data.append(obj)

            if provided_mime:
                # mime types
                obj = {
                    'id': "mime",
                    'name': _("Mime types"),
                    'icon': "icon_image.png",
                    'url': _generate_action_url("mime"),
                    'alt': _("Show mime types handled by package"),
                    'extra_url_meta': "rel=\"nofollow\"",
                }
                data.append(obj)

            if not is_source_repo:
                # provided libraries
                obj = {
                    'id': "provided_libs",
                    'name': _("Provided libraries"),
                    'icon': "icon_bricks.png",
                    'url': _generate_action_url("provided_libs"),
                    'alt': _("Show libraries provided by package"),
                    'extra_url_meta': "rel=\"nofollow\"",
                }
                data.append(obj)
                # needed libraries
                obj = {
                    'id': "needed_libs",
                    'name': _("Needed libraries"),
                    'icon': "icon_bricks.png",
                    'url': _generate_action_url("needed_libs"),
                    'alt': _("Show libraries needed by package"),
                    'extra_url_meta': "rel=\"nofollow\"",
                }
                data.append(obj)

                # content
                obj = {
                    'id': "content",
                    'name': _("Content"),
                    'icon': "icon_package.png",
                    'url': _generate_action_url("content"),
                    'alt': _("Show files belonging to package"),
                    'extra_url_meta': "rel=\"nofollow\"",
                }
                data.append(obj)
                # download
                obj = {
                    'id': "download",
                    'name': _("Download"),
                    'icon': "icon_disk.png",
                    'url': _generate_action_url("download"),
                    'alt': _("Show package file download mirrors"),
                    'extra_url_meta': "rel=\"nofollow\"",
                }
                data.append(obj)

            # sources
            obj = {
                'id': "sources",
                'name': _("Sources"),
                'icon': "icon_source.png",
                'url': _generate_action_url("sources"),
                'alt': _("Show source code belonging to package"),
                'extra_url_meta': "rel=\"nofollow\"",
            }
            data.append(obj)

        if not is_source_repo:
            if repository_id == model.config.ETP_REPOSITORY:

                try:
                    user_agent = request.environ['HTTP_USER_AGENT']
                except (AttributeError, KeyError):
                    user_agent = None

                # WARNING: hard coded arches!!
                found_arch = "x86"
                if user_agent is not None:
                    if user_agent.find("x86_64") != -1:
                        found_arch = "amd64"
                if found_arch == arch:
                    # install
                    obj = self.__get_metadata_install_app_item(hash_id)
                    obj['url'] += "#package-widget-show-what"
                    data.append(obj)

        return data

    def _get_package_base_metadata(self, entropy, repository_id,
        package_id, arch, product, branch, entropy_repository,
        extended_meta_items = False):
        """
        Internal method used to build up basic metadata for package.
        """
        is_source_repo = self._is_source_repository(repository_id)
        meta_items_hash = 1

        # caching
        sha = hashlib.sha1()
        hash_str = "%s|%s|%s|%s|%s|%s|%s|%s|%s" % (
            repository_id,
            package_id,
            arch,
            product,
            branch,
            extended_meta_items,
            repr(self._get_valid_repository_mtime(entropy, repository_id,
                arch, branch, product)),
            is_source_repo,
            meta_items_hash,
        )
        sha.update(repr(hash_str))
        cache_key = "_get_package_base_metadata_" + sha.hexdigest()

        data = None
        if model.config.WEBSITE_CACHING:
            data = self._cacher.pop(cache_key,
                cache_dir = model.config.WEBSITE_CACHE_DIR)
        if data is not None:
            return data

        base_data = entropy_repository.getBaseData(package_id)
        if base_data is None:
            return None

        atom, name, version, tag, description, category, chost, cflags, \
            cxxflags, homepage, license, x_branch, download, digest, slot, \
            etpapi, mtime, p_size, revision = base_data
        key = category + "/" + name

        try:
            r_arch = entropy_repository.getSetting("arch")
        except KeyError:
            r_arch = None
        """
        # doesn't work for source-based repos
        if r_arch != arch:
            return None # invalid !
        """
        date = entropy_tools.convert_unix_time_to_human_time(float(mtime))
        hash_id = self._api_human_encode_package(name,
            package_id, repository_id, arch, branch, product)
        hash_id_api = self._api_encode_package(package_id, repository_id, arch,
            branch, product)

        meta_items = self._setup_metadata_items(entropy,
            package_id, repository_id, arch, hash_id, is_source_repo,
            key, entropy_repository, short_list = not extended_meta_items)

        size = "0b"
        if p_size is not None:
            size = entropy_tools.bytes_into_human(p_size)

        data = {
            'atom': atom,
            'name': name,
            'slot': slot,
            'tag': tag,
            'license': license,
            'category': category,
            'key': key,
            'ugc': None,
            'branch': branch,
            'description': description,
            'download': download,
            'homepage': homepage,
            'revision': revision,
            'package_id': package_id,
            'arch': arch,
            'repository_id': repository_id,
            'product': product,
            'is_source_repo': is_source_repo,
            'spm_repo': entropy_repository.retrieveSpmRepository(package_id),
            'hash_id': hash_id,
            'hash_id_api': hash_id_api,
            'date': date,
            'mtime': mtime,
            'digest': digest,
            'chost': chost,
            'cflags': cflags,
            'cxxflags': cxxflags,
            'size': size,
            'change': self._api_extract_latest_change(
                atom, entropy_repository.retrieveChangelog(package_id)),
            'meta_items': meta_items,
        }
        if repository_id == model.config.ETP_REPOSITORY:
            data['app_install'] = self.__get_metadata_install_app_item(hash_id)

        if model.config.WEBSITE_CACHING:
            self._cacher.save(cache_key, data,
                cache_dir = model.config.WEBSITE_CACHE_DIR)

        return data

    def _get_package_extended_metadata(self, entropy, repository_id,
        package_id, arch, product, branch, entropy_repository):
        """
        Internal method used to build up extended metadata for package.
        """
        # caching
        brief_list_hash = 2
        is_source_repo = self._is_source_repository(repository_id)
        sha = hashlib.sha1()
        hash_str = "%s|%s|%s|%s|%s|%s|%s|%s" % (
            repository_id,
            package_id,
            arch,
            product,
            branch,
            repr(self._get_valid_repository_mtime(entropy, repository_id,
                arch, branch, product)),
            is_source_repo,
            brief_list_hash,
        )
        sha.update(repr(hash_str))
        cache_key = "_get_package_extended_metadata_" + sha.hexdigest()

        data = None
        if model.config.WEBSITE_CACHING:
            data = self._cacher.pop(cache_key,
                cache_dir = model.config.WEBSITE_CACHE_DIR)
        if data is not None:
            return data

        base_data = self._get_package_base_metadata(entropy, repository_id,
            package_id, arch, product, branch, entropy_repository,
            extended_meta_items = True)
        if base_data is None:
            return None

        ondisksize = "0b"
        o_size = entropy_repository.retrieveOnDiskSize(package_id)
        if o_size is not None:
            ondisksize = entropy_tools.bytes_into_human(o_size)

        brief_list = []
        brief_list.append({
            'key': "repository_id",
            'name': _("Repository"),
            'url': None,
            'split': False,
            'icon': "icon_database_table.png",
        })
        brief_list.append({
            'key': "spm_repo",
            'name': _("Sub-repository"),
            'url': None,
            'split': False,
            'icon': "icon_drive_network.png",
        })
        brief_list.append({
            'key': "license",
            'name': _("License"),
            'url': model.config.PACKAGE_SHOW_LICENSE_URL + "/--item--",
            'extra_url_meta': "rel=\"nofollow\"",
            'split': True,
            'icon': "icon_changelog.png",
        })
        if not is_source_repo:
            brief_list.append({
                'key': "ondisksize",
                'name': _("Required space"),
                'url': None,
                'split': False,
                'icon': "icon_disk.png",
            })
        brief_list.append({
            'key': "category",
            'name': _("Category"),
            'url': model.config.PACKAGE_SHOW_CATEGORY_URL + "/" + \
                base_data['category'],
            'extra_url_meta': "rel=\"nofollow\"",
            'split': False,
            'icon': "icon_folder.png",
        })
        brief_list.append({
            'key': "slot",
            'name': _("Slot"),
            'url': None,
            'split': False,
            'icon': "icon_bricks.png",
        })
        brief_list.append({
            'key': "tag",
            'name': _("Tag"),
            'url': None,
            'split': False,
            'icon': "icon_tag_purple.png",
        })
        if not is_source_repo:
            brief_list.append({
                'key': "chost",
                'name': "CHOST",
                'url': None,
                'split': False,
                'icon': "icon_database_table.png",
            })
            brief_list.append({
                'key': "cflags",
                'name': "CFLAGS",
                'url': None,
                'split': False,
                'icon': "icon_database_table.png",
            })
            brief_list.append({
                'key': "cxxflags",
                'name': "CXXFLAGS",
                'url': None,
                'split': False,
                'icon': "icon_database_table.png",
            })
            brief_list.append({
                'key': "digest",
                'name': _("Checksum"),
                'url': None,
                'split': False,
                'icon': "icon_timeline_marker.png",
            })
            brief_list.append({
                'key': "sha256",
                'name': _("SHA 256"),
                'url': None,
                'split': False,
                'icon': "icon_timeline_marker.png",
            })
            brief_list.append({
                'key': "download",
                'name': _("Package file"),
                'url': None,
                'split': False,
                'icon': "icon_package.png",
            })
            brief_list.append({
                'key': "size",
                'name': _("Package size"),
                'url': None,
                'split': False,
                'icon': "icon_attach.png",
            })
        brief_list.append({
            'key': "useflags",
            'name': _("USE flags"),
            'url': model.config.PACKAGE_SHOW_USEFLAG_URL + "/--item--",
            'extra_url_meta': "rel=\"nofollow\"",
            'split': True,
            'icon': "icon_flag_purple.png",
        })

        data = {
            'ondisksize': ondisksize,
            'useflags': entropy_repository.retrieveUseflags(package_id),
            'brief_list': brief_list,
        }
        data['sha1'], data['sha256'], data['sha512'], data['gpg'] = \
            entropy_repository.retrieveSignatures(package_id)

        data.update(base_data)

        if model.config.WEBSITE_CACHING:
            self._cacher.save(cache_key, data,
                cache_dir = model.config.WEBSITE_CACHE_DIR)

        return data

    def _get_packages_internal_metadata(self, entropy, ugc, package_tuples,
        extended = False):
        """
        Get basic metadata of given entropy package tuples.
        """
        meta_map = {}
        repo_cache = {}
        ugc_cache = {}

        try:
            for pkg_obj in package_tuples:
                p_id, r, a, b, p = pkg_obj

                if (r, a, b, p) in repo_cache:
                    repo = repo_cache.get((r, a, b, p))
                else:
                    repo = self._api_get_repo(entropy, r, a, b, p)
                    repo_cache[(r, a, b, p)] = repo

                try:
                    if repo is None:
                        continue
                    if extended:
                        pkg_data = self._get_package_extended_metadata(
                            entropy, r, p_id, a, p, b, repo)
                    else:
                        pkg_data = self._get_package_base_metadata(
                            entropy, r, p_id, a, p, b, repo)
                    if pkg_data is None:
                        continue
                    meta_map[pkg_obj] = pkg_data

                    key = meta_map[pkg_obj]['key']
                    if key not in ugc_cache:
                        ugc_data = self._get_ugc_base_metadata(entropy, ugc, r,
                            key)
                        ugc_cache[key] = ugc_data
                    meta_map[pkg_obj]['ugc'] = ugc_cache[key]
                except (OperationalError, DatabaseError):
                    continue

        finally:
            for repo in repo_cache.values():
                if repo is not None:
                    repo.close()
            ugc_cache.clear()
            repo_cache.clear()
            del ugc_cache
            del repo_cache

        return meta_map

    def _get_packages_base_metadata(self, entropy, ugc, package_tuples):
        """
        Get basic metadata of given entropy package tuples.
        """
        return self._get_packages_internal_metadata(entropy, ugc,
            package_tuples, extended = False)


    def _get_packages_extended_metadata(self, entropy, ugc, package_tuples):
        """
        Get extended metadata of given entropy package tuples.
        """
        return self._get_packages_internal_metadata(entropy, ugc,
            package_tuples, extended = True)
