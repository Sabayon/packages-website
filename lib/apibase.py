# -*- coding: utf-8 -*-
import base64
import urllib

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

import entropy.tools as entropy_tools

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
        import www.model.Entropy
        import www.model.UGC
        self._ugc = www.model.UGC.UGC
        self._entropy = www.model.Entropy.Entropy

    def _get_available_branches(self, entropy, repoid, product):
        arches = self._get_available_arches(entropy, repoid, product)
        branches = set()
        for arch in arches:
            branches |= set(entropy._get_branches(repoid, arch, product))
        return sorted(branches, reverse = True)

    def _get_available_repositories(self, entropy, product, arch):
        return sorted(entropy._get_repositories(product, arch))

    def _get_available_arches(self, entropy, repoid, product):
        return entropy._get_arches(repoid, product)

    def _api_get_repo(self, entropy, repository_id, arch, branch, product):
        """
        Internal method, stay away.
        """
        try:
            dbconn = entropy._open_db(repository_id, arch, product, branch)
            dbconn.validate()
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

        order_by_types = {
            'alphabet': "0",
            'vote': "1",
            'downloads': "2",
        }
        # order by
        o = request.params.get('o') or "alphabet"
        o = order_by_types.get(o, order_by_types.get("alphabet"))

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
        id_str = base64.urlsafe_b64decode(encoded_id_str)
        try:
            package_id, repository_id, a, b, p = id_str.split()
            package_id = int(package_id)
        except ValueError:
            return None
        return package_id, repository_id, a, b, p

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

    def _api_search_pkg(self, entropy, q):
        """
        Search packages in repositories using given query string.

        @param q: query string
        @type q: string
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
                    data.extend((pkg_id, repository_id, arch, branch, product) \
                        for pkg_id in pkg_ids)
            finally:
                if repo is not None:
                    repo.close()
        return data

    def _api_search_desc(self, entropy, q):
        """
        Search packages in repositories using given query string
        (description strategy).

        @param q: query string
        @type q: string
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
                    data.extend((pkg_id, repository_id, arch, branch, product) \
                        for pkg_id in pkg_ids)
            finally:
                if repo is not None:
                    repo.close()
        return data

    def _api_search_lib(self, entropy, q):
        """
        Search packages in repositories using given query string
        (library strategy).

        @param q: query string
        @type q: string
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
                    pkg_ids = list(repo.searchNeeded(q))
                    if len(pkg_ids) > 10:
                        pkg_ids = pkg_ids[:10]
                    data.extend((pkg_id, repository_id, arch, branch, product) \
                        for pkg_id in pkg_ids)
            finally:
                if repo is not None:
                    repo.close()
        return data

    def _api_search_path(self, entropy, q):
        """
        Search packages in repositories using given query string
        (content strategy).

        @param q: query string
        @type q: string
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
                    data.extend((pkg_id, repository_id, arch, branch, product) \
                        for pkg_id in pkg_ids)
            finally:
                if repo is not None:
                    repo.close()
        return data

    def _api_search_sets(self, entropy, q):
        """
        Search packages in repositories using given query string
        (sets strategy).

        @param q: query string
        @type q: string
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
                    data.extend((pkg_id, repository_id, arch, branch, product) \
                        for pkg_id in pkg_ids)
            finally:
                if repo is not None:
                    repo.close()
        return data

    def _api_search_mime(self, entropy, q):
        """
        Search packages in repositories using given query string
        (mimetype strategy).

        @param q: query string
        @type q: string
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
                    data.extend((pkg_id, repository_id, arch, branch, product) \
                        for pkg_id in pkg_ids)
            finally:
                if repo is not None:
                    repo.close()
        return data

    def _api_search_match(self, entropy, q):
        """
        Search packages in repositories using given query string (match strategy).

        @param q: query string
        @type q: string
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

        pkgs = sorted(raw_latest, key = lambda x: x[0])
        if len(pkgs) > max_count:
            pkgs = pkgs[:max_count]
        return [(p_id, r, a, b, p) for cdate, p_id, r, a, b, p in pkgs]

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

    def _setup_metadata_items(self, entropy, package_id, repository_id,
        hash_id, is_source_repo, package_key, entropy_repository,
        short_list = True):
        """
        This cryptic method setups a simple list of links (and their metadata)
        that are shown right below the main package information.
        Example links: Homepage, Bugs, etc.

        @return: list of dictionaries
        @rtype: list
        """
        def _generate_action_url(target):
            return "%s/%s/%s" % (model.config.PACKAGE_SHOW_URL,
                hash_id, target)

        data = []
        # homepage
        homepage = entropy_repository.retrieveHomepage(package_id)
        if homepage:
            obj = {
                'name': _("Homepage"),
                'icon': "icon_homepage.png",
                'url': homepage,
                'alt': _("Visit package homepage"),
                'extra_url_meta': "rel=\"nofollow\"",
            }
            data.append(obj)

        # changelog
        obj = {
            'name': _("ChangeLog"),
            'icon': "icon_changelog.png",
            'url': _generate_action_url("changelog"),
            'alt': _("Package ChangeLog"),
            'extra_url_meta': "rel=\"nofollow\"",
        }
        data.append(obj)

        # setup bugs
        if not short_list:
            quoted_key = urllib.quote_plus(package_key)
            if not is_source_repo:
                bug_url = "http://bugs.sabayon.org/buglist.cgi?quicksearch=%s" % (
                    quoted_key,)
                obj = {
                    'name': _("Bugs"),
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
                'name': _("Upstream bugs"),
                'icon': "icon_bugs.png",
                'url': upstream_bug_url,
                'alt': _("Gentoo bugs related to package"),
                'extra_url_meta': "rel=\"nofollow\"",
            }
            data.append(obj)

        return data


    def _get_package_base_metadata(self, entropy, ugc, repository_id,
        package_id, product, entropy_repository, get_ugc = True):
        """
        Internal method used to build up a basic metadata for package.
        """
        key_slot = entropy_repository.retrieveKeySlot(package_id)
        if key_slot is not None:
            key, slot = key_slot
        else:
            key, slot = "n/a", "0"
        category, name = key.split("/", 1)
        try:
            arch = entropy_repository.getSetting("arch")
        except KeyError:
            arch = None
        branch = entropy_repository.retrieveBranch(package_id)
        mtime = float(entropy_repository.retrieveCreationDate(package_id))
        date = entropy_tools.convert_unix_time_to_human_time(mtime)
        atom = entropy_repository.retrieveAtom(package_id)
        hash_id = self._api_encode_package(package_id, repository_id,
                arch, branch, product)
        is_source_repo = self._is_source_repository(repository_id)
        data = {
            'atom': atom,
            'name': name,
            'category': category,
            'key': key,
            'ugc': None,
            'branch': branch,
            'description': entropy_repository.retrieveDescription(package_id),
            'download': entropy_repository.retrieveDownloadURL(package_id),
            'revision': entropy_repository.retrieveRevision(package_id),
            'package_id': package_id,
            'arch': arch,
            'repository_id': repository_id,
            'product': product,
            'is_source_repo': is_source_repo,
            'hash_id': hash_id,
            'date': date,
            'mtime': mtime,
            'change': self._api_extract_latest_change(
                atom, entropy_repository.retrieveChangelog(package_id)),
            'meta_items': self._setup_metadata_items(entropy,
                package_id, repository_id, hash_id, is_source_repo,
                key, entropy_repository),
        }
        #size = "0b"
        #p_size = entropy_repository.retrieveSize(package_id)
        #if p_size is not None:
        #    size = entropy_tools.bytes_into_human(p_size)
        #data['size'] = size
        if get_ugc:
            data['ugc'] = self._get_ugc_base_metadata(entropy, ugc,
                repository_id, key)
        return data

    def _get_packages_base_metadata(self, entropy, ugc, package_tuples):
        """
        Get metadata of given entropy package tuples.
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
                    meta_map[pkg_obj] = self._get_package_base_metadata(
                        entropy, ugc, r, p_id, p, repo, get_ugc = False)

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

