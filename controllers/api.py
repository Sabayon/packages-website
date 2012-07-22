import base64

import json
from www.lib.base import *
from www.lib.website import *
from www.lib.apibase import ApibaseController
from www.lib.dict2xml import dict_to_xml
from www.lib.exceptions import ServiceConnectionError

from entropy.const import etpConst
from entropy.exceptions import SystemDatabaseError
from entropy.db.exceptions import ProgrammingError, OperationalError, \
    DatabaseError
import entropy.dep as entropy_dep
import entropy.tools as entropy_tools

class ApiController(BaseController, WebsiteController, ApibaseController):

    CACHE_DIR = "www/packages_cache"

    def __init__(self):
        BaseController.__init__(self)
        WebsiteController.__init__(self)
        ApibaseController.__init__(self)

    def _api_render(self, response, renderer):
        if renderer == "json":
            return json.dumps(response)
        elif renderer == "jsonp":
            callback = "callback"
            try:
                callback = request.params.get('callback') or callback
            except AttributeError:
                callback = "callback"
            return callback + "(" + json.dumps(response) + ");"
        else:
            raise AttributeError("programming error: invalid renderer")

    def _api_get_args(self):
        """
        Return API arguments, as passed in arg0, arg1 and arg2
        """
        arg1 = None
        arg2 = None
        arg0 = request.params.get("arg0")
        if arg0 is None:
            return None, None, None
        arg1 = request.params.get("arg1")
        if arg1 is None:
            return arg0, None, None
        arg2 = request.params.get("arg2")
        if arg2 is None:
            return arg0, arg1, None
        return arg0, arg1, arg2

    def _api_order_by(self, pkgs_data, order_by):
        """
        Order a list of tuples composed by (package_id, repository_id,
        arch, branch, product, entropy_repository) using given order_by directive,
        can be either alphabet, vote, downloads
        """
        def _alphabet_order():
            key_sorter = lambda x: x[5].retrieveAtom(x[0])
            return sorted(pkgs_data, key = key_sorter)

        def _downloads_order():
            ugc = None
            try:
                ugc = self._ugc(https=False)
                key_sorter = lambda x: ugc.get_ugc_vote(
                    entropy_dep.dep_getkey(x[5].retrieveAtom(x[0])))
                return sorted(pkgs_data, key = key_sorter)
            except ServiceConnectionError:
                return []
            finally:
                if ugc is not None:
                    ugc.disconnect()
                    del ugc

        def _vote_order():
            ugc = None
            try:
                ugc = self._ugc(https=False)
                key_sorter = lambda x: ugc.get_ugc_download(
                    entropy_dep.dep_getkey(x[5].retrieveAtom(x[0])))
                return sorted(pkgs_data, key = key_sorter, reverse = True)
            except ServiceConnectionError:
                return []
            finally:
                if ugc is not None:
                    ugc.disconnect()
                    del ugc

        order_map = {
            "alphabet": _alphabet_order,
            "downloads": _downloads_order,
            "vote": _vote_order
        }
        func = order_map.get(order_by, _alphabet_order)
        return func()

    def _api_error(self, renderer, code, message):
        """
        API request error, build response and return
        """
        response = self._api_base_response(code, message = message)
        return self._api_render(response, renderer)

    def _api_categories(self, repository_id, arch, branch, product, order_by,
        renderer):
        """
        Return a list of available entropy categories for given repository.
        NOTE: order_by doesn't have any effect here.
        """
        response = self._api_base_response(200)
        dbconn = self._api_get_repo(self._entropy(), repository_id, arch,
            branch, product)

        try:
            if dbconn is None:
                return self._api_error(renderer, 503, "repository not available")
            response['r'] = sorted(dbconn.listAllCategories())
        except Exception as err:
            return self._api_error(renderer, 503, repr(err))
        finally:
            if dbconn is not None:
                dbconn.close()

        return self._api_render(response, renderer)

    def _api_groups(self, repository_id, arch, branch, product, order_by,
        renderer):
        """
        Return Package Groups for given repository.
        The returned object is a dict, key is the name of the package group,
        value is a dict containing metadata related to that group, such as:
        name<string>, categories<list>, description<string>.
        NOTE: order_by doesn't have any effect here.
        """
        response = self._api_base_response(200)
        entropy = self._entropy()
        spm_class = entropy.Spm_class()
        dbconn = self._api_get_repo(entropy, repository_id, arch, branch,
            product)

        try:
            if dbconn is None:
                return self._api_error(renderer, 503, "repository not available")
            categories = sorted(dbconn.listAllCategories())
            groups = spm_class.get_package_groups().copy()
            for data in groups.values():
                exp_cats = set()
                for g_cat in data['categories']:
                    exp_cats.update([x for x in categories if \
                        x.startswith(g_cat)])
                data['categories'] = sorted(exp_cats)
            response['r'] = groups
        except Exception as err:
            return self._api_error(renderer, 503, repr(err))
        finally:
            if dbconn is not None:
                dbconn.close()

        return self._api_render(response, renderer)

    def _api_search_packages(self, search_term, repository_id, arch, branch,
        product, order_by, renderer):
        """
        Search inside repository the given search term.
        """
        if len(search_term) < 3:
            # invalid
            return self._api_error(renderer, 400, "bad request")

        response = self._api_base_response(200)
        entropy = self._entropy()
        dbconn = self._api_get_repo(entropy, repository_id, arch, branch,
            product)

        try:
            if dbconn is None:
                return self._api_error(renderer, 503, "repository not available")
            pkg_ids = dbconn.searchPackages(search_term, just_id = True)
            pkgs_data = [
                (pkg_id, repository_id, arch, branch, product, dbconn) for \
                    pkg_id in pkg_ids]

            ordered_pkgs = self._api_order_by(pkgs_data, order_by)
            # drop dbconn
            ordered_pkgs = [(p_id, r, a, b, p) for (p_id, r, a, b, p, x) in \
                ordered_pkgs]
            response['r'] = [self._api_encode_package(*x) for x in ordered_pkgs]
        except Exception as err:
            return self._api_error(renderer, 503, repr(err))
        finally:
            if dbconn is not None:
                dbconn.close()

        return self._api_render(response, renderer)

    def _api_packages_in_groups(self, groups_str, repository_id, arch, branch,
        product, order_by, renderer):
        """
        Return a list of packages in given Package Groups. Results are returned
        in list form, ordered by order_by directive. Package ids are encoded
        in base64.
        http://url/api?q=packages_in_groups&arg0=development%20lxde
        """
        requested_groups = frozenset(groups_str.split())

        entropy = self._entropy()
        spm_class = entropy.Spm_class()
        groups = spm_class.get_package_groups()
        # validate groups
        avail_groups = set(groups.keys())
        group_validation = requested_groups - avail_groups
        if group_validation:
            # invalid
            return self._api_error(renderer, 400, "bad request")

        response = self._api_base_response(200)
        dbconn = self._api_get_repo(entropy, repository_id, arch, branch,
            product)

        try:
            if dbconn is None:
                return self._api_error(renderer, 503, "repository not available")
            categories = sorted(dbconn.listAllCategories())
            pkg_ids = set()
            for group in requested_groups:
                group_data = groups[group]
                # expand category
                my_categories = set()
                for g_cat in group_data['categories']:
                    my_categories.update([x for x in categories if \
                        x.startswith(g_cat)])
                for my_category in my_categories:
                    # now get packages belonging to this category
                    pkg_ids |= dbconn.listPackageIdsInCategory(my_category)
            pkgs_data = [
                (pkg_id, repository_id, arch, branch, product, dbconn) for \
                    pkg_id in pkg_ids]
            ordered_pkgs = self._api_order_by(pkgs_data, order_by)
            # drop dbconn
            ordered_pkgs = [(p_id, r, a, b, p) for (p_id, r, a, b, p, x) in \
                ordered_pkgs]
            response['r'] = [self._api_encode_package(*x) for x in ordered_pkgs]
        except Exception as err:
            return self._api_error(renderer, 503, repr(err))
        finally:
            if dbconn is not None:
                dbconn.close()

        return self._api_render(response, renderer)

    def _api_packages_in_categories(self, categories_str, repository_id, arch,
        branch, product, order_by, renderer):
        """
        Return a list of packages in given Package Categories. Results are
        returned in list form, ordered by order_by directive.
        Package ids are encoded in base64.
        http://url/api?q=packages_in_categories&arg0=x11-apps%20app-misc
        """
        requested_categories = frozenset(categories_str.split())
        entropy = self._entropy()

        response = self._api_base_response(200)
        dbconn = self._api_get_repo(entropy, repository_id, arch, branch,
            product)

        try:
            if dbconn is None:
                return self._api_error(renderer, 503, "repository not available")
            categories = dbconn.listAllCategories()
            # validate categories
            categories_validation = requested_categories - set(categories)
            if categories_validation:
                # invalid
                return self._api_error(renderer, 400, "bad request")
            pkg_ids = set()
            for category in categories:
                # now get packages belonging to this category
                pkg_ids |= dbconn.listPackageIdsInCategory(category)
            pkgs_data = [
                (pkg_id, repository_id, arch, branch, product, dbconn) for \
                    pkg_id in pkg_ids]
            ordered_pkgs = self._api_order_by(pkgs_data, order_by)
            # drop dbconn
            ordered_pkgs = [(p_id, r, a, b, p) for (p_id, r, a, b, p, x) in \
                ordered_pkgs]
            response['r'] = [self._api_encode_package(*x) for x in ordered_pkgs]
        except Exception as err:
            return self._api_error(renderer, 503, repr(err))
        finally:
            if dbconn is not None:
                dbconn.close()

        return self._api_render(response, renderer)

    def _api_categories_in_groups(self, groups_str, repository_id, arch,
        branch, product, order_by, renderer):
        """
        Return a list of package categories contained in given package groups.
        """
        requested_groups = frozenset(groups_str.split())

        entropy = self._entropy()
        spm_class = entropy.Spm_class()
        groups = spm_class.get_package_groups()
        # validate groups
        avail_groups = set(groups.keys())
        group_validation = requested_groups - avail_groups
        if group_validation:
            # invalid
            return self._api_error(renderer, 400, "bad request")

        response = self._api_base_response(200)
        dbconn = self._api_get_repo(entropy, repository_id, arch, branch,
            product)

        try:
            if dbconn is None:
                return self._api_error(renderer, 503, "repository not available")
            categories = sorted(dbconn.listAllCategories())
            out_cats = set()
            for group in requested_groups:
                group_data = groups[group]
                # expand category
                for g_cat in group_data['categories']:
                    out_cats.update([x for x in categories if \
                        x.startswith(g_cat)])
            response['r'] = sorted(out_cats)
        except Exception as err:
            return self._api_error(renderer, 503, repr(err))
        finally:
            if dbconn is not None:
                dbconn.close()

        return self._api_render(response, renderer)

    def _api_package_to_hash(self, package_id_str, repository_id, arch,
        branch, product, order_by, renderer):
        """
        Given package_id, repository id, arch, branch, product, return
        its base64 encoded hash.
        NOTE: this method doesn't use order_by.
        """
        try:
            package_id = int(package_id_str)
        except ValueError:
            return self._api_error(renderer, 400, "bad request")

        pkg_hash = self._api_encode_package(package_id, repository_id, arch,
            branch, product)

        response = self._api_base_response(200)
        response['r'] = pkg_hash

        return self._api_render(response, renderer)

    def _get_api_package_basic_info(self, entropy_repository, ugc, package_id,
        repository_id, arch, branch, product):
        """
        Internal method. Return a dict containing all the basic info of a
        package.
        atom, key, name, category, branch, description, revision
        package_id, repository_id, vote, downloads, number of documents,
        arch, product.
        NOTE: can return None!
        """
        base_data = entropy_repository.getBaseData(package_id)
        if base_data is None:
            return None
        atom, name, version, tag, desc, cat, chost, cflags, cxxflags, \
            homepage, license, branch, download, digest, slot, api, \
            date, size, rev = base_data
        pkg_key = entropy_dep.dep_getkey(atom)

        docs_number = len(ugc.get_ugc_metadata_doctypes(pkg_key,
            [ugc.DOC_TYPES[x] for x in ugc.DOC_TYPES]))

        pkg_data = {
            'atom': atom,
            'key': pkg_key,
            'slot': slot,
            'name': name,
            'category': cat,
            'branch': branch,
            'description': desc,
            'repository_id': repository_id,
            'arch': arch,
            'product': product,
            'package_id': package_id,
            'vote': round(ugc.get_ugc_vote(pkg_key), 2),
            'downloads': ugc.get_ugc_download(pkg_key),
            'docs_number': docs_number,
        }
        return pkg_data

    def _get_api_package_detailed_info(self, entropy_repository, ugc, package_id,
        repository_id, arch, branch, product):
        """
        Internal method. Return a dict containing all the detailed info of a
        package. See below.
        NOTE: can return None!
        """
        base_data = entropy_repository.getBaseData(package_id)
        if base_data is None:
            return None
        atom, name, version, tag, desc, cat, chost, cflags, cxxflags, \
            homepage, license, branch, download, digest, slot, api, \
            date, size, rev = base_data
        if size is None:
            size = "0b"
        else:
            size = entropy_tools.bytes_into_human(size)
        on_disk_size = entropy_repository.retrieveOnDiskSize(package_id)
        pkg_key = entropy_dep.dep_getkey(atom)
        t_time = float(date)

        pkg_data = {
            'version': version,
            'revision': rev,
            'homepage': homepage,
            'size': size,
            'md5': digest,
            'api': api,
            'date': date,
            'download': download,
            'cflags': cflags,
            'chost': chost,
            'cxxflags': cxxflags,
            'license': license.split(),
            'tag': tag,
            'ondisksize': entropy_tools.bytes_into_human(on_disk_size),
            'use': sorted(entropy_repository.retrieveUseflags(package_id)),
            'date': entropy_tools.convert_unix_time_to_human_time(t_time),
            'time': t_time,
            'repository_id': repository_id,
            'arch': arch,
            'product': product,
            'package_id': package_id,
            'docs': ugc.get_ugc_metadata_doctypes(pkg_key,
                [ugc.DOC_TYPES[x] for x in ugc.DOC_TYPES]),
        }
        for mydoc in pkg_data['docs']:
            self._expand_ugc_doc_metadata(ugc, mydoc)

        dependencies = entropy_repository.retrieveDependencies(package_id,
            extended = True)
        pkg_data['build_deps'] = sorted([x for x, y in dependencies if y == \
            etpConst['dependency_type_ids']['bdepend_id']])
        pkg_data['run_deps'] = sorted([x for x, y in dependencies if y == \
            etpConst['dependency_type_ids']['rdepend_id']])
        pkg_data['post_deps'] = sorted([x for x, y in dependencies if y == \
            etpConst['dependency_type_ids']['pdepend_id']])
        pkg_data['manual_deps'] = sorted([x for x, y in dependencies if y == \
            etpConst['dependency_type_ids']['mdepend_id']])
        pkg_data['conflicts'] = sorted(
            entropy_repository.retrieveConflicts(package_id))

        pkg_data['sha1'], pkg_data['sha256'], pkg_data['sha512'], \
            pkg_data['gpg'] = entropy_repository.retrieveSignatures(package_id)

        return pkg_data

    def _api_get_packages(self, package_hashes, repository_id, arch,
        branch, product, order_by, renderer):
        """
        Get basic information for given package hashes. Please see:
        _get_api_package_basic_info() and _get_api_package_detailed_info()
        for more info.
        key is package hash, value is dict containing keys above.
        NOTE: order_by is ignored
        """
        return self._api_get_packages_impl(package_hashes, repository_id, arch,
            branch, product, order_by, renderer, False)

    def _api_get_packages_details(self, package_hashes, repository_id, arch,
        branch, product, order_by, renderer):
        """
        Get detailed information for given package hashes. Please see:
        _get_api_package_basic_info() for more info.
        key is package hash, value is dict containing keys above.
        NOTE: order_by is ignored
        """
        return self._api_get_packages_impl(package_hashes, repository_id, arch,
            branch, product, order_by, renderer, True)

    def _api_get_packages_impl(self, package_hashes, repository_id, arch,
        branch, product, order_by, renderer, details):
        """
        Internal.
        Get basic or detailed information for given package hashes.
        """
        package_hashes = package_hashes.split()
        packages = set()
        # validate hashes
        for package_hash in package_hashes:
            decoded = self._api_decode_package(package_hash)
            if decoded is None:
                return self._api_error(renderer, 400, "bad request")
            package_id, hash_repository_id, a, b, p = decoded
            # validate single elements
            if hash_repository_id != repository_id:
                return self._api_error(renderer, 400, "invalid repository")
            if a != arch:
                return self._api_error(renderer, 400, "invalid arch")
            if b != branch:
                return self._api_error(renderer, 400, "invalid branch")
            if p != product:
                return self._api_error(renderer, 400, "invalid product")

            packages.add((package_hash, decoded))

        response = self._api_base_response(200)
        entropy = self._entropy()
        dbconn = self._api_get_repo(entropy, repository_id, arch, branch,
            product)
        try:
            if dbconn is None:
                return self._api_error(renderer, 503, "repository not available")
            ugc = None
            try:
                ugc = self._ugc(https=False)
                pkgs_data = {}
                for package_hash, (package_id, repository_id, a, b, p) in packages:
                    if details:
                        pkg_data = self._get_api_package_detailed_info(
                            dbconn, ugc, package_id, repository_id, a, b, p)
                    else:
                        pkg_data = self._get_api_package_basic_info(
                            dbconn, ugc, package_id, repository_id, a, b, p)
                    if pkg_data is None:
                        return self._api_error(renderer, 503,
                            "package not available")
                    pkgs_data[package_hash] = pkg_data
                response['r'] = pkgs_data
            except ServiceConnectionError:
                return self._api_error(
                    renderer, 503, "service not available")
            finally:
                if ugc is not None:
                    ugc.disconnect()
                    del ugc
        except Exception as err:
            return self._api_error(renderer, 503, repr(err))
        finally:
            if dbconn is not None:
                dbconn.close()

        return self._api_render(response, renderer)

    def execute(self):
        """
        Public API, only supporting json or jsonp.

        GET parameters:
        q=<query type>: type of API request [mandatory]
            supported:
            - <list> search()
            - <list> categories()
            - <dict> groups()
            - <list> packages_in_groups(groups<space separated list of groups>)
            - <list> categories_in_groups(groups<space separated list of groups>)
            - <list> packages_in_categories(categories<space separated list of categories>)
            - <dict> get_packages(packages<string separated package hashes>)
            - <dict> get_packages_details(packages<string separated package hashes>)
                get detailed information for given package hashes.
            - <string> package_to_hash(package_id) [other parameters given via r,a,b,p HTTP GET]
        arg0=<query argument>: argument 0 to use in combination with query type
        arg1=<query argument>: argument 1 to use in combination with query type
        arg2=<query argument>: argument 2 to use in combination with query type

        r=<repo>: repository id [default: sabayonlinux.org]
        a=<arch>: architecture [default: amd64]
        b=<branch>: repository branch [default: 5]
        p=<product>: product [default: standard]
        o=<order by>: order packages by (alphabet, vote, downloads)
            [default: alphabet]

        Response will be printed in form of json or jsonp objects and data
        will be contained inside 'r' dict value.
        Moreover, client must check 'code' value, which contains an HTTP-alike
        code int (200 is OK, 404 is invalid api call, 503 is server error, 400
        is bad request).
        'code' will be always there, as well as 'api_rev', representing the
        API response revision (current is: 1), and 'message', which is bound
        to 'code' value.
        """
        api_map = {
            "search": self._api_search_packages,
            "categories": self._api_categories,
            "groups": self._api_groups,
            "packages_in_groups": self._api_packages_in_groups,
            "packages_in_categories": self._api_packages_in_categories,
            "categories_in_groups": self._api_categories_in_groups,
            "package_to_hash": self._api_package_to_hash,
            "get_packages": self._api_get_packages,
            "get_packages_details": self._api_get_packages_details,
        }

        q = request.params.get("q")
        if q not in api_map:
            q = None

        try:
            renderer = request.params.get('render')
            if renderer not in ("json", "jsonp"):
                raise AttributeError()
        except AttributeError:
            renderer = "json"

        if q is None:
            # no need to go further
            return self._api_error(renderer, 400, "bad request")

        r, a, b, p, o = self._api_get_params()
        if r is None:
            q = None
        if a is None:
            q = None
        if b is None:
            q = None
        if p is None:
            q = None
        if o is None:
            q = None

        args = self._api_get_args()
        args = [x for x in args if x is not None]
        args.extend([r, a, b, p, o, renderer])

        callback = api_map.get(q)
        if callback is None:
            # unsupported q=
            return self._api_error(renderer, 400, "bad request")
        try:
            return callback(*args)
        except TypeError as err:
            return self._api_error(renderer, 400, repr(err))
