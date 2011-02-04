
import json
from www.lib.base import *
from www.lib.website import *
from www.lib.dict2xml import dict_to_xml

from entropy.exceptions import SystemDatabaseError
from entropy.db.exceptions import ProgrammingError, OperationalError, \
    DatabaseError
import entropy.dep

class ApiController(BaseController, WebsiteController):

    CACHE_DIR = "www/packages_cache"

    def __init__(self):
        BaseController.__init__(self)
        WebsiteController.__init__(self)

    def _api_base_response(self, code):
        response = {
            'code': code,
            'api_rev': 1,
        }
        return response

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
        return base64.b64encode(id_str)

    def _api_decode_package(self, encoded_id_str):
        """
        Decode a base64 encoded package hash back into a full blown package
        tuple.

        @param encoded_id_str: package hash base64 encoded
        @type: string
        @return: tuple composed by (package_id, repository_id, arch, branch, product)
        @rtype: tuple
        """
        id_str = base64.b64decode(encoded_id_str)
        try:
            package_id, repository_id, a, b, p = id_str.split()
            package_id = int(package_id)
        except ValueError:
            return None
        return package_id, repository_id, a, b, p

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
            ugc = self.UGC()
            try:
                key_sorter = lambda x: ugc.get_ugc_vote(
                    entropy.dep.dep_getkey(x[5].retrieveAtom(x[0])))
                return sorted(pkgs_data, key = key_sorter)
            finally:
                ugc.disconnect()
                del ugc

        def _vote_order():
            ugc = self.UGC()
            try:
                key_sorter = lambda x: ugc.get_ugc_downloads(
                    entropy.dep.dep_getkey(x[5].retrieveAtom(x[0])))
                return sorted(pkgs_data, key = key_sorter, reverse = True)
            finally:
                ugc.disconnect()
                del ugc

        order_map = {
            "alphabet": _alphabet_order,
            "downloads": _downloads_order,
            "vote": _vote_order
        }
        func = order_map.get(order_by, _alphabet_order)
        return func()

    def _api_error(self, renderer, code = 404):
        """
        API request error, build response and return
        """
        response = self._api_base_response(code)
        return self._api_render(response, renderer)

    def _api_categories(self, repository_id, arch, branch, product, order_by,
        renderer):
        """
        Return a list of available entropy categories for given repository.
        NOTE: order_by doesn't have any effect here.
        """
        response = self._api_base_response(200)
        dbconn = self._api_get_repo(self.Entropy(), repository_id, arch,
            product, branch)
        if dbconn is None:
            return self._api_error(renderer, 503)

        try:
            response['r'] = sorted(dbconn.listAllCategories())
        except:
            return self._api_error(renderer, 503)
        finally:
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
        entropy = self.Entropy()
        spm_class = entropy.Spm_class()
        dbconn = self._api_get_repo(entropy, repository_id, arch, product,
            branch)
        if dbconn is None:
            return self._api_error(renderer, 503)

        try:
            categories = sorted(dbconn.listAllCategories())
            groups = spm_class.get_package_groups().copy()
            for data in groups.values():
                exp_cats = set()
                for g_cat in data['categories']:
                    exp_cats.update([x for x in categories if \
                        x.startswith(g_cat)])
                data['categories'] = sorted(exp_cats)
            response['r'] = groups
        except:
            return self._api_error(renderer, 503)
        finally:
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

        entropy = self.Entropy()
        spm_class = entropy.Spm_class()
        groups = spm_class.get_package_groups()
        # validate groups
        avail_groups = set(groups.keys())
        group_validation = requested_groups - avail_groups
        if group_validation:
            # invalid
            return self._api_error(renderer, 400)

        response = self._api_base_response(200)
        dbconn = self._api_get_repo(entropy, repository_id, arch, product,
            branch)
        if dbconn is None:
            return self._api_error(renderer, 503)

        try:
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
        except:
            return self._api_error(renderer, 503)
        finally:
            dbconn.close()

        return self._api_render(response, renderer)

    def execute(self):
        """
        Public API, only supporting json or jsonp.

        GET parameters:
        q=<query type>: type of API request [mandatory]
            supported:
            - <list> categories()
            - <dict> groups()
            - <list> packages_in_groups(groups<space separated list of groups>)
            - <list> categories_in_groups(groups<space separated list of groups>)
            - <list> packages_in_categories(categories<space separated list of categories>)
            - <list of dict> get_packages(packages<string separated package ids>)
            - <list of dict> get_packages_details(packages<string separated package ids>)
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
        API response revision (current is: 1).
        """
        api_map = {
            "categories": self._api_categories,
            "groups": self._api_groups,
            "packages_in_groups": self._api_packages_in_groups,
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
            return self._api_error(renderer)

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
            return self._api_error(renderer)
        try:
            return callback(*args)
        except TypeError:
            return self._api_error(renderer)