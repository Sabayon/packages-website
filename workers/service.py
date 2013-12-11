#!/usr/bin/python2

import hashlib
import os

import sys

_dir = os.path.dirname(__file__)
WWW_PATH = os.path.abspath(os.path.join(_dir, "../../"))
PROJECT_NAME = "www"
sys.path.append(WWW_PATH)
sys.path.append(os.path.join(WWW_PATH, PROJECT_NAME))

"""
from paste.registry import RegistryManager, StackedObjectProxy
myglobal = StackedObjectProxy()
app = RegistryManager(None)

environ['paste.registry'].register(myglobal, obj)
"""

import model

from www.lib.apibase import ApibaseController
from www.lib.exceptions import ServiceConnectionError

from entropy.services.client import WebService
from entropy.client.services.interfaces import RepositoryWebService, Document

class StandaloneController(ApibaseController):

    def __init__(self):
        super(StandaloneController, self).__init__()

    @classmethod
    def error(cls, msg):
        sys.stderr.write("%sq" % (msg,))
        sys.stderr.flush()

    @classmethod
    def data(cls, text):
        sys.stdout.write("%s" % (text,))
        sys.stdout.flush()

    def get_package_ids(self):
        entropy_client = self._entropy()
        try:
            r, a, b, p = self._reposerv_get_params(entropy_client, os.environ)
        except AssertionError as err:
            self.error(err)
            return 1

        repo = None
        try:
            repo = self._api_get_repo(entropy_client, r, a, b, p)
            if repo is None:
                self.error("unavailable repository")
                return 1

            package_ids = repo.listAllPackageIds(order_by = "package_id")
            response = self._api_base_response(
                WebService.WEB_SERVICE_RESPONSE_CODE_OK)
            response['r'] = package_ids
            self.data(self._service_render(response))
            return 0
        finally:
            if repo is not None:
                repo.close()

    def repository_revision(self):
        entropy_client = self._entropy()
        try:
            r, a, b, p = self._reposerv_get_params(entropy_client, os.environ)
        except AssertionError as err:
            self.error(err)
            return 1

        revision = self._reposerv_get_revision(entropy_client, r, a, b, p)
        response = self._api_base_response(
            WebService.WEB_SERVICE_RESPONSE_CODE_OK)
        response['r'] = revision
        self.data(self._service_render(response))
        return 0

    def _get_package_ids(self):
        """
        Get Entropy Package ids from HTTP request data.
        """
        package_ids = os.environ.get("package_ids", "").strip().split()
        if not package_ids:
            raise AttributeError("package ids not found")
        try:
            package_ids = [int(x) for x in package_ids]
            # do not enforce an upper bound
            package_ids = list(set(package_ids))
        except (ValueError, TypeError):
            raise AttributeError("package ids are invalid")

        # check data
        invalid_ints = [x for x in package_ids if x < 1]
        if invalid_ints:
            raise AttributeError("package ids are invalid (2)")

        # increase determinism
        package_ids.sort()
        return package_ids

    def get_packages_metadata(self):
        """
        Get Packages metadata.
        """
        entropy_client = self._entropy()
        try:
            r, a, b, p = self._reposerv_get_params(entropy_client, os.environ)
        except AssertionError as err:
            self.error(err)
            return 1

        try:
            package_ids = self._get_package_ids()
        except AttributeError as err:
            self.error(err)
            return 1

        max_len = RepositoryWebService.MAXIMUM_PACKAGE_REQUEST_SIZE
        if len(package_ids) > max_len:
            self.error("too many package_ids")
            return 1
        package_ids = sorted(package_ids)

        cached_obj = None
        if model.config.WEBSITE_CACHING:
            mtime = self._get_valid_repository_mtime(
                entropy_client, r, a, b, p)

            sha = hashlib.sha1()
            sha.update("%f;" % (mtime,))
            sha.update(";".join(["%s" % (x,) for x in package_ids]))
            sha.update(";")
            sha.update(r)
            sha.update(";")
            sha.update(a)
            sha.update(";")
            sha.update(b)
            sha.update(";")
            sha.update(p)
            cache_key = "_service_get_packages_metadata_%s_%s_%s_%s_%s_v2" % (
                sha.hexdigest(), r, a, b, p)

            cached_obj = self._cacher.pop(
                cache_key, cache_dir = model.config.WEBSITE_CACHE_DIR)
            if cached_obj is not None:
                self.data(cached_obj)
                return 0

        repo = None
        try:
            repo = self._api_get_repo(entropy_client, r, a, b, p)
            if repo is None:
                self.error("invalid repository")
                return 1

            pkg_data = {}
            for package_id in package_ids:
                pkg_meta = repo.getPackageData(package_id,
                    content_insert_formatted = True,
                    get_content = False, get_changelog = False)
                if pkg_meta is None:
                    # request is out of sync, we can abort everything
                    self.error("requesting unavailable packages")
                    return 1

                self._reposerv_json_pkg_data(pkg_meta)
                pkg_data[package_id] = pkg_meta

            response = self._api_base_response(
                WebService.WEB_SERVICE_RESPONSE_CODE_OK)
            response['r'] = pkg_data
            cached_obj = self._service_render(response)

            if model.config.WEBSITE_CACHING:
                self._cacher.save(
                    cache_key, cached_obj,
                    cache_dir = model.config.WEBSITE_CACHE_DIR)

            self.data(cached_obj)
            return 0

        finally:
            if repo is not None:
                repo.close()

    def get_repository_metadata(self):
        """
        Get repository metadata.
        """
        entropy_client = self._entropy()
        try:
            r, a, b, p = self._reposerv_get_params(entropy_client, os.environ)
        except AssertionError as err:
            self.error(err)
            return 1

        repo = None
        try:
            repo = self._api_get_repo(entropy_client, r, a, b, p)
            if repo is None:
                self.error("unavailable repository")
                return 1

            meta = {
                'sets': dict((x, list(y)) for x, y in \
                    repo.retrievePackageSets().items()),
                'treeupdates_actions': repo.listAllTreeUpdatesActions(),
                'treeupdates_digest': repo.retrieveRepositoryUpdatesDigest(r),
                'revision': self._reposerv_get_revision(
                    entropy_client, r, a, b, p),
                'checksum': repo.checksum(do_order = True,
                    strict = False, include_signatures = True),
            }

            response = self._api_base_response(
                WebService.WEB_SERVICE_RESPONSE_CODE_OK)
            response['r'] = meta
            self.data(self._service_render(response))
            return 0
        finally:
            if repo is not None:
                repo.close()


if __name__ == "__main__":

    con = StandaloneController()
    args_map = {
        "service.get_package_ids": con.get_package_ids,
        "service.repository_revision": con.repository_revision,
        "service.get_packages_metadata": con.get_packages_metadata,
        "service.get_repository_metadata": con.get_repository_metadata,
        }

    try:
        func = args_map.get(sys.argv[1])
    except IndexError:
        StandaloneController.error("Invalid parameters")
        raise SystemExit(1)

    if func is None:
        StandaloneController.error("Invalid parameters")
        raise SystemExit(1)

    raise SystemExit(func())
