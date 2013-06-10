#!/usr/bin/python2

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

from entropy.services.client import WebService

class StandaloneController(ApibaseController):

    def __init__(self):
        super(StandaloneController, self).__init__()
        # drop this
        model.config.WEBSITE_CACHE_DIR = "/tmp/cache"

    @classmethod
    def error(cls, msg):
        sys.stderr.write(msg)
        sys.stderr.flush()

    @classmethod
    def data(cls, text):
        sys.stdout.write(text)
        sys.stdout.flush()

    def get_package_ids(self):
        entropy_client = self._entropy()
        try:
            r, a, b, p = self._reposerv_get_params(entropy_client, os.environ)
        except AssertionError as err:
            self.error("%s\n" % (err,))
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


if __name__ == "__main__":

    # params are passed via env
    env = {
        "arch": "amd64",
        "product": "standard",
        "branch": "5",
        "__repository_id__": "sabayonlinux.org",
        }
    os.environ.update(env)

    con = StandaloneController()
    args_map = {
        "packages.get_package_ids": con.get_package_ids
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
