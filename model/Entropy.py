# -*- coding: utf-8 -*-
import os
import config
from entropy.const import *
from entropy.exceptions import SystemDatabaseError
etpConst['entropygid'] = config.DEFAULT_WEB_GID
from entropy.client.interfaces import Client

class Entropy(Client):

    def init_singleton(self):
        Client.init_singleton(self, noclientdb = 2, repo_validation = False,
            load_ugc = False, xcache = False)
        try:
            self.clientLog.close()
        except (AttributeError, IOError, OSError,):
            pass

    def _guess_repo_db_path(self, repoid, arch, product, branch = None):

        repo_dir = os.path.join(config.MY_ETP_DIR, product, repoid)
        if not os.path.isdir(repo_dir):
            repo_dir = os.path.join(config.COMMUNITY_REPOS_DIR, repoid, product,
                repoid)

        if not os.path.isdir(repo_dir):
            return

        mypath = os.path.join(repo_dir, config.MY_ETP_DBDIR, arch)
        if branch:
            mypath = os.path.join(mypath, branch)

        return mypath

    def _guess_repo_packages_path(self, repoid, arch, product, branch = None):
        repo_dir = os.path.join(config.MY_ETP_DIR, product, repoid)
        if not os.path.isdir(repo_dir):
            repo_dir = os.path.join(config.COMMUNITY_REPOS_DIR, repoid,
                product, repoid)

        mypath = os.path.join(repo_dir, config.MY_ETP_PKGDIR, arch)
        if branch:
            mypath = os.path.join(mypath, branch)
        return mypath

    def _compile_mirror_download_paths(self, repoid, product, mirrors):
        new_mirrors = []
        for mirror in mirrors:
            new_mirrors.append(os.path.join(mirror,product,repoid))
        return new_mirrors

    def _get_branches(self, repoid, arch, product):
        branches = []
        dir_path = self._guess_repo_db_path(repoid, arch, product)
        if dir_path is None:
            return branches
        if os.path.isdir(dir_path):
            items = os.listdir(dir_path)
            for item in items:
                if os.path.isdir(os.path.join(dir_path,item)):
                    branches.append(item)
        return branches

    def _get_arches(self, repoid, product):

        supported_arches = config.available_arches.copy()
        arches = []

        repo_dir = os.path.join(config.MY_ETP_DIR, product, repoid)
        if os.path.isdir(repo_dir):
            arches = os.listdir(os.path.join(repo_dir, config.MY_ETP_DBDIR))
        else:
            repo_dir = os.path.join(config.COMMUNITY_REPOS_DIR, repoid, product,
                repoid)
            if os.path.isdir(repo_dir):
                arches = os.listdir(os.path.join(repo_dir, config.MY_ETP_DBDIR))

        found_arches = dict((x, supported_arches.get(x, x),) for x in arches)

        return found_arches

    def _get_repositories(self, product, arch = None):
        repositories = []

        supported_repo_dir = os.path.join(config.MY_ETP_DIR, product)
        if os.path.isdir(supported_repo_dir):
            for repoid in os.listdir(supported_repo_dir):
                repoid_dir_path = os.path.join(supported_repo_dir, repoid, config.MY_ETP_DBDIR)
                if not os.path.isdir(repoid_dir_path):
                    continue
                if arch in os.listdir(repoid_dir_path) or (arch is None):
                    repositories.append(repoid)

        community_repo_dir = os.path.join(config.COMMUNITY_REPOS_DIR)
        if os.path.isdir(community_repo_dir):
            for repoid in os.listdir(community_repo_dir):
                # also check product first
                repoid_dir_path = os.path.join(community_repo_dir, repoid, product)
                if not os.path.isdir(repoid_dir_path):
                    # no product avail
                    continue
                repoid_dir_path = os.path.join(repoid_dir_path, repoid,
                    config.MY_ETP_DBDIR)
                if not os.path.isdir(repoid_dir_path):
                    continue
                if arch in os.listdir(repoid_dir_path) or (arch is None):
                    repositories.append(repoid)

        return sorted([x for x in set(repositories) if x not \
            in config.disabled_repositories]) # remove dupies

    def _open_db(self, repoid, arch, product, branch):
        dir_path = self._guess_repo_db_path(repoid, arch, product, branch)
        db_path = os.path.join(dir_path, etpConst['etpdatabasefile'])
        db_path_lock = os.path.join(dir_path, etpConst['etpdatabasedownloadlockfile'])
        if os.path.isfile(db_path_lock):
            # temporarily not available
            raise SystemDatabaseError("temporarily not available")
        return self.open_generic_repository(db_path, xcache = True,
            read_only = True, indexing_override = False)

    def output(*myargs, **mykwargs):
        pass

