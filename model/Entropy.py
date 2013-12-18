# -*- coding: utf-8 -*-
import os
import threading

import config
from entropy.const import *
from entropy.exceptions import SystemDatabaseError
etpConst['entropygid'] = config.DEFAULT_WEB_GID
from entropy.client.interfaces import Client
from entropy.db import EntropyRepository
from entropy.db.exceptions import DatabaseError
from entropy.cache import EntropyCacher
# do not write to memory, especially when xcache=False
# this is just enforced here.
EntropyCacher.STASHING_CACHE = False

import entropy.tools

class Entropy(Client):

    def init_singleton(self):
        Client.init_singleton(self, noclientdb = 2, repo_validation = False,
            load_ugc = False, xcache = False)
        try:
            self.clientLog.close()
        except (AttributeError, IOError, OSError,):
            pass

    def _guess_repo_db_path(self, repoid, arch, product, branch = None):

        product = os.path.basename(product)
        repoid = os.path.basename(repoid)
        arch = os.path.basename(arch)
        if branch is not None:
            branch = os.path.basename(branch)

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

    def _get_branches(self, repoid, arch, product):

        # validate
        product = os.path.basename(product)
        repoid = os.path.basename(repoid)
        arch = os.path.basename(arch)

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

        # validate
        product = os.path.basename(product)
        repoid = os.path.basename(repoid)

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
        # validate
        product = os.path.basename(product)
        if arch is not None:
            arch = os.path.basename(arch)

        supported_repo_dir = os.path.join(config.MY_ETP_DIR, product)
        if os.path.isdir(supported_repo_dir):
            for repoid in os.listdir(supported_repo_dir):
                repoid_dir_path = os.path.join(supported_repo_dir, repoid,
                    config.MY_ETP_DBDIR)
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

    def get_mirrors(self, repoid, arch, product, branch):
        """
        Get Repository built-in mirrors.
        """
        dir_path = self._guess_repo_db_path(repoid, arch, product, branch)
        if dir_path is None:
            return tuple()

        mirror_path = os.path.join(
            dir_path, etpConst['etpdatabasemirrorsfile'])
        if not os.path.isfile(mirror_path):
            return tuple()

        mirrors = entropy.tools.generic_file_content_parser(
            mirror_path, encoding=etpConst['conf_encoding'])

        expanded_mirrors = []
        for mirror in mirrors:
            mirror = entropy.tools.expand_plain_package_mirror(
                mirror, product, repoid)
            expanded_mirrors.append(mirror)

        return tuple(expanded_mirrors)

    _open_db_tls = threading.local()

    def _open_db(self, repoid, arch, product, branch, xcache = False):
        """
        xcache is False by default, because in most cases (like search functions)
        the repository is opened once and used once and then, closed.
        This causes checksum() to be calculated every time atomMatch is called,
        due to xcache being enabled. So, xcache is disabled by defalt.
        """
        dir_path = self._guess_repo_db_path(repoid, arch, product, branch)
        if dir_path is None:
            return None
        db_path = os.path.join(dir_path, etpConst['etpdatabasefile'])
        if not os.path.isfile(db_path):
            return None
        if os.path.getsize(db_path) < 10:
            return None

        if not hasattr(self._open_db_tls, "cache"):
            self._open_db_tls.cache = {}

        cache_key = (repoid, arch, product, branch)
        if cache_key in self._open_db_tls.cache:
            return self._open_db_tls.cache[cache_key]

        try:
            repo = EntropyRepository(
                readOnly = True,
                dbFile = db_path,
                name = repoid,
                xcache = xcache,
                indexing = True,
                direct = True,
                skipChecks = True)
        except DatabaseError as err:
            sys.stderr.write("Error opening %s: %s\n" % (
                    db_path, repr(err),))
            repo = None

        self._open_db_tls.cache[cache_key] = repo
        return repo

    def output(*myargs, **mykwargs):
        pass
