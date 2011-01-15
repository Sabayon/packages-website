# -*- coding: utf-8 -*-
import logging
import json
log = logging.getLogger(__name__)

from www.lib.base import *
from www.lib.website import *

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

class PackagesController(BaseController,WebsiteController):

    CACHE_DIR = "www/packages_cache"

    def __init__(self):

        BaseController.__init__(self)
        WebsiteController.__init__(self)
        self.valid_search_types = {
            "0": self._search_package,
            "1": self._search_package_match,
            "2": self._search_description,
            "3": self._search_files,
            "4": self._search_libraries,
        }
        self.search_types_strings = {
            "0": _("Packages"),
            "1": _("Packages match"),
            "2": _("Package descriptions"),
            "3": _("Files"),
            "4": _("Libraries"),
        }
        self.order_bys_strings = {
            "0": _("Alphabet"),
            "1": _("Vote"),
            "2": _("Downloads"),
        }
        import www.model.Entropy
        import www.model.UGC
        self.UGC = www.model.UGC.UGC
        self.Entropy = www.model.Entropy.Entropy
        etpConst['entropygid'] = model.config.DEFAULT_WEB_GID

    def _render(self, page):
        rendering_map = {
            'json': self._render_json,
            'html': self._render_mako,
            'jsonp': self._render_jsonp,
            'xml': self._render_xml,
        }
        try:
            renderer = request.params.get('render')
        except AttributeError:
            renderer = None
        return rendering_map.get(renderer, self._render_mako)(page)

    def _render_mako(self, page):
        return render_mako(page)

    def _get_renderer_public_data_map(self):
        json_public_map = {}
        for release in c.search_data['misc']['releases']:
            obj = json_public_map.setdefault(release, [])
            for atom in c.search_data['atoms'][release]:
                obj.append(c.search_data['data'][release][atom])
        json_public_map['__misc__'] = c.search_data['misc']
        return json_public_map

    def _render_json(self, page):
        if not c.search_data:
            return ''
        if not isinstance(c.search_data, dict):
            return ''

        try:
            json_public_map = self._get_renderer_public_data_map()
        except KeyError:
            return ''

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
        try:
            json_public_map = self._get_renderer_public_data_map()
        except KeyError:
            return ''
        try:
            return entropy_tools.xml_from_dict(json_public_map)
        except TypeError:
            return ''

    def __get_cache_item_key(self, cache_item):
        return os.path.join(PackagesController.CACHE_DIR, cache_item)

    def _get_cached(self, cache_item, delta_secs = 86400):

        key = self.__get_cache_item_key(cache_item)
        cur_time = int(time.time())
        cache_time = entropy_dump.getobjmtime(key)
        if (cache_time + delta_secs) < cur_time:
            # expired
            return None
        return entropy_dump.loadobj(key)

    def _save_cached(self, cache_item, item):
        cache_key = self.__get_cache_item_key(cache_item)
        entropy_dump.dumpobj(cache_key, item)

    def _search_package(self, entropy, branch, dbconn, s):
        return dbconn.searchPackages(s, just_id = True)

    def _search_package_match(self, entropy, branch, dbconn, s):
        idpackages, result = dbconn.atomMatch(s, multiMatch = True)
        if result != 0:
            return []
        return idpackages

    def _search_description(self, entropy, branch, dbconn, s):
        if hasattr(dbconn, 'searchPackagesByDescription'):
            results = dbconn.searchPackagesByDescription(s)
        else:
            results = dbconn.searchDescription(s)
        idpackages = []
        for atom, idpackage in results:
            idpackages.append(idpackage)
        return idpackages

    def _search_files(self, entropy, branch, dbconn, s):
        return dbconn.searchBelongs(s, like = True)

    def _search_libraries(self, entropy, branch, dbconn, s):
        return list(dbconn.resolveNeeded(s))

    def _get_package_baseinfo(self, repoid, ugc, idpackage, dbconn):
        data = {}
        data['atom'] = dbconn.retrieveAtom(idpackage)
        data['ugc'] = {}
        data['name'] = dbconn.retrieveName(idpackage)
        data['category'] = dbconn.retrieveCategory(idpackage)
        if data['atom']:
            data['ugc'] = self._get_ugc_info_summary(repoid, entropy_dep.dep_getkey(data['atom']), ugc)
        data['branch'] = dbconn.retrieveBranch(idpackage)
        data['description'] = dbconn.retrieveDescription(idpackage)
        data['download'] = dbconn.retrieveDownloadURL(idpackage)
        data['revision'] = dbconn.retrieveRevision(idpackage)
        data['homepage'] = dbconn.retrieveHomepage(idpackage)
        mysize = dbconn.retrieveSize(idpackage)
        data['size'] = "0b"
        if mysize != None:
            data['size'] = entropy_tools.bytes_into_human(mysize)
        data['digest'] = dbconn.retrieveDigest(idpackage)
        data['idpackage'] = idpackage
        return data

    def __atom_match_official_repo(self, dep, product, arch, branch):
        entropy = self.Entropy()
        repoid = model.config.ETP_REPOSITORY

        try:
            dbconn = entropy._open_db(repoid, arch, product, branch)
            dbconn.validate()
        except (ProgrammingError, OperationalError, SystemDatabaseError):
            try:
                dbconn.close()
            except:
                pass
            return -1, None

        match_id = dbconn.atomMatch(dep)[0]
        dbconn.close()
        return match_id, repoid

    def _get_package_extrainfo(self, product, repoid, arch, ugc, idpackage, dbconn):

        mydata = dbconn.getBaseData(idpackage)
        depdata = {}
        data = {}
        data['atom'] = mydata[0]
        data['ugc'] = {}
        if data['atom']:
            data['ugc'] = self._get_ugc_info(repoid, entropy_dep.dep_getkey(data['atom']), ugc)
        data['branch'] = mydata[11]
        data['cflags'] = mydata[7]
        data['chost'] = mydata[6]
        data['size'] = entropy_tools.bytes_into_human(mydata[17])
        data['license'] = mydata[10].split()
        data['homepage'] = mydata[9]
        data['description'] = mydata[4]
        dependencies = dbconn.retrieveDependencies(idpackage, extended = True)
        for dep, dep_type in dependencies:
            match_repo = repoid
            match_id = dbconn.atomMatch(dep)[0]
            if (match_id == -1) and (repoid != model.config.ETP_REPOSITORY): # search in official repo
                match_id, match_repo = self.__atom_match_official_repo(dep, product, arch, data['branch'])
                if match_repo is None:
                    match_repo = repoid
            depdata[dep] = (match_id, match_repo)
        data['build_deps'] = sorted([x for x, y in dependencies if y == etpConst['dependency_type_ids']['bdepend_id']])
        data['run_deps'] = sorted([x for x, y in dependencies if y == etpConst['dependency_type_ids']['rdepend_id']])
        data['post_deps'] = sorted([x for x, y in dependencies if y == etpConst['dependency_type_ids']['pdepend_id']])
        data['manual_deps'] = sorted([x for x, y in dependencies if y == etpConst['dependency_type_ids']['mdepend_id']])
        data['conflicts'] = dbconn.retrieveConflicts(idpackage)
        data['category'] = mydata[5]
        data['download'] = mydata[12]
        data['name'] = mydata[1]
        data['version'] = mydata[2]
        data['tag'] = mydata[3]
        data['revision'] = mydata[18]
        data['digest'] = mydata[13]
        data['ondisksize'] = entropy_tools.bytes_into_human(dbconn.retrieveOnDiskSize(idpackage))
        data['useflags'] = ' '.join(sorted(dbconn.retrieveUseflags(idpackage)))
        data['creationdate'] = entropy_tools.convert_unix_time_to_human_time(float(mydata[16]))
        data['slot'] = mydata[14]
        data['idpackage'] = idpackage
        data['repo'] = repoid
        data['sha1'], data['sha256'], data['sha512'], data['gpg'] = \
            dbconn.retrieveSignatures(idpackage)
        return data, depdata

    def _generate_search_data(self, entropy, ugc, search_string, product, repoid, arch, branch, searchtype, orderby):

        not_found = False
        if repoid is None:
            repoid = model.config.ETP_REPOSITORY
        if product is None:
            product = model.config.default_product
        if branch is None:
            branch = model.config.default_branch
        if arch is None:
            arch = model.config.default_arch
        c.repoid = repoid
        c.products = model.config.available_products
        c.arches = self._get_available_arches(entropy, repoid, product)

        entries_found = 0
        c.search_data = {
            'data': {},
            'misc': {},
            'atoms': {},
            'entries_found': 0,
            'you_meant': set(),
        }
        if isinstance(search_string, basestring):
            search_string = search_string.strip()
        if (not search_string) or (len(search_string) < 2):
            not_found = True
        if product not in model.config.available_products:
            not_found = True
        if arch not in c.arches:
            not_found = True
        if searchtype not in self.valid_search_types:
            not_found = True

        c.search_data['misc']['product'] = model.config.available_products.get(product)
        c.search_data['misc']['releases'] = set()
        c.search_data['misc']['idproduct'] = product
        c.search_data['misc']['arch'] = arch
        c.product = product
        c.arch = arch
        c.branches = self._get_available_branches(entropy, repoid, product)
        c.repositories = self._get_available_repositories(entropy, product, arch)

        c.searchtype = searchtype
        c.searchtypes = self.search_types_strings
        c.search_string = search_string
        if not orderby: orderby = "0"
        c.order_by = orderby
        c.order_bys = self.order_bys_strings
        if branch not in entropy._get_branches(repoid, c.arch, c.product):
            branch = model.config.default_branch
        c.branch = branch

        if not_found:
            return entries_found

        c.repo_mirrors = entropy._compile_mirror_download_paths(repoid,
            c.product, model.config.ETP_REPOSITORY_DOWNLOAD_MIRRORS)

        if branch in entropy._get_branches(repoid, c.arch, c.product):

            while 1:
                try:
                    dbconn = entropy._open_db(repoid, c.arch, c.product, branch)
                    dbconn.validate()
                except (ProgrammingError, OperationalError, SystemDatabaseError):
                    try:
                        dbconn.close()
                    except:
                        pass
                    break

                func = self.valid_search_types.get(c.searchtype)
                try:
                    idpackages = func(entropy, branch, dbconn, c.search_string)
                except DatabaseError:
                    # database is probably being uploaded
                    # so it's not available atm
                    idpackages = []

                # XXX for now, without paging
                if len(idpackages) > 200:
                    break

                if not idpackages:

                    try:
                        meant_data = entropy.get_meant_packages(search_string,
                            valid_repos = [dbconn])
                    except DatabaseError:
                        # database is probably being uploaded
                        # so it's not available atm
                        meant_data = []
                    for idpackage, dbc in meant_data:
                        data = dbc.retrieveKeySlot(idpackage)
                        if not isinstance(data, tuple):
                            continue
                        keyslot = data[0]+":"+data[1]
                        c.search_data['you_meant'].add(keyslot)

                    dbconn.close()
                    break

                c.search_data['misc']['releases'].add(branch)
                c.search_data['data'][branch] = {}
                c.search_data['atoms'][branch] = []

                c.search_data['entries_found'] += len(idpackages)
                entries_found += len(idpackages)

                for idpackage in idpackages:
                    try:
                        tdata = self._get_package_baseinfo(repoid, ugc, idpackage,
                        dbconn)
                    except DatabaseError:
                        continue
                    myatom = tdata['atom']
                    c.search_data['atoms'][branch].append(myatom)
                    owndata = {}
                    owndata['ugc'] = tdata['ugc']
                    owndata['atom'] = tdata['atom']
                    owndata['description'] = tdata['description']
                    owndata['name'] = tdata['name']
                    owndata['category'] = tdata['category']
                    owndata['branch'] = tdata['branch']
                    owndata['download'] = tdata['download']
                    owndata['revision'] = tdata['revision']
                    owndata['homepage'] = tdata['homepage']
                    owndata['size'] = tdata['size']
                    owndata['digest'] = tdata['digest']
                    owndata['idpackage'] = tdata['idpackage']
                    c.search_data['data'][branch][myatom] = owndata.copy()

                dbconn.close()
                break

        # order by vote
        orderby_dict = {
            "1": "vote",
            "2": "downloads",
        }
        if orderby in orderby_dict:
            myitem = orderby_dict.get(orderby)
            for branch in c.search_data['atoms']:
                items = {}
                for atom in c.search_data['atoms'][branch]:
                    try:
                        myval = c.search_data['data'][branch][atom]['ugc'][myitem]
                    except (TypeError, KeyError):
                        myval = 0.0
                    if not items.has_key(myval):
                        items[myval] = []
                    items[myval].append(atom)
                new_atoms = []
                myvals = sorted(items, reverse = True)
                for myval in myvals:
                    new_atoms.extend(items[myval])
                c.search_data['atoms'][branch] = new_atoms

        c.search_data['misc']['releases'] = \
            sorted(c.search_data['misc']['releases'], reverse = True)
        c.search_data['you_meant'] = sorted(c.search_data['you_meant'])

        return entries_found

    def _get_ugc_info_summary(self, repoid, pkgkey, ugc = None):

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
            ugc = self.UGC()
        mydata = {
            'vote': ugc.get_ugc_vote(pkgkey),
            'downloads': ugc.get_ugc_downloads(pkgkey),
            'docs': len(ugc.get_ugc_metadata_doctypes(pkgkey, [ugc.DOC_TYPES[x] for x in ugc.DOC_TYPES])),
        }
        if close_ugc:
            ugc.disconnect()
            del ugc
        return mydata

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
            ugc = self.UGC()
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
        ugc = self.UGC()
        results, found_rows = ugc.search_content_items(searchstring,
            iddoctypes = doctypes, results_offset = results_offset,
            results_limit = results_limit, order_by = orderby)
        for item in results:
            ugc._get_ugc_extra_metadata(item)
        ugc.disconnect()
        del ugc
        return results, found_rows

    def _search_ugc_keyword(self, searchstring, doctypes, orderby, results_offset, results_limit):
        ugc = self.UGC()
        results, found_rows = ugc.search_keyword_items(searchstring,
            iddoctypes = doctypes, results_offset = results_offset,
            results_limit = results_limit, order_by = orderby)
        for item in results:
            ugc._get_ugc_extra_metadata(item)
        ugc.disconnect()
        del ugc
        return results, found_rows

    def _search_ugc_username(self, searchstring, doctypes, orderby, results_offset, results_limit):
        ugc = self.UGC()
        results, found_rows = ugc.search_username_items(searchstring,
            iddoctypes = doctypes, results_offset = results_offset,
            results_limit = results_limit, order_by = orderby)
        for item in results:
            ugc._get_ugc_extra_metadata(item)
        ugc.disconnect()
        del ugc
        return results, found_rows

    def _search_ugc_pkgname(self, searchstring, doctypes, orderby, results_offset, results_limit):
        ugc = self.UGC()
        results, found_rows = ugc.search_pkgkey_items(searchstring,
            iddoctypes = doctypes, results_offset = results_offset,
            results_limit = results_limit, order_by = orderby)
        for item in results:
            ugc._get_ugc_extra_metadata(item)
        ugc.disconnect()
        del ugc
        return results, found_rows

    def _search_ugc_iddoc(self, searchstring, doctypes, orderby, results_offset, results_limit):
        ugc = self.UGC()
        results, found_rows = ugc.search_iddoc_item(searchstring,
            iddoctypes = doctypes, results_offset = results_offset,
            results_limit = results_limit, order_by = orderby)
        for item in results:
            ugc._get_ugc_extra_metadata(item)
        ugc.disconnect()
        del ugc
        return results, found_rows

    def _generate_feeds(self, entropy, repoid):
        feeds = {}
        for pstring in model.config.available_products:
            arches = self._get_available_arches(entropy, repoid, pstring)
            feeds[pstring] = {}
            for parch in arches:
                for branch in entropy._get_branches(repoid, parch, pstring):
                    feeds[pstring][parch+" "+branch] = model.config.repository_feeds_uri+pstring+"/"+repoid+"/database/"+parch+"/"+branch+"/"+etpConst['rss-name']
                    feeds[pstring][parch+" %s (light)" % (branch,)] = model.config.repository_feeds_uri+pstring+"/"+repoid+"/database/"+parch+"/"+branch+"/"+etpConst['rss-light-name']
        return feeds

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

    def _generate_packages_home(self, index = False):
        model.config.setup_internal(model, c, session, request)

        search_string = request.params.get('searchstring')
        if search_string and not c.search_string:
            c.search_string = search_string

        if c.product not in model.config.available_products:
            c.product = model.config.default_product
        c.products = model.config.available_products

        if not c.repoid:
            c.repoid = model.config.ETP_REPOSITORY

        entropy = self.Entropy()
        c.arches = self._get_available_arches(entropy, c.repoid, c.product)
        c.branches = self._get_available_branches(entropy, c.repoid, c.product)
        c.repositories = self._get_available_repositories(entropy, c.product, None)
        c.searchtype = "0"
        c.searchtypes = self.search_types_strings
        c.order_by = "0"
        c.order_bys = self.order_bys_strings

        c.repository_feeds = {}
        if index:
            c.repository_feeds = self._generate_feeds(entropy, c.repoid)

    def _generate_packages_ugc(self):
        model.config.setup_internal(model, c, session, request)
        c.stype = 0
        c.srest = 0
        c.sorder_by = 0
        c.ugc_searchtypes = {
            0: _("Package name"),
            1: _("Content (text)"),
            2: _("Keyword (tag)"),
            3: _("Username"),
            4: _("Document id."),
        }
        c.ugc_searchrestrict = {
            0: _("No restrictions"),
        }
        c.ugc_searchrestrict.update(c.ugc_doctypes_desc_singular)
        c.ugc_order_by = {
            0: _("Alphabet"),
            1: _("Username"),
            2: _("Vote"),
            3: _("Number of downloads"),
        }
        c.ugc_order_by_string = {
            0: _("key"),
            1: _("username"),
            2: _("vote"),
            3: _("downloads")
        }

        def ugc_search_no_restrictions():
            return c.ugc_doctypes.values()

        def ugc_search_comment_restrict():
            return [c.ugc_doctypes['comments']]

        def ugc_search_image_restrict():
            return [c.ugc_doctypes['image']]

        def ugc_search_generic_file_restrict():
            return [c.ugc_doctypes['generic_file']]

        def ugc_search_yt_video_restrict():
            return [c.ugc_doctypes['youtube_video']]

        self.ugc_searchrestrict_func = {
            None: ugc_search_no_restrictions,
            0: ugc_search_no_restrictions,
            1: ugc_search_comment_restrict,
            3: ugc_search_image_restrict,
            4: ugc_search_generic_file_restrict,
            5: ugc_search_yt_video_restrict,
        }
        self.ugc_searchtypes_func = {
            0: self._search_ugc_pkgname,
            1: self._search_ugc_content,
            2: self._search_ugc_keyword,
            3: self._search_ugc_username,
            4: self._search_ugc_iddoc,
        }
        c.ugc_searchresults_limit = 10

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

    def index(self):

        # support old url path
        search = request.params.get('search')
        arch = request.params.get('arch')
        product = request.params.get('product')
        if search and arch and product:
            branch = model.config.default_branch
            myurl = '/repository/search/%s/%s/%s/%s/%s' % (
                etpConst['officialrepositoryid'], product, arch, branch, search,
            )
            try:
                myurl = str(myurl)
                return redirect(url(myurl))
            except (UnicodeEncodeError, UnicodeDecodeError,):
                pass

        self._generate_packages_home(index = True)
        c.show_search_order = True
        c.page_title = _('Sabayon Linux Packages Repository')
        return self._render('/packages/index.html')

    def get_search_args(self):

        search_types = ("expanded", "compact",)

        try:
            product = str(request.params.get('product'))
            if product not in model.config.available_products:
                raise ValueError
        except (ValueError,TypeError,UnicodeDecodeError,UnicodeEncodeError,):
            return ''

        entropy = self.Entropy()
        repos = self._get_available_repositories(entropy, product, None)
        if not repos:
            # enforce supported product
            product = config.default_product
            repos = self._get_available_repositories(entropy, product, None)
        if not repos:
            # wtf?
            return ''

        try:
            repoid = str(request.params.get('repo'))
            if repoid not in repos:
                # we need to revert to the first available repo
                repoid = sorted(repos)[0] # support the first one
        except (ValueError,TypeError,UnicodeDecodeError,UnicodeEncodeError,):
            return ''

        try:
            search_type = str(request.params.get('search_type'))
            if search_type not in search_types:
                raise ValueError
        except (ValueError,TypeError,UnicodeDecodeError,UnicodeEncodeError,):
            return ''

        arches = self._get_available_arches(entropy, repoid, product)
        c.arches = arches
        c.repositories = repos
        c.branches = self._get_available_branches(entropy, repoid, product)
        c.products = model.config.available_products
        c.repoid = repoid
        c.product = product
        c.dependency_type_ids = etpConst['dependency_type_ids']

        if search_type == "expanded":
            return self._render('/packages/searchparams_args.html')
        return self._render('/packages/searchparams_compact_args.html')

    def home(self):
        self._generate_packages_home()
        c.show_search_order = True
        return self._render('/packages/searchbox.html')

    def ugc(self):
        self._generate_packages_ugc()
        return self._render('/packages/ugc.html')

    def search_ugc_package(self, search_type = None, search_string = None, search_string2 = None):

        repoid = model.config.ETP_REPOSITORY
        entropy = self.Entropy()
        c.repository_feeds = self._generate_feeds(entropy, repoid)
        self._generate_packages_ugc()

        ugc_search_types_map = {
            "package": 0,
            "content": 1,
            "keyword": 2,
            "username": 3,
            "iddoc": 4,
        }

        if search_type not in ugc_search_types_map:
            return self.index()

        search_type = ugc_search_types_map.get(search_type)
        c.stype = search_type

        if not search_string: search_string = ''
        if (len(search_string) < 3) and (search_type != 4):
            return self.index()

        if search_type == 4:
            c.search_expand = True

        if search_string2:
            search_string += "/"+search_string2

        # run query
        restrict_func = self.ugc_searchrestrict_func.get(0)
        doctypes = restrict_func()
        search_func = self.ugc_searchtypes_func.get(search_type)

        orderby = c.ugc_order_by.get(0)
        c.ugc_searchresults, c.found_results = search_func(search_string,
            doctypes, orderby, 0, c.ugc_searchresults_limit)
        c.search_string = search_string
        c.offset = 0

        c.show_search_results = True
        c.page_title = _('Sabayon Linux Packages Repository')
        return self._render('/packages/ugc.html')

    def ugc_search(self):
        if request.method != "POST":
            return self.index()
        self._generate_packages_ugc()

        searchstring = request.params.get('searchstring')
        if not searchstring: searchstring = ''
        if len(searchstring) < 3:
            return "%s: %s" % (_("Error"), _("invalid search string"),)

        try:
            searchtype = int(request.params.get('searchtype'))
            if searchtype not in c.ugc_searchtypes:
                raise ValueError
        except (ValueError,TypeError,):
            return "%s: %s" % (_("Error"), _("invalid search type"),)
        try:
            restrict = int(request.params.get('restrict'))
            if restrict not in c.ugc_searchrestrict:
                raise ValueError
        except (ValueError,TypeError,):
            return "%s: %s" % (_("Error"), _("invalid search restriction type"),)
        try:
            orderby = int(request.params.get('orderby'))
            if orderby not in c.ugc_order_by:
                raise ValueError
        except (ValueError,TypeError,):
            return "%s: %s" % (_("Error"), _("invalid 'order by'"),)

        c.ugc_searchresults = {}
        c.stype = searchtype
        c.srest = restrict
        c.sorder_by = orderby

        # run query
        restrict_func = self.ugc_searchrestrict_func.get(restrict)
        if restrict_func == None:
            restrict_func = self.ugc_searchrestrict_func.get(0)
        doctypes = restrict_func()
        search_func = self.ugc_searchtypes_func.get(searchtype)
        if search_func == None: search_func = self.ugc_searchtypes_func.get(0)

        try:
            offset = int(request.params.get('offset'))
        except (ValueError,TypeError,):
            offset = 0

        c.offset = offset
        c.ugc_searchresults, c.found_results = search_func(searchstring, doctypes, orderby, offset, c.ugc_searchresults_limit)
        c.search_string = searchstring

        return self._render('/packages/ugc_searchresults.html')

    def _do_query_pkg(self, repoid, pkgstring, product, arch, branch, search_type, orderby):
        self._generate_packages_home(index = True)
        entropy = self.Entropy()
        ugc = self.UGC()
        self._generate_search_data(entropy, ugc, pkgstring, product, repoid, arch, branch, search_type, orderby)
        ugc.disconnect()
        del ugc
        c.show_search_results = True
        c.show_search_order = True
        return self._render('/packages/index.html')

    def _do_query_pkg_atom(self, repoid, pkgcat, pkgnamever, product, arch, branch, search_type, orderby):
        self._generate_packages_home(index = True)
        entropy = self.Entropy()
        ugc = self.UGC()
        if not pkgnamever: pkgnamever = ''
        if not pkgcat: pkgcat = ''
        atom = pkgcat+"/"+pkgnamever
        if (not pkgcat) and (not pkgnamever): atom = None
        entries_found = self._generate_search_data(entropy, ugc, atom, product, repoid, arch, branch, search_type, orderby)
        if not entries_found:
            self._generate_search_data(entropy, ugc, atom, product, repoid, arch, branch, "1", orderby) # package match
        ugc.disconnect()
        del ugc
        c.show_search_results = True
        c.show_search_order = True
        return self._render('/packages/index.html')

    # http://URL/repository/search/repoid/product/arch/branch/pkgstring
    def search_pkg(self, repoid = None, pkgstring = None, product = None, arch = None, branch = None):
        return self._do_query_pkg(repoid, pkgstring, product, arch, branch, "0", "0")

    def search_pkg_atom(self, repoid = None, pkgcat = None, pkgnamever = None, product = None, arch = None, branch = None):
        return self._do_query_pkg_atom(repoid, pkgcat, pkgnamever, product, arch, branch, "0", "0")

    def match_pkg(self, repoid = None, pkgstring = None, product = None, arch = None, branch = None):
        return self._do_query_pkg(repoid, pkgstring, product, arch, branch, "1", "0")

    def match_pkg_atom(self, repoid = None, pkgcat = None, pkgnamever = None, product = None, arch = None, branch = None):
        return self._do_query_pkg_atom(repoid, pkgcat, pkgnamever, product, arch, branch, "1", "0")

    def catname(self, category = None, name = None):
        repoid = request.params.get('repo') or None
        arch = request.params.get('arch') or None
        product = request.params.get('product') or None
        branch = request.params.get('branch') or None
        return self._do_query_pkg_atom(repoid, category, name, product, arch, branch, "1", "0")

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

        entropy = self.Entropy()
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

        return self._render('/packages/do_document_page.html')

    def ugc_delete(self):
        model.config.setup_internal(model, c, session, request)

        user_id = self._get_logged_user_id()
        if not user_id:
            return "%s: %s" % (_("Error"), _("not logged in"),)

        try:
            iddoc = int(request.params.get('iddoc'))
        except (ValueError,TypeError,):
            return "%s: %s" % (_("Error"), _("invalid document"),)

        ugc = self.UGC()
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
        ugc = self.UGC()
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
        return self._render('/packages/ugc_show_doc.html')

    def stats(self):

        c.products = model.config.available_products
        c.arches = model.config.available_arches # fine this way
        entropy = self.Entropy()
        repoid = model.config.ETP_REPOSITORY

        overview = self._get_cached('stats')
        if overview is None:

            overview = {}
            for pstring in model.config.available_products:
                overview[pstring] = {}
                arches = self._get_available_arches(entropy, repoid, pstring)
                for parch in arches:
                    overview[pstring][parch] = {}
                    branches = entropy._get_branches(repoid,parch,pstring)
                    packages = 0
                    categories = set()
                    files_number = 0
                    size = 0

                    for branch in branches:
                        try:
                            dbconn = entropy._open_db(repoid, parch, pstring, branch)
                        except (ProgrammingError, OperationalError, SystemDatabaseError):
                            try:
                                dbconn.close()
                            except:
                                pass
                            continue
                        try:

                            if hasattr(dbconn, 'listAllIdpackages'):
                                # backward compat
                                packages += len(dbconn.listAllIdpackages())
                            else:
                                packages += len(dbconn.listAllPackageIds())
                            categories |= set(dbconn.listAllCategories())

                            if hasattr(dbconn, 'cursor'):
                                dbconn.cursor.execute('select sum(size) from extrainfo')
                                size += dbconn.cursor.fetchone()[0]
                            else:
                                cur = dbconn._cursor().execute('SELECT sum(size) FROM extrainfo')
                                size += cur.fetchone()[0]

                            dbconn.close()

                        except (ProgrammingError, OperationalError,):
                            try:
                                dbconn.close()
                            except:
                                pass
                            continue

                    categories = len(categories)
                    overview[pstring][parch]['branches'] = ', '.join(branches)
                    overview[pstring][parch]['packages'] = packages
                    overview[pstring][parch]['categories'] = categories
                    overview[pstring][parch]['files_number'] = files_number
                    overview[pstring][parch]['repo_size'] = entropy_tools.bytes_into_human(size)

            self._save_cached('stats', overview)


        c.repoid = repoid
        c.overview = overview
        return self._render('/packages/stats.html')

    def htsearch(self):

        if request.method != "POST":
            return self.index()

        model.config.setup_internal(model, c, session, request)
        entropy = self.Entropy()
        ugc = self.UGC()

        searchtype = request.params.get('searchtype')
        orderby = request.params.get('orderby')
        if not orderby:
            orderby = "0"

        arch = request.params.get('arch')
        product = request.params.get('product')
        branch = request.params.get('branch')
        repoid = request.params.get('repo')

        # kill missing params
        if not arch:
            return self.index()
        elif not product:
            return self.index()
        elif not branch:
            return self.index()
        elif not repoid:
            return self.index()

        entries_found = self._generate_search_data(
            entropy, ugc, request.params.get('searchstring'),
            product, repoid, arch, branch, searchtype, orderby
        )
        if not entries_found and searchtype == "0":
            self._generate_search_data(
                entropy, ugc, request.params.get('searchstring'),
                product, repoid, arch, branch, "1", orderby # search matches
            )
        c.show_search_order = True
        ugc.disconnect()
        del ugc
        return self._render('/packages/searchresults.html')

    def search(self):
        """
        Public API for searching, answering to: http://host/search
        GET parameters:
        q=<query>: search keyword [mandatory]
        a=<arch>: architecture [default: amd64]
        t=<type>: search type (pkg, match, desc, file. lib) [default: pkg]
        r=<repo>: repository id [default: sabayonlinux.org]
        b=<branch>: repository branch [default: 5]
        p=<product>: product [default: standard]
        o=<order by>: order packages by (alphabet, vote, downloads)
        """
        q = request.params.get('q')
        if not q:
            return self.index()

        model.config.setup_internal(model, c, session, request)
        entropy = self.Entropy()
        search_types = {
            'pkg': "0",
            'match': "1",
            'desc': "2",
            'lib': "4",
            'file': "3",
        }
        order_by_types = {
            'alphabet': "0",
            'vote': "1",
            'downloads': "2",
        }

        # arch
        a = request.params.get('a') or model.config.default_arch
        if a not in model.config.available_arches:
            a = model.config.default_arch

        # product
        p = request.params.get('p') or model.config.default_product
        if p not in model.config.available_products:
            p = model.config.default_product

        avail_repos = self._get_available_repositories(entropy, p, a)

        # search type
        t = request.params.get('t') or "pkg"
        t = search_types.get(t, search_types.get("pkg"))

        # repository
        r = request.params.get('r') or model.config.ETP_REPOSITORY
        if r not in avail_repos:
            return self.index()

        # validate arch
        avail_arches = self._get_available_arches(entropy, r, p)
        if a not in avail_arches:
            return self.index()

        # branch
        b = request.params.get('b') or model.config.default_branch
        if b not in self._get_available_branches(entropy, r, p):
            return self.index()

        # order by
        o = request.params.get('o') or "alphabet"
        o = order_by_types.get(o, order_by_types.get("alphabet"))

        return self._do_query_pkg(r, q, p, a, b, t, o)

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
                ugc = self.UGC()
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
        return self._render('/packages/voted.html')

    def extrainfo(self):
        model.config.setup_internal(model, c, session, request)

        c.products = model.config.available_products
        c.searchtypes = self.search_types_strings
        entropy = self.Entropy()
        ugc = self.UGC()

        not_found, idpackage, product, repo, arch, branch = \
            self._get_post_get_idpackage_product_arch_branch(entropy)
        c.arches = {}
        if (repo and product):
            c.arches = self._get_available_arches(entropy, repo, product)
        c.repoid = repo

        atominfo = {}
        atominfo['idproduct'] = product
        atominfo['product'] = model.config.available_products.get(product)
        atominfo['arch'] = arch
        atominfo['repo'] = repo
        depdata = {}
        c.product = product
        c.arch = arch
        c.branch = branch
        c.repoid = repo

        if not not_found:

            c.repo_mirrors = entropy._compile_mirror_download_paths(repo, product, model.config.ETP_REPOSITORY_DOWNLOAD_MIRRORS)

            valid = True
            try:
                dbconn = entropy._open_db(repo, arch, product, branch)
                dbconn.validate()
            except (ProgrammingError, OperationalError, SystemDatabaseError):
                try:
                    dbconn.close()
                except:
                    pass
                valid = False

            try:
                if hasattr(dbconn, 'isIDPackageAvailable'):
                    pkg_id_avail = dbconn.isIDPackageAvailable(idpackage)
                else:
                    pkg_id_avail = dbconn.isPackageIdAvailable(idpackage)

                if valid and pkg_id_avail:
                    mydata, depdata = self._get_package_extrainfo(product, repo, arch, ugc, idpackage, dbconn)
                    atominfo.update(mydata)
            except: # trap DatabaseError and other sync shit
                pass
            if valid:
                try:
                    dbconn.close()
                except:
                    pass

        c.atominfo = atominfo
        c.depdata = depdata
        ugc.disconnect()
        del ugc
        return self._render("/packages/extrainfo.html")

    def depends(self):

        entropy = self.Entropy()
        not_found, idpackage, product, repo, arch, branch = \
            self._get_post_get_idpackage_product_arch_branch(entropy)
        c.repoid = repo

        c.miscinfo = {}
        c.miscinfo['arch'] = arch
        c.miscinfo['product'] = product
        c.miscinfo['repo'] = repo
        c.miscinfo['branch'] = branch
        c.idpackages = {}

        if not not_found:

            valid = True
            try:
                dbconn = entropy._open_db(repo, arch, product, branch)
                dbconn.validate()
            except (ProgrammingError, OperationalError,SystemDatabaseError):
                try:
                    dbconn.close()
                except:
                    pass
                valid = False

            if valid:
                if hasattr(dbconn, 'retrieveDepends'):
                    # backward compatibility
                    mydepends = dbconn.retrieveDepends(idpackage)
                else:
                    mydepends = dbconn.retrieveReverseDependencies(idpackage)
                for mydepend in mydepends:
                    c.idpackages[mydepend] = dbconn.retrieveAtom(mydepend)
                dbconn.close()
        return self._render('/packages/depends.html')

    def content(self):

        entropy = self.Entropy()

        not_found, idpackage, product, repo, arch, branch = \
            self._get_post_get_idpackage_product_arch_branch(entropy)
        c.repoid = repo

        c.miscinfo = {}
        c.miscinfo['arch'] = arch
        c.miscinfo['product'] = product
        c.miscinfo['repo'] = repo
        c.miscinfo['branch'] = branch
        c.idpackages = {}
        c.files = []
        c.idpackage = idpackage
        c.branch = branch

        if not not_found:

            valid = True
            try:
                dbconn = entropy._open_db(repo, arch, product, branch)
                dbconn.validate()
            except (ProgrammingError, OperationalError,SystemDatabaseError):
                try:
                    dbconn.close()
                except:
                    pass
                valid = False

            if valid:
                c.files = dbconn.retrieveContent(idpackage, order_by = 'file')
                dbconn.close()

        return self._render('/packages/content.html')

    def getadvisory(self):

        entropy = self.Entropy()

        atom = request.params.get('atom')
        if not atom:
            return ''

        repo = request.params.get('atom')
        if not repo:
            return ''
        c.repoid = repo

        key = entropy_dep.dep_getkey(atom)
        if not key: return ''

        name = key.split("/")[1]
        import feedparser
        feed = feedparser.parse(model.config.GLSA_URI)
        entries = 2000 # infinite
        strip = None
        # now filter good ones
        myfeed = {}
        myfeed['entries'] = []
        for item in feed['entries']:
            if item['title'].find(name) != -1:
                myfeed['entries'].append(item.copy())

        c.strip = strip
        c.entries = entries
        c.feed = myfeed
        return self._render('/packages/feed.html')

    def advisories(self):
        c.entries = 50
        c.strip = None
        feed_data = self._get_cached('advisories')
        if feed_data is None:
            import feedparser
            c.feed = feedparser.parse(model.config.GLSA_URI)
            self._save_cached('advisories', c.feed)
        else:
            c.feed = feed_data
        return self._render('/packages/advisories.html')

    def categories(self):
        self._generate_packages_home()
        c.hide_search_type = True
        return self._render('/packages/categories.html')

    def show_categories(self):

        product = request.params.get('product')
        if not product:
            return ''
        arch = request.params.get('arch')
        if not arch:
            return ''
        repo = request.params.get('repo')
        if not repo:
            return ''
        c.repoid = repo

        if product not in model.config.available_products:
            return ''

        entropy = self.Entropy()
        arches = self._get_available_arches(entropy, repo, product)

        if arch not in arches:
            return ''

        c.categories = {}
        c.miscinfo = {}
        c.miscinfo['product'] = product
        c.miscinfo['arch'] = model.config.available_arches.get(arch)
        c.miscinfo['idarch'] = arch
        c.miscinfo['product'] = model.config.available_products.get(product)
        c.miscinfo['repo'] = repo
        c.miscinfo['idproduct'] = product
        branches = entropy._get_branches(repo, arch, product)

        for branch in branches:

            try:
                dbconn = entropy._open_db(repo, arch, product, branch)
                dbconn.validate()
            except (ProgrammingError, OperationalError, SystemDatabaseError):
                try:
                    dbconn.close()
                except:
                    pass
                continue

            categories = dbconn.listAllCategories(order_by = 'category')
            for category in categories:
                s = category[0].lower()
                if s not in c.categories:
                    c.categories[s] = []
                c.categories[s].append(category)
            dbconn.close()

        return self._render('/packages/show_categories.html')

    def category(self):

        product = request.params.get('product')
        if not product:
            return ''
        arch = request.params.get('arch')
        if not arch:
            return ''
        repo = request.params.get('repo')
        if not arch:
            return ''
        c.repoid = repo

        if product not in model.config.available_products:
            return ''

        entropy = self.Entropy()
        arches = self._get_available_arches(entropy, repo, product)
        if arch not in arches:
            return ''

        cat = request.params.get('cat')
        if not cat:
            return ''

        branches = entropy._get_branches(repo, arch, product)
        c.miscinfo = {}
        c.miscinfo['product'] = product
        c.miscinfo['arch'] = model.config.available_arches.get(arch)
        c.miscinfo['idarch'] = arch
        c.miscinfo['product'] = model.config.available_products.get(product)
        c.miscinfo['repo'] = repo
        c.miscinfo['idproduct'] = product
        c.packages = {}
        c.atoms = {}
        c.cat = cat

        for branch in branches:

            try:
                dbconn = entropy._open_db(repo, arch, product, branch)
                dbconn.validate()
            except (ProgrammingError, OperationalError, SystemDatabaseError):
                try:
                    dbconn.close()
                except:
                    pass
                continue

            c.packages[branch] = {}
            c.atoms[branch] = []

            idpackages = dbconn.listPackageIdsInCategory(cat)
            for idpackage in idpackages:
                myatom = dbconn.retrieveAtom(idpackage)
                if not myatom:
                    continue
                myatom = myatom.split("/")[1]
                c.atoms[branch].append(myatom)
                c.packages[branch][myatom] = {}
                c.packages[branch][myatom]['description'] = dbconn.retrieveDescription(idpackage)
                c.packages[branch][myatom]['idpackage'] = idpackage

            dbconn.close()

        return self._render('/packages/category.html')

    def releases(self):
        self._generate_packages_home()
        c.hide_search_type = True
        return self._render('/packages/releases.html')

    def show_release(self):

        product = request.params.get('product')
        if not product:
            return ''
        arch = request.params.get('arch')
        if not arch:
            return ''
        repo = request.params.get('repo')
        if not repo:
            return ''
        c.repoid = repo

        if product not in model.config.available_products:
            return ''

        entropy = self.Entropy()
        arches = self._get_available_arches(entropy, repo, product)
        if arch not in arches:
            return ''

        branches = entropy._get_branches(repo, arch, product)
        c.miscinfo = {}
        c.miscinfo['product'] = product
        c.miscinfo['arch'] = model.config.available_arches.get(arch)
        c.miscinfo['idarch'] = arch
        c.miscinfo['product'] = model.config.available_products.get(product)
        c.miscinfo['repo'] = repo
        c.miscinfo['idproduct'] = product
        c.miscinfo['branches'] = branches

        return self._render('/packages/release.html')

    def release(self):

        product = request.params.get('product')
        if not product:
            return ''
        arch = request.params.get('arch')
        if not arch:
            return ''
        repo = request.params.get('repo')
        if not repo:
            return ''
        c.repoid = repo

        if product not in model.config.available_products:
            return ''

        entropy = self.Entropy()
        arches = self._get_available_arches(entropy, repo, product)
        if arch not in model.config.available_arches:
            return ''
        branch = request.params.get('branch')

        branches = entropy._get_branches(repo, arch, product)
        if branch not in branches:
            return ''

        c.miscinfo = {}
        c.miscinfo['product'] = product
        c.miscinfo['arch'] = model.config.available_arches.get(arch)
        c.miscinfo['idarch'] = arch
        c.miscinfo['product'] = model.config.available_products.get(product)
        c.miscinfo['idproduct'] = product
        c.miscinfo['repo'] = repo
        c.miscinfo['branches'] = branches
        c.miscinfo['branch'] = branch

        c.atoms = {}
        c.letters = set()

        valid = True
        try:
            dbconn = entropy._open_db(repo, arch, product, branch)
            dbconn.validate()
        except (ProgrammingError, OperationalError, SystemDatabaseError):
            try:
                dbconn.close()
            except:
                pass
            valid = False

        if valid:
            for myatom, idpackage, branch in dbconn.listAllPackages(order_by="atom"):
                myupper = myatom[0].upper()
                if not c.atoms.has_key(myupper):
                    c.atoms[myupper] = []
                    c.letters.add(myupper)
                c.atoms[myupper].append((myatom,idpackage))
            dbconn.close()

        c.letters = sorted(c.letters)
        return self._render('/packages/show_release.html')
