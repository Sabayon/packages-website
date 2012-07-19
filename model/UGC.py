# -*- coding: utf-8 -*-
import os
import time
import subprocess
import shutil
from datetime import datetime

import MySQLdb

# python-gdata
import gdata
import gdata.youtube
import gdata.youtube.service

import config

from entropy.const import etpConst, const_setup_perms, const_get_stringtype, \
    const_set_chmod, const_setup_file
etpConst['entropygid'] = config.DEFAULT_WEB_GID
import entropy.dump
import entropy.tools

import entropy.exceptions as etp_exceptions
from entropy.misc import EntropyGeoIP
from entropy.client.services.interfaces import Document, DocumentFactory
from entropy.core.settings.base import SystemSettings
from entropy.i18n import _

from www.lib.mysql import Database
from www.lib.exceptions import ServiceConnectionError


class DistributionUGCInterface(Database):

    # ONLY WITH INNODB, ON DELETE CASCADE WORKS !!!
    # INNODB is much slower for big data (it seems), that's why it's not
    # used everywhere
    SQL_TABLES = {
        'entropy_base': """
            CREATE TABLE `entropy_base` (
            `idkey` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            `key` VARCHAR( 255 )  collate utf8_bin NOT NULL,
            UNIQUE KEY `key` (`key`)
            ) ENGINE=INNODB;
        """,
        'entropy_votes': """
            CREATE TABLE `entropy_votes` (
            `idvote` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            `idkey` INT UNSIGNED NOT NULL,
            `userid` INT UNSIGNED NOT NULL,
            `vdate` DATE NOT NULL,
            `vote` TINYINT NOT NULL,
            `ts` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY  (`idkey`) REFERENCES `entropy_base` (`idkey`)
            ) ENGINE=INNODB;
        """,
        'entropy_user_scores': """
            CREATE TABLE `entropy_user_scores` (
            `userid` INT UNSIGNED NOT NULL PRIMARY KEY,
            `score` INT UNSIGNED NOT NULL DEFAULT 0
            ) ENGINE=INNODB;
        """,
        'entropy_downloads': """
            CREATE TABLE `entropy_downloads` (
            `iddownload` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            `idkey` INT UNSIGNED NOT NULL,
            `ddate` DATE NOT NULL,
            `count` INT UNSIGNED NOT NULL DEFAULT '0',
            UNIQUE KEY `idkey` (`idkey`,`ddate`),
            KEY `idkey_2` (`idkey`),
            FOREIGN KEY  (`idkey`) REFERENCES `entropy_base` (`idkey`)
            ) ENGINE=INNODB;
        """,
        'entropy_total_downloads': """
            CREATE TABLE `entropy_total_downloads` (
            `idtotaldownload` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            `idkey` INT UNSIGNED NOT NULL,
            `count` INT UNSIGNED NULL DEFAULT '0',
            UNIQUE KEY `idkey` (`idkey`),
            FOREIGN KEY  (`idkey`) REFERENCES `entropy_base` (`idkey`)
            ) ENGINE=INNODB;
        """,
        'entropy_docs': """
            CREATE TABLE `entropy_docs` (
            `iddoc` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            `idkey` INT UNSIGNED NOT NULL,
            `userid` INT UNSIGNED NOT NULL,
            `username` VARCHAR( 255 ),
            `iddoctype` TINYINT NOT NULL,
            `ddata` TEXT NOT NULL,
            `title` VARCHAR( 512 ),
            `description` VARCHAR( 4000 ),
            `ts` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            KEY `idkey` (`idkey`),
            KEY `userid` (`userid`),
            KEY `idkey_2` (`idkey`,`userid`,`iddoctype`),
            KEY `title` (`title`(333)),
            KEY `description` (`description`(333)),
            FOREIGN KEY  (`idkey`) REFERENCES `entropy_base` (`idkey`)
            ) ENGINE=INNODB;
        """,
        'entropy_doctypes': """
            CREATE TABLE `entropy_doctypes` (
            `iddoctype` TINYINT NOT NULL PRIMARY KEY,
            `description` TEXT NOT NULL
            ) ENGINE=INNODB;
        """,
        'entropy_docs_keywords': """
            CREATE TABLE `entropy_docs_keywords` (
            `iddoc` INT UNSIGNED NOT NULL,
            `keyword` VARCHAR( 100 ) NOT NULL,
            KEY `keyword` (`keyword`),
            FOREIGN KEY  (`iddoc`) REFERENCES `entropy_docs` (`iddoc`)
                ON DELETE CASCADE
            ) ENGINE=INNODB;
        """,
        'entropy_distribution_usage': """
            CREATE TABLE `entropy_distribution_usage` (
            `entropy_distribution_usage_id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            `entropy_branches_id` INT NOT NULL,
            `entropy_release_strings_id` INT NOT NULL,
            `ts` TIMESTAMP ON UPDATE CURRENT_TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            `ip_address` VARCHAR( 15 ) NOT NULL,
            `entropy_ip_locations_id` INT UNSIGNED NOT NULL DEFAULT 0,
            `creation_date` DATETIME NOT NULL,
            `hits` INT UNSIGNED NOT NULL DEFAULT 0,
            FOREIGN KEY  (`entropy_branches_id`) REFERENCES `entropy_branches` (`entropy_branches_id`),
            FOREIGN KEY  (`entropy_release_strings_id`)
                REFERENCES `entropy_release_strings` (`entropy_release_strings_id`),
            UNIQUE KEY `ip_address` (`ip_address`),
            KEY `entropy_ip_locations_id` (`entropy_ip_locations_id`)
            ) ENGINE=INNODB;
        """,
        'entropy_hardware_usage': """
            CREATE TABLE `entropy_hardware_usage` (
            `entropy_hardware_usage_id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            `entropy_distribution_usage_id` INT UNSIGNED NOT NULL,
            `entropy_hardware_hash` VARCHAR ( 80 ),
            FOREIGN KEY  (`entropy_distribution_usage_id`)
                REFERENCES `entropy_distribution_usage` (`entropy_distribution_usage_id`)
            ) ENGINE=INNODB;
        """,
        'entropy_branches': """
            CREATE TABLE `entropy_branches` (
            `entropy_branches_id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            `entropy_branch` VARCHAR( 100 ),
            UNIQUE KEY `entropy_branch` (`entropy_branch`)
            ) ENGINE=INNODB;
        """,
        'entropy_release_strings': """
            CREATE TABLE `entropy_release_strings` (
            `entropy_release_strings_id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            `release_string` VARCHAR( 255 )
            ) ENGINE=INNODB;
        """,
        'entropy_ip_locations': """
            CREATE TABLE `entropy_ip_locations` (
            `entropy_ip_locations_id` INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
            `ip_latitude` FLOAT( 8,5 ),
            `ip_longitude` FLOAT( 8,5 ),
            KEY `ip_locations_lat_lon` (`ip_latitude`,`ip_longitude`)
            ) ENGINE=INNODB;
        """,
    }
    VOTE_RANGE = list(range(1, 6))
    VIRUS_CHECK_EXEC = '/usr/bin/clamscan'
    VIRUS_CHECK_ARGS = []
    entropy_docs_title_len = 512
    entropy_docs_description_len = 4000
    entropy_docs_keyword_len = 100
    COMMENTS_SCORE_WEIGHT = 5
    DOCS_SCORE_WEIGHT = 10
    VOTES_SCORE_WEIGHT = 2
    STATS_MAP = {
        'installer': "installer",
    }

    def __init__(self, connection_data, store_path, store_url = None):

        if store_url is None:
            store_url = ""
        self._store_url = store_url
        self.FLOOD_INTERVAL = 30
        self.DOC_TYPES = {
            'comments': Document.COMMENT_TYPE_ID,
            'image': Document.IMAGE_TYPE_ID,
            'generic_file': Document.FILE_TYPE_ID,
            'youtube_video': Document.VIDEO_TYPE_ID,
            'icon': Document.ICON_TYPE_ID,
        }
        self.UPLOADED_DOC_TYPES = [
            self.DOC_TYPES['image'],
            self.DOC_TYPES['icon'],
            self.DOC_TYPES['generic_file']
        ]
        Database.__init__(self)
        self.set_connection_data(connection_data)
        self.connect()
        self._initialize_tables()
        self._initialize_doctypes()
        self._setup_store_path(store_path)
        self.__system_settings = SystemSettings()
        self._system_name = self.__system_settings['system']['name']

    def _get_geoip_data_from_ip_address(self, ip_address):
        geoip_dbpath = self.connection_data.get('geoip_dbpath', '')
        if os.path.isfile(geoip_dbpath) and os.access(geoip_dbpath, os.R_OK):
            try:
                geo = EntropyGeoIP(geoip_dbpath)
                return geo.get_geoip_record_from_ip(ip_address)
            except: # lame, but I don't know what exceptions are thrown
                pass

    def _setup_store_path(self, path):
        path = os.path.realpath(path)
        if not os.path.isabs(path):
            raise etp_exceptions.PermissionDenied("not a valid directory path")
        if not os.path.isdir(path):
            try:
                os.makedirs(path)
            except OSError as err:
                raise etp_exceptions.PermissionDenied(err)
            if etpConst['entropygid'] != None:
                const_setup_perms(path, etpConst['entropygid'],
                    recursion = False)
        self.STORE_PATH = path

    def _initialize_tables(self):
        notable = False
        for table in self.SQL_TABLES:
            if self.table_exists(table):
                continue
            notable = True
            self.execute_script(self.SQL_TABLES[table])
        if notable:
            self.commit()

    def _is_iddoctype_available(self, iddoctype):
        rows = self.execute_query("""
        SELECT `iddoctype` FROM entropy_doctypes WHERE `iddoctype` = %s
        """, (iddoctype,))
        if rows:
            return True
        return False

    def _initialize_doctypes(self):
        for mydoctype in self.DOC_TYPES:
            if self._is_iddoctype_available(self.DOC_TYPES[mydoctype]):
                continue
            self.execute_query("""
            INSERT INTO entropy_doctypes VALUES (%s, %s)
            """, (self.DOC_TYPES[mydoctype], mydoctype,))

    def _insert_entropy_release_string(self, release_string):
        self.execute_query("""
        INSERT INTO entropy_release_strings VALUES (%s, %s)
        """, (None, release_string,))
        return self.lastrowid()

    def _insert_entropy_ip_locations_id(self, ip_latitude, ip_longitude):
        self.execute_query("""
        INSERT INTO entropy_ip_locations VALUES (%s, %s, %s)
        """, (None, ip_latitude, ip_longitude,))
        return self.lastrowid()

    def _handle_entropy_ip_locations_id(self, ip_addr):
        entropy_ip_locations_id = 0
        geo_data = self._get_geoip_data_from_ip_address(ip_addr)
        if isinstance(geo_data, dict):
            ip_lat = geo_data.get('latitude')
            ip_long = geo_data.get('longitude')
            if isinstance(ip_lat, float) and isinstance(ip_long, float):
                ip_lat = round(ip_lat, 5)
                ip_long = round(ip_long, 5)
                entropy_ip_locations_id = self._get_entropy_ip_locations_id(
                    ip_lat, ip_long)
                if entropy_ip_locations_id == -1:
                    entropy_ip_locations_id = \
                        self._insert_entropy_ip_locations_id(ip_lat, ip_long)
        return entropy_ip_locations_id

    def _update_total_downloads(self, idkeys):
        for idkey in idkeys:
            self.execute_query("""
            UPDATE entropy_total_downloads SET `count` = `count`+1
            WHERE `idkey` = %s LIMIT 1;
            """, (idkey,))
            if not rows_affected:
                self.execute_query("""
                INSERT INTO entropy_total_downloads (`idkey`, `count`) VALUES
                (%s, %s)
                ON DUPLICATE KEY UPDATE `count` = `count` + 1;
                """, (idkey, 1))

    def _get_idkey(self, key):
        self.execute_query("""
        SELECT `idkey` FROM entropy_base WHERE `key` = %s
        """, (key,))
        data = self.fetchone() or {}
        return data.get('idkey', -1)

    def get_iddoctype(self, iddoc):
        self.execute_query("""
        SELECT `iddoctype` FROM entropy_docs WHERE `iddoc` = %s
        """, (iddoc,))
        data = self.fetchone() or {}
        return data.get('iddoctype', -1)

    def _get_entropy_branches_id(self, branch):
        self.execute_query("""
        SELECT `entropy_branches_id` FROM entropy_branches
        WHERE `entropy_branch` = %s
        """, (branch,))
        data = self.fetchone() or {}
        return data.get('entropy_branches_id', -1)

    def _get_entropy_release_strings_id(self, release_string):
        self.execute_query("""
        SELECT `entropy_release_strings_id` FROM entropy_release_strings
        WHERE `release_string` = %s
        """, (release_string,))
        data = self.fetchone() or {}
        return data.get('entropy_release_strings_id', -1)

    def _get_entropy_ip_locations_id(self, ip_latitude, ip_longitude):
        self.execute_query("""
        SELECT `entropy_ip_locations_id` FROM 
        entropy_ip_locations WHERE
        `ip_latitude` = %s AND `ip_longitude` = %s
        """, (ip_latitude, ip_longitude,))
        data = self.fetchone() or {}
        return data.get('entropy_ip_locations_id', -1)

    def _get_pkgkey(self, idkey):
        self.execute_query("""
        SELECT `key` FROM entropy_base WHERE `idkey` = %s
        """, (idkey,))
        data = self.fetchone() or {}
        return data.get('key')

    def _get_ugc_keywords(self, iddoc):
        self.execute_query("""
        SELECT `keyword` FROM entropy_docs_keywords
        WHERE `iddoc` = %s order by `keyword`
        """, (iddoc,))
        return [x['keyword'] for x in self.fetchall()]

    def get_ugc_metadata_doctypes(self, pkgkey, typeslist, offset = 0,
        length = 100, latest = False):

        if latest:
            order_by = "DESC"
        else:
            order_by = "ASC"

        if len(typeslist) == 1:
            self.execute_query("""
                SELECT SQL_CACHE SQL_CALC_FOUND_ROWS *
                FROM entropy_docs, entropy_base WHERE 
                entropy_docs.`idkey` = entropy_base.`idkey` AND 
                entropy_base.`key` = %s AND 
                ( entropy_docs.`iddoctype` = %s  )
                ORDER BY entropy_docs.`ts` """ + order_by + """
                LIMIT %s, %s""", (pkgkey, typeslist[0], offset, length,))
        else:
            self.execute_query("""
                SELECT SQL_CACHE SQL_CALC_FOUND_ROWS *
                FROM entropy_docs,entropy_base WHERE 
                entropy_docs.`idkey` = entropy_base.`idkey` AND 
                entropy_base.`key` = %s AND 
                ( entropy_docs.`iddoctype` IN %s  )
                ORDER BY entropy_docs.`ts` """ + order_by + """
                LIMIT %s, %s""", (pkgkey, typeslist, offset, length,))

        raw_docs = self.fetchall()

        self.execute_query('SELECT FOUND_ROWS() as count')
        data = self.fetchone() or {}
        count = data.get('count', 0)
        if count is None:
            count = 0
        return count, [self._get_ugc_extra_metadata(x) for x in raw_docs]

    def get_ugc_metadata_doctypes_by_identifiers(self, identifiers, typeslist):
        if len(identifiers) < 2:
            identifiers = list(identifiers) + [0]
        if len(typeslist) < 2:
            typeslist = list(typeslist) + [0]
        self.execute_query("""
        SELECT * FROM entropy_docs WHERE `iddoc` IN %s AND `iddoctype` IN %s
        """, (identifiers, typeslist,))
        return [self._get_ugc_extra_metadata(x) for x in self.fetchall()]

    def get_ugc_metadata_by_identifiers(self, identifiers):
        if len(identifiers) < 2:
            identifiers = list(identifiers) + [0]
            identifiers += [0]
        self.execute_query("""
        SELECT * FROM entropy_docs WHERE `iddoc` IN %s
        """, (identifiers,))
        return [self._get_ugc_extra_metadata(x) for x in self.fetchall()]

    def _get_ugc_extra_metadata(self, mydict):
        mydict['store_url'] = None
        mydict['keywords'] = self._get_ugc_keywords(mydict['iddoc'])
        if "key" in mydict:
            mydict['pkgkey'] = mydict['key']
        else:
            mydict['pkgkey'] = self._get_pkgkey(mydict['idkey'])
        # for binary files, get size too
        mydict['size'] = 0
        if mydict['iddoctype'] in self.UPLOADED_DOC_TYPES:
            myfilename = mydict['ddata']
            if not isinstance(myfilename, const_get_stringtype()):
                myfilename = myfilename.tostring()
            mypath = os.path.join(self.STORE_PATH, myfilename)
            try:
                mydict['size'] = entropy.tools.get_file_size(mypath)
            except OSError:
                pass
            mydict['store_url'] = os.path.join(self._store_url, myfilename)
        return mydict

    def get_ugc_icon(self, pkgkey):
        """
        Retrieve UGC icon URL for package key. URL if found (using store_url),
        None otherwise.
        TODO: once the repository-manager crap is gone, rename all the
        image document types containing __icon__ as title to icon type
        """
        self.execute_query("""
        SELECT SQL_CACHE * FROM entropy_docs, entropy_base
        WHERE entropy_base.`idkey` = entropy_docs.`idkey`
        AND entropy_base.`key` = %s
        AND ( 
        ( entropy_docs.iddoctype = %s AND entropy_docs.title = "__icon__"
        ) OR ( entropy_docs.iddoctype = %s
        ))
        ORDER BY entropy_docs.ts DESC
        LIMIT 1""", (pkgkey, self.DOC_TYPES['image'], self.DOC_TYPES['icon']))
        data = self.fetchone() or {}
        icon_path = data.get('ddata')
        if not isinstance(icon_path, const_get_stringtype()) \
            and (icon_path is not None):
            icon_path = icon_path.tostring()
        if icon_path is not None:
            icon_path = os.path.join(self._store_url, icon_path.lstrip("/"))
        return icon_path

    def get_ugc_vote(self, pkgkey):
        self.execute_query("""
        SELECT SQL_CACHE avg(entropy_votes.`vote`) as avg_vote
        FROM entropy_votes,entropy_base WHERE 
        entropy_base.`key` = %s AND 
        entropy_base.idkey = entropy_votes.idkey""", (pkgkey,))
        data = self.fetchone() or {}
        avg_vote = data.get('avg_vote')
        if not avg_vote:
            return 0.0
        return avg_vote

    def get_ugc_votes(self, pkgkeys):

        if len(pkgkeys) == 1:
            # then return data without caching, probably user just pushed
            # a new vote and wants to get back his value
            self.execute_query("""
            SELECT SQL_CACHE avg(entropy_votes.`vote`) as avg_vote
            FROM entropy_votes, entropy_base WHERE 
            entropy_base.idkey = entropy_votes.idkey
            AND entropy_base.`key` = %s""", (pkgkeys[0],))
            data = self.fetchone() or {}
            return {pkgkeys[0]: data.get('avg_vote', None),}

        self.execute_query("""
        SELECT SQL_CACHE entropy_base.`key` as `vkey`,
        round(avg(entropy_votes.vote), 2) as `avg_vote` FROM 
        entropy_votes,entropy_base WHERE 
        entropy_votes.`idkey` = entropy_base.`idkey` AND
        entropy_base.`key` IN %s
        GROUP BY entropy_base.`key`
        """, (pkgkeys,))
        return dict((x['vkey'], x['avg_vote']) for x in self.fetchall())

    def get_ugc_allvotes(self):
        self.execute_query("""
        SELECT SQL_CACHE entropy_base.`key` as `vkey`,
        round(avg(entropy_votes.vote), 2) as `avg_vote` FROM 
        entropy_votes,entropy_base WHERE 
        entropy_votes.`idkey` = entropy_base.`idkey` GROUP BY entropy_base.`key`
        """)
        return dict((x['vkey'], x['avg_vote']) for x in self.fetchall())

    def get_ugc_download(self, pkgkey):
        self.execute_query("""
        SELECT SQL_CACHE
            entropy_total_downloads.`count` AS tot_downloads
        FROM entropy_total_downloads, entropy_base
        WHERE
            entropy_base.idkey = entropy_total_downloads.idkey AND
            entropy_base.`key` = %s
        """, (pkgkey,))
        data = self.fetchone() or {}
        downloads = data.get('tot_downloads')
        if not downloads:
            return 0
        return downloads

    def get_ugc_downloads(self, pkgkeys):
        if len(pkgkeys) == 1:
            pkgkey = pkgkeys[0]
            downloads = self.get_ugc_download(pkgkey)
            return {pkgkey: downloads,}

        self.execute_query("""
        SELECT SQL_CACHE
            entropy_base.`key` as vkey,
            entropy_total_downloads.`count` AS tot_downloads
        FROM entropy_total_downloads, entropy_base
        WHERE
            entropy_base.idkey = entropy_total_downloads.idkey AND
            entropy_base.`key` IN %s
        """, (pkgkeys,))
        return dict((x['vkey'], x['tot_downloads']) for x in self.fetchall())

    def get_ugc_alldownloads(self):
        self.execute_query("""
        SELECT SQL_CACHE
            entropy_base.`key` as vkey,
            entropy_total_downloads.`count` AS tot_downloads
        FROM entropy_total_downloads, entropy_base
        WHERE
            entropy_base.idkey = entropy_total_downloads.idkey
        """)
        raw_data = self.fetchall()
        return dict((x['vkey'], x['tot_downloads'],) for x in raw_data)

    def get_iddoc_userid(self, iddoc):
        self.execute_query("""
        SELECT `userid` FROM entropy_docs WHERE `iddoc` = %s
        """, (iddoc,))
        data = self.fetchone() or {}
        return data.get('userid', None)

    def _get_user_score_ranking(self, userid):
        self.execute_query('SET @row = 0')
        self.execute_query("""
        SELECT Row, col_a FROM (SELECT @row := @row + 1 AS Row, userid AS col_a
        FROM entropy_user_scores ORDER BY score DESC) As derived1
        WHERE col_a = %s""", (userid,))
        data = self.fetchone() or {}
        ranking = data.get('Row', 0) # key can be avail but is None
        if not ranking:
            return 0
        return ranking

    def _is_user_score_available(self, userid):
        rows = self.execute_query("""
        SELECT `userid` FROM entropy_user_scores WHERE `userid` = %s
        """, (userid,))
        if rows:
            return True
        return False

    def _calculate_user_score(self, userid):
        docs_cnts = self._get_user_doctypes_count(userid)
        votes, votes_avg = self._get_user_votes_stats(userid)
        comments = 0
        docs = 0
        for key, val in docs_cnts.items():
            if key == self.DOC_TYPES['comments']:
                comments += val
            else:
                docs += val
        return (comments*self.COMMENTS_SCORE_WEIGHT) + \
            (docs*self.DOCS_SCORE_WEIGHT) + \
            (votes*self.VOTES_SCORE_WEIGHT)

    def _update_user_score(self, userid):
        avail = self._is_user_score_available(userid)
        myscore = self._calculate_user_score(userid)
        if avail:
            self.execute_query("""
            UPDATE entropy_user_scores SET score = %s WHERE `userid` = %s
            """, (myscore, userid,))
        else:
            self.execute_query("""
            INSERT INTO entropy_user_scores VALUES (%s,%s)
            """, (userid, myscore,))
        return myscore

    def get_user_score(self, userid):
        self.execute_query("""
        SELECT score FROM entropy_user_scores WHERE userid = %s
        """, (userid,))
        data = self.fetchone() or {}
        myscore = data.get('score')
        if myscore is None:
            myscore = self._update_user_score(userid)
        return myscore

    def _get_user_generic_doctype_count(self, userid, doctype,
        doctype_sql_cmp = "="):
        self.execute_query("""
        SELECT count(`iddoc`) as docs FROM entropy_docs
        WHERE `userid` = %s AND `iddoctype` """ + \
            doctype_sql_cmp + """ %s""", (userid, doctype,))
        data = self.fetchone() or {}
        return data.get('docs', 0)

    def _get_user_doctypes_count(self, userid):
        self.execute_query("""
        SELECT iddoctype, count(`iddoc`) as docs
        FROM entropy_docs WHERE `userid` = %s GROUP BY iddoctype
        """, (userid,))
        return dict((x['iddoctype'], x['docs']) for x in self.fetchall())

    def _get_user_votes_stats(self, userid):
        self.execute_query("""
        SELECT count(`idvote`) as votes, round(avg(`vote`), 2) as vote_avg
        FROM entropy_votes WHERE `userid` = %s""", (userid,))
        data = self.fetchone() or {}
        return data.get('votes', 0), data.get('votes_avg', 0.0)

    def get_user_stats(self, userid):

        mydict = {}
        data = self._get_user_doctypes_count(userid)
        mydict['comments'] = data.get(self.DOC_TYPES['comments'], 0)
        mydict['images'] = data.get(self.DOC_TYPES['image'], 0)
        mydict['files'] = data.get(self.DOC_TYPES['generic_file'], 0)
        mydict['yt_videos'] = data.get(self.DOC_TYPES['youtube_video'], 0)
        mydict['docs'] = mydict['images'] + mydict['files'] + \
            mydict['yt_videos']
        mydict['votes'], mydict['votes_avg'] = self._get_user_votes_stats(
            userid)
        mydict['total_docs'] = mydict['comments'] + mydict['docs']
        mydict['score'] = self.get_user_score(userid)
        return mydict

    def _handle_entropy_branches_id(self, branch):
        branch_id = self._get_entropy_branches_id(branch)
        if branch_id == -1:
            # deal with races
            self.execute_query("""
            INSERT IGNORE INTO entropy_branches VALUES (%s,%s)
            """, (None, branch,))
            branch_id = self.lastrowid()
            if not branch_id:
                # race
                branch_id = self._get_entropy_branches_id(branch)
        return branch_id

    def _handle_pkgkey(self, key):
        idkey = self._get_idkey(key)
        if idkey == -1:
            # deal with races
            self.execute_query("""
            INSERT IGNORE INTO entropy_base (`key`) VALUES (%s);
            """, (key,))
            idkey = self.lastrowid()
            if not idkey:
                # race
                idkey = self._get_idkey(key)
        return idkey

    def insert_flood_control_check(self, userid):
        self.execute_query("""
        SELECT max(`ts`) as ts FROM entropy_docs WHERE `userid` = %s
        """, (userid,))
        data = self.fetchone()
        if not data:
            return False
        elif 'ts' not in data:
            return False
        elif data['ts'] is None:
            return False
        delta = datetime.fromtimestamp(time.time()) - data['ts']
        if (delta.days == 0) and (delta.seconds <= self.FLOOD_INTERVAL):
            return True
        return False

    def insert_generic_doc(self, idkey, userid, username, doc_type, data,
        title, description, keywords):

        title = title[:self.entropy_docs_title_len]
        description = description[:self.entropy_docs_description_len]

        # flood control
        flood_risk = self.insert_flood_control_check(userid)
        if flood_risk:
            return 'flooding detected'

        self.execute_query("""
        INSERT INTO entropy_docs VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (None, idkey, userid, username, doc_type, data, title,
                description, None,))
        iddoc = self.lastrowid()
        self._insert_keywords(iddoc, keywords)
        self._update_user_score(userid)
        return iddoc

    def _insert_keywords(self, iddoc, keywords):
        self.execute_many("""
        INSERT INTO entropy_docs_keywords VALUES (%s,%s)
        """, [(iddoc, x) for x in keywords])

    def insert_comment(self, pkgkey, userid, username, comment, title,
        keywords):
        idkey = self._handle_pkgkey(pkgkey)
        iddoc = self.insert_generic_doc(idkey, userid, username,
            self.DOC_TYPES['comments'], comment, title, '', keywords)
        if isinstance(iddoc, const_get_stringtype()):
            return False, iddoc
        return True, iddoc

    def remove_comment(self, iddoc):
        userid = self.get_iddoc_userid(iddoc)
        if userid is None:
            return False, None
        self.execute_query("""
        DELETE FROM entropy_docs WHERE `iddoc` = %s AND `iddoctype` = %s
        """, (iddoc, self.DOC_TYPES['comments'],))
        if userid:
            self._update_user_score(userid)
        return True, iddoc

    def do_vote(self, pkgkey, userid, vote):
        idkey = self._handle_pkgkey(pkgkey)
        if self._has_user_already_voted(idkey, userid):
            return False
        self.execute_query("""
        INSERT INTO entropy_votes VALUES (%s,%s,%s,CURDATE(),%s,%s)
        """, (None, idkey, userid, vote, None,))
        self._update_user_score(userid)
        return True

    def _has_user_already_voted(self, idkey, userid):
        self.execute_query("""
        SELECT `idvote` FROM entropy_votes WHERE `idkey` = %s AND `userid` = %s
        """, (idkey, userid,))
        data = self.fetchone()
        if data:
            return True
        return False

    def _do_downloads(self, pkgkeys, ip_addr = None):
        idkeys = set()
        for pkgkey in pkgkeys:
            idkey = self._handle_pkgkey(pkgkey)

            query = """
            UPDATE entropy_downloads SET `count` = `count` + 1
            WHERE idkey = %s AND ddate = CURDATE() LIMIT 1;
            """
            rows_affected = self.execute_query(query, (idkey,))
            if not rows_affected:
                query = """
                INSERT INTO entropy_downloads
                (idkey, ddate, count)
                VALUES (%s, CURDATE(), %s)
                ON DUPLICATE KEY UPDATE `count` = `count` + 1;
                """
                self.execute_query(query, (idkey, 1))

            idkeys.add(idkey)

        if idkeys:
            self._update_total_downloads(idkeys)

        del iddownloads
        del idkeys

        return True

    def do_download_stats(self, branch, release_string, hw_hash, pkgkeys,
        ip_addr):

        branch_id = self._handle_entropy_branches_id(branch)
        rel_strings_id = self._get_entropy_release_strings_id(release_string)
        if rel_strings_id == -1:
            rel_strings_id = self._insert_entropy_release_string(release_string)

        self._do_downloads(pkgkeys, ip_addr = ip_addr)

        hits = len(pkgkeys)
        if self.STATS_MAP['installer'] in pkgkeys:
            hits = 1

        entropy_ip_locations_id = self._handle_entropy_ip_locations_id(
            ip_addr)

        query = """
        INSERT INTO entropy_distribution_usage
        (entropy_branches_id, entropy_release_strings_id,
         ip_address, entropy_ip_locations_id,
         creation_date, hits)
        VALUES (%s, %s, %s, %s, CURDATE(), %s)
        ON DUPLICATE KEY UPDATE hits = hits + %s;
        """
        self.execute_query(
            query,
            (branch_id, rel_strings_id,
             ip_addr, entropy_ip_locations_id,
             hits, hits))
        entropy_distribution_usage_id = self.lastrowid()

        # store hardware hash if set
        if hw_hash and not \
            self._is_entropy_hardware_usage_stats_available(
                entropy_distribution_usage_id):

            self._do_entropy_hardware_usage_stats(entropy_distribution_usage_id,
                hw_hash)

        return True

    def _do_entropy_hardware_usage_stats(self, entropy_distribution_usage_id,
        hw_hash):

        self.execute_query("""
        INSERT INTO entropy_hardware_usage VALUES (%s,%s,%s)
        """, (None, entropy_distribution_usage_id, hw_hash,))

    def _is_entropy_hardware_usage_stats_available(self,
        entropy_distribution_usage_id):
        self.execute_query("""
        SELECT entropy_hardware_usage_id  FROM entropy_hardware_usage
        WHERE `entropy_distribution_usage_id` = %s
        """, (entropy_distribution_usage_id,))
        data = self.fetchone()
        if data:
            return True
        return False

    def _is_user_ip_available_in_entropy_distribution_usage(self, ip_address):
        self.execute_query("""
        SELECT entropy_distribution_usage_id FROM entropy_distribution_usage
        WHERE `ip_address` = %s
        """, (ip_address,))
        data = self.fetchone() or {}
        myid = data.get('entropy_distribution_usage_id')
        if myid is None:
            return -1
        return myid

    def _scan_for_viruses(self, filepath):

        if not os.access(filepath, os.R_OK):
            return False, None

        args = [self.VIRUS_CHECK_EXEC]
        args += self.VIRUS_CHECK_ARGS
        args += [filepath]
        with open("/dev/null", "w") as f:
            p = subprocess.Popen(args, stdout = f, stderr = f)
            rc = p.wait()
        if rc == 1:
            return True, None
        return False, None

    def _insert_generic_file(self, pkgkey, userid, username, file_path,
            file_name, doc_type, title, description, keywords):
        file_path = os.path.realpath(file_path)

        # do a virus check?
        virus_found, virus_type = self._scan_for_viruses(file_path)
        if virus_found:
            os.remove(file_path)
            return False, None

        # flood control
        flood_risk = self.insert_flood_control_check(userid)
        if flood_risk:
            return False, 'flooding detected'

        # validity check
        if doc_type == self.DOC_TYPES['image']:
            valid = False
            if os.path.isfile(file_path) and os.access(file_path, os.R_OK):
                valid = entropy.tools.is_supported_image_file(file_path)
            if not valid:
                return False, 'not a valid image'

        dest_path = os.path.join(self.STORE_PATH, file_name)

        # create dir if not exists
        dest_dir = os.path.dirname(dest_path)
        if not os.path.isdir(dest_dir):
            try:
                os.makedirs(dest_dir)
            except OSError as err:
                raise etp_exceptions.PermissionDenied(err)
            if etpConst['entropygid'] != None:
                const_setup_perms(dest_dir, etpConst['entropygid'],
                    recursion = False)

        orig_dest_path = dest_path
        dcount = 0
        while os.path.isfile(dest_path):
            dcount += 1
            dest_path_name = "%s_%s" % (dcount,
                os.path.basename(orig_dest_path),)
            dest_path = os.path.join(os.path.dirname(orig_dest_path),
                dest_path_name)

        if os.path.dirname(file_path) != dest_dir:
            try:
                os.rename(file_path, dest_path)
            except OSError:
                # fallback to non atomic
                shutil.move(file_path, dest_path)
        if etpConst['entropygid'] != None:
            try:
                const_setup_file(dest_path, etpConst['entropygid'], 0o664)
            except OSError:
                pass
            # at least set chmod
            try:
                const_set_chmod(dest_path, 0o664)
            except OSError:
                pass

        title = title[:self.entropy_docs_title_len]
        description = description[:self.entropy_docs_description_len]

        # now store in db
        idkey = self._handle_pkgkey(pkgkey)
        self.execute_query("""
        INSERT INTO entropy_docs VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (None, idkey, userid, username, doc_type, file_name,
                title, description, None,))
        iddoc = self.lastrowid()
        self._insert_keywords(iddoc, keywords)
        store_url = os.path.basename(dest_path)
        if self._store_url:
            store_url = os.path.join(self._store_url, store_url)
        self._update_user_score(userid)
        return True, (iddoc, store_url)

    def insert_image(self, pkgkey, userid, username, image_path, file_name,
            title, description, keywords):
        if not entropy.tools.is_supported_image_file(image_path):
            return False, 'not an image'
        return self._insert_generic_file(pkgkey, userid, username, image_path,
            file_name, self.DOC_TYPES['image'], title, description, keywords)

    def insert_icon(self, pkgkey, userid, username, image_path, file_name,
            title, description, keywords):
        if not entropy.tools.is_supported_image_file(image_path):
            return False, 'not an image'
        return self._insert_generic_file(pkgkey, userid, username, image_path,
            file_name, self.DOC_TYPES['icon'], title, description, keywords)

    def insert_file(self, pkgkey, userid, username, file_path, file_name, title,
            description, keywords):
        return self._insert_generic_file(pkgkey, userid, username, file_path,
            file_name, self.DOC_TYPES['generic_file'], title, description,
            keywords)

    def delete_image(self, iddoc):
        return self._delete_generic_file(iddoc, self.DOC_TYPES['image'])

    def delete_icon(self, iddoc):
        return self._delete_generic_file(iddoc, self.DOC_TYPES['icon'])

    def delete_file(self, iddoc):
        return self._delete_generic_file(iddoc, self.DOC_TYPES['generic_file'])

    def _delete_generic_file(self, iddoc, doc_type):
        userid = self.get_iddoc_userid(iddoc)
        if userid is None:
            return False, None
        self.execute_query("""
        SELECT `ddata` FROM entropy_docs WHERE `iddoc` = %s
        AND `iddoctype` = %s
        """, (iddoc, doc_type,))
        data = self.fetchone() or {}
        mypath = data.get('ddata')
        if not isinstance(mypath, const_get_stringtype()) and \
            (mypath is not None):
            mypath = mypath.tostring()
        if mypath is not None:
            mypath = os.path.join(self.STORE_PATH, mypath)
            if os.path.isfile(mypath) and os.access(mypath, os.W_OK):
                os.remove(mypath)

        self.execute_query("""
        DELETE FROM entropy_docs WHERE `iddoc` = %s AND `iddoctype` = %s
        """, (iddoc, doc_type,))
        if userid:
            self._update_user_score(userid)
        return True, (iddoc, None)

    def insert_youtube_video(self, pkgkey, userid, username, video_path,
        file_name, title, description, keywords):

        idkey = self._handle_pkgkey(pkgkey)
        video_path = os.path.realpath(video_path)
        if not (os.access(video_path, os.R_OK) and os.path.isfile(video_path)):
            return False
        virus_found, virus_type = self._scan_for_viruses(video_path)
        if virus_found:
            os.remove(video_path)
            return False, None

        new_video_path = video_path
        if isinstance(file_name, const_get_stringtype()):
            # move file to the new filename
            new_video_path = os.path.join(os.path.dirname(video_path),
                os.path.basename(file_name)) # force basename
            scount = 0
            while os.path.lexists(new_video_path):
                scount += 1
                bpath = "%s.%s" % (str(scount), os.path.basename(file_name),)
                new_video_path = os.path.join(os.path.dirname(video_path), bpath)
            shutil.move(video_path, new_video_path)

        yt_service = self.get_youtube_service()
        if yt_service is None:
            return False, None

        mykeywords = ', '.join([x.strip().strip(',') for x in \
            keywords + ["sabayon"] if (x.strip() and x.strip(",") and \
                (len(x.strip()) > 4))])
        gd_keywords = gdata.media.Keywords(text = mykeywords)

        mydescription = "%s: %s" % (pkgkey, description,)
        mytitle = "%s: %s" % (self._system_name, title,)
        my_media_group = gdata.media.Group(
            title = gdata.media.Title(text = mytitle),
            description = gdata.media.Description(
                description_type = 'plain',
                text = mydescription
            ),
            keywords = gd_keywords,
            category = gdata.media.Category(
                text = 'Tech',
                scheme = 'http://gdata.youtube.com/schemas/2007/categories.cat',
                label = 'Tech'
            ),
            player = None
        )
        video_entry = gdata.youtube.YouTubeVideoEntry(media = my_media_group)
        new_entry = yt_service.InsertVideoEntry(video_entry, new_video_path)
        if not isinstance(new_entry, gdata.youtube.YouTubeVideoEntry):
            return False, None
        video_url = new_entry.GetSwfUrl()
        video_id = os.path.basename(video_url)

        iddoc = self.insert_generic_doc(idkey, userid, username,
            self.DOC_TYPES['youtube_video'], video_id, title, description,
            keywords)
        if isinstance(iddoc, const_get_stringtype()):
            return False, (iddoc, None,)
        return True, (iddoc, video_id,)

    def remove_youtube_video(self, iddoc):
        userid = self.get_iddoc_userid(iddoc)
        if userid is None:
            return False, None

        yt_service = self.get_youtube_service()
        if yt_service is None:
            return False, None

        def do_remove():
            self.execute_query("""
            DELETE FROM entropy_docs WHERE `iddoc` = %s
            AND `iddoctype` = %s
            """, (
                    iddoc,
                    self.DOC_TYPES['youtube_video'],
                )
            )

        self.execute_query("""
        SELECT `ddata` FROM entropy_docs WHERE `iddoc` = %s
        AND `iddoctype` = %s
        """, (iddoc, self.DOC_TYPES['youtube_video'],))
        data = self.fetchone()
        if data is None:
            do_remove()
            return False, None
        elif 'ddata' not in data:
            do_remove()
            return False, None

        video_id = data.get('ddata')
        video_entry = yt_service.GetYouTubeVideoEntry(video_id = video_id)
        # workaround broken API
        video_entry.link[0].rel = "edit"
        video_entry.link[0].href = \
            'http://gdata.youtube.com/feeds/api/users/%s/uploads/%s' % (
                "SabayonChannel", video_id)
        deleted = yt_service.DeleteVideoEntry(video_entry)

        if deleted:
            do_remove()
        if userid:
            self._update_user_score(userid)
        return deleted, (iddoc, video_id,)

    def get_youtube_service(self):
        keywords = ['google_email', 'google_password']
        for keyword in keywords:
            if keyword not in self.connection_data:
                return None
        # note: your google account must be linked with the YouTube one
        srv = gdata.youtube.service.YouTubeService()
        srv.email = self.connection_data['google_email']
        srv.password = self.connection_data['google_password']
        if 'google_developer_key' in self.connection_data:
            srv.developer_key = self.connection_data['google_developer_key']
        srv.source = 'Entropy'
        srv.ProgrammaticLogin()
        return srv


class UGC(DistributionUGCInterface):

    def __init__(self, conn_data = None):
        if conn_data is None:
            conn_data = config.ugc_connection_data

        store_path = conn_data.get("store_path", config.ugc_store_path)
        store_url = conn_data.get("store_url", config.ugc_store_url)

        DistributionUGCInterface.__init__(self, conn_data, store_path,
            store_url)
        # cannot set this inside DistributionUGCInterface
        # for compatibility reasons
        self.dbconn.set_character_set('utf8')

    def insert_document_autosense(self, pkgkey, doc_type, userid, username,
        comment_text, file_path, file_name, real_filename, title, description,
        keywords):

        status = False
        iddoc = 'invalid doc type'

        if doc_type == self.DOC_TYPES['comments']:
            status, iddoc = self.insert_comment(pkgkey, userid, username,
                comment_text, title, keywords)

        elif doc_type == self.DOC_TYPES['icon']:
            status, ddata = self.insert_icon(pkgkey, userid, username,
                file_path, file_name, title, description, keywords)
            if isinstance(ddata, tuple):
                iddoc, doc_path = ddata

        elif doc_type == self.DOC_TYPES['image']:
            status, ddata = self.insert_image(pkgkey, userid, username,
                file_path, file_name, title, description, keywords)
            if isinstance(ddata,tuple):
                iddoc, doc_path = ddata

        elif doc_type == self.DOC_TYPES['generic_file']:
            status, ddata = self.insert_file(pkgkey, userid, username,
                file_path, file_name, title, description, keywords)
            if isinstance(ddata,tuple):
                iddoc, doc_path = ddata

        elif doc_type == self.DOC_TYPES['youtube_video']:
            status, ddata = self.insert_youtube_video(pkgkey, userid, username,
                file_path, real_filename, title, description, keywords)
            if isinstance(ddata, tuple):
                iddoc, doc_path = ddata

        if isinstance(iddoc, long):
            iddoc = int(iddoc)

        return status, iddoc

    def remove_document_autosense(self, iddoc, doc_type):

        status = False
        r_iddoc = 'type not supported locally'

        if doc_type == self.DOC_TYPES['generic_file']:
            status, r_iddoc = self.delete_file(iddoc)
        elif doc_type == self.DOC_TYPES['image']:
            status, r_iddoc = self.delete_image(iddoc)
        elif doc_type == self.DOC_TYPES['icon']:
            status, r_iddoc = self.delete_icon(iddoc)
        elif doc_type == self.DOC_TYPES['youtube_video']:
            status, r_iddoc = self.remove_youtube_video(iddoc)
        elif doc_type == self.DOC_TYPES['comments']:
             status, r_iddoc = self.remove_comment(iddoc)

        return status, r_iddoc

