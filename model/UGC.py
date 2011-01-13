# -*- coding: utf-8 -*-
import os
import config
from entropy.services.ugc.interfaces import Server as DistributionUGCInterface
from entropy.const import *
etpConst['entropygid'] = config.DEFAULT_WEB_GID
import entropy.exceptions as etp_exceptions
try:
    from entropy.services.exceptions import ServiceConnectionError
except ImportError:
    ServiceConnectionError = Exception

class UGC(DistributionUGCInterface):

    def __init__(self, conn_data = None):
        if conn_data == None: conn_data = config.ugc_connection_data
        store_path = config.ugc_store_path
        store_url = config.ugc_store_url
        if conn_data.has_key('store_path'): store_path = conn_data.get('store_path')
        if conn_data.has_key('store_url'): store_url = conn_data.get('store_url')
        DistributionUGCInterface.__init__(self, conn_data, store_path, store_url)
        # cannot set this inside DistributionUGCInterface for compatibility reasons
        self.dbconn.set_character_set('utf8')

    def insert_document_autosense(self, pkgkey, doc_type, userid, username, comment_text, file_path, file_name, real_filename, title, description, keywords):

        #const_setup_perms(self.STORE_PATH,config.DEFAULT_WEB_GID)

        status = False
        iddoc = _('invalid doc type')

        if doc_type == self.DOC_TYPES['image']:
            status, ddata = self.insert_image(pkgkey, userid, username, file_path, file_name, title, description, keywords)
            if isinstance(ddata,tuple): (iddoc, doc_path) = ddata
        elif doc_type == self.DOC_TYPES['generic_file']:
            status, ddata = self.insert_file(pkgkey, userid, username, file_path, file_name, title, description, keywords)
            if isinstance(ddata,tuple): (iddoc, doc_path) = ddata
        elif doc_type == self.DOC_TYPES['youtube_video']:
            status, ddata = self.insert_youtube_video(pkgkey, userid, username, file_path, real_filename, title, description, keywords)
            if isinstance(ddata,tuple): (iddoc, doc_path) = ddata
        elif doc_type == self.DOC_TYPES['comments']:
            status, iddoc = self.insert_comment(pkgkey, userid, username, comment_text, title, keywords)

        if isinstance(iddoc,(long,)):
            iddoc = int(iddoc)

        return status, iddoc

    def remove_document_autosense(self, iddoc, doc_type):

        status = False
        r_iddoc = _('type not supported locally')

        if doc_type == self.DOC_TYPES['generic_file']:
            status, r_iddoc = self.delete_file(iddoc)
        elif doc_type == self.DOC_TYPES['image']:
            status, r_iddoc = self.delete_image(iddoc)
        elif doc_type == self.DOC_TYPES['youtube_video']:
            status, r_iddoc = self.remove_youtube_video(iddoc)
        elif doc_type == self.DOC_TYPES['comments']:
             status, r_iddoc = self.remove_comment(iddoc)

        return status, r_iddoc

    def __del__(self):
        if hasattr(self,'commit'):
            try:
                self.commit()
            except:
                pass
        if hasattr(self,'disconnect'):
            try:
                self.disconnect()
            except ServiceConnectionError:
                pass
