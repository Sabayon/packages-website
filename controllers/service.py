import os
import json
import hashlib
import errno
import tempfile
import shutil
import cgi
import re
import time

from www.lib.base import *
from www.lib.website import *
from www.lib.apibase import ApibaseController

from entropy.const import const_convert_to_rawstring, const_get_stringtype
from entropy.services.client import WebService
from entropy.client.services.interfaces import ClientWebService, Document, \
    DocumentFactory
from entropy.misc import EmailSender

import entropy.tools
import entropy.dep

from datetime import datetime

class ServiceController(BaseController, WebsiteController, ApibaseController):

    def __init__(self):
        BaseController.__init__(self)
        WebsiteController.__init__(self)
        ApibaseController.__init__(self)
        self.__service_auth = None
        self._supported_repository_ids = ["sabayonlinux.org",
            "sabayon-weekly", "sabayon-limbo"]

    @property
    def _auth(self):
        if self.__service_auth is None:
            from www.lib.phpbb import Authenticator
            self.__service_auth = Authenticator()
        return self.__service_auth

    def _try_auth_login(self):
        """
        Helper method used to attempt the login procedure against users
        database. This method automatically handles the conversion to raw
        string (from unicode) if necessary.

        @return: the user identifier (if login succeeds)
        @rtype: int
        @raise AttributeError: if credentials are invalid.
        """
        username, password = request.params.get("username"), \
            request.params.get("password")
        if not (username and password):
            raise AttributeError("credentials not available")

        # explicitly use utf8_bin format for username
        username = const_convert_to_rawstring(username,
            from_enctype = 'raw_unicode_escape')
        # and shitty raw for this, don't ask me why
        password = const_convert_to_rawstring(password,
            from_enctype = 'utf-8')
        user_id = self._auth.login(username, password)
        return username, user_id

    def _validate_repository_id(self, repository_id = None):
        """
        Validate provided repository_id in HTTP request against those supported
        by this instance.

        @raise AttributeError: if invalid
        """
        if repository_id is None:
            repository_id = self._get_repository_id()
        if repository_id not in self._supported_repository_ids:
            raise AttributeError("unsupported repository_id")

    def _get_repository_id(self):
        """
        Return the repository_id string contained in HTTP request metadata.
        There is no validation here !!
        """
        return request.params.get("__repository_id__")

    def _generic_invalid_request(self, code = None, message = None):
        """
        Generate a generic invalid request HTTP response
        """
        if code is None:
            code = WebService.WEB_SERVICE_INVALID_REQUEST_CODE
        response = self._api_base_response(code, message = message)
        return self._service_render(response)

    def _get_package_names(self):
        """
        Get package names list from HTTP request data.
        Validate them and raise AttributeError in case of failure.
        """
        package_names = request.params.get("package_names") or ""
        package_names = package_names.strip()
        if not package_names:
            raise AttributeError("no package_names")

        package_names = package_names.split()
        if len(package_names) > 200:
            # WTF !?!?!?!
            raise AttributeError("wtf too big")
        # validate package_names
        try:
            self._validate_package_names(package_names)
        except AttributeError:
            raise
        return [entropy.dep.dep_getkey(x) for x in package_names]

    def _get_package_name(self):
        """
        Get package name list from HTTP request data.
        Validate them and raise AttributeError in case of failure.
        """
        package_name = (request.params.get("package_name") or "").strip()
        if not package_name:
            raise AttributeError("no package_name")

        # validate package_names
        try:
            self._validate_package_names([package_name])
            package_name = entropy.dep.dep_getkey(package_name)
        except AttributeError:
            raise
        return package_name

    def _get_document_type_filter(self):
        """
        Get Document type filter list from HTTP request data.
        Validate them and raise AttributeError in case of failure.
        """
        type_filters = (request.params.get("filter") or "").strip()
        type_filters = type_filters.split()
        if len(type_filters) > len(Document.SUPPORTED_TYPES):
            raise AttributeError("too many filters")
        try:
            type_filters = [int(x) for x in type_filters]
        except (TypeError, ValueError):
            raise AttributeError("malformed filters")

        for document_type_id in type_filters:
            if document_type_id not in Document.SUPPORTED_TYPES:
                raise AttributeError("unsupported filters")

        return type_filters

    def _get_document_type_id(self):
        """
        Get Document type id from HTTP request data.
        """
        document_type_id = request.params.get(
            Document.DOCUMENT_DOCUMENT_TYPE_ID)
        if not document_type_id:
            raise AttributeError("document type id not found")
        try:
            document_type_id = int(document_type_id)
            if document_type_id not in Document.SUPPORTED_TYPES:
                raise ValueError()
        except (ValueError, TypeError):
            raise AttributeError("document type id is invalid")
        return document_type_id

    def _get_document_ids(self):
        """
        Get Document ids from HTTP request data.
        """
        document_ids = (request.params.get("document_ids") or \
            "").strip().split()
        if not document_ids:
            raise AttributeError("document ids not found")
        try:
            document_ids = [int(x) for x in document_ids]
        except (ValueError, TypeError):
            raise AttributeError("document ids are invalid")

        # check data
        invalid_ints = [x for x in document_ids if x < 1]
        if invalid_ints:
            raise AttributeError("document ids are invalid (2)")

        return document_ids

    def _get_document_id(self):
        """
        Get Document ids from HTTP request data.
        """
        document_id = (request.params.get(Document.DOCUMENT_DOCUMENT_ID) or \
            "").strip()
        if not document_id:
            raise AttributeError("document id not found")
        try:
            document_id = int(document_id)
        except (ValueError, TypeError):
            raise AttributeError("document id is invalid")

        # check data
        if document_id < 1:
            raise AttributeError("document id is invalid (2)")

        return document_id

    def _ugc_document_data_to_document(self, document_data_list):
        """
        Convert raw UGC document metadata list to Document list.

        @raise AttributeError: if document data is malformed
        """
        outcome = []
        try:
            repository_id = self._get_repository_id()
            self._validate_repository_id(repository_id = repository_id)
        except AttributeError:
            raise
        for raw_document in document_data_list:
            self._validate_keywords(raw_document['keywords'])
            try:
                iddoc = int(raw_document['iddoc'])
            except (TypeError, ValueError):
                raise AttributeError("invalid iddoc")
            try:
                iddoctype = int(raw_document['iddoctype'])
                if iddoctype not in Document.SUPPORTED_TYPES:
                    raise ValueError()
            except (TypeError, ValueError):
                raise AttributeError("invalid iddoctype")

            doc = Document(repository_id, iddoc, iddoctype)
            unix_time = time.mktime(raw_document['ts'].timetuple())
            doc[Document.DOCUMENT_TIMESTAMP_ID] = unix_time
            doc[Document.DOCUMENT_DATA_ID] = raw_document['ddata']
            doc[Document.DOCUMENT_KEYWORDS_ID] = \
                " ".join(raw_document['keywords'])
            # these are html encoded ;-)
            doc[Document.DOCUMENT_TITLE_ID] = raw_document['title']
            doc[DocumentFactory.DOCUMENT_USERNAME_ID] = raw_document['username']
            doc[Document.DOCUMENT_DESCRIPTION_ID] = \
                raw_document['description']
            doc[Document.DOCUMENT_URL_ID] = raw_document['store_url']
            outcome.append(doc)

        return outcome

    def _service_render(self, response):
        try:
            return json.dumps(response)
        except TypeError:
            abort(503)

    def data_send_available(self):
        """
        Reads test_data field from the POST/GET request, calculates its
        md5 and returns the result.
        """
        test_param = request.params.get("test_param")
        if test_param != "hello":
            return self._generic_invalid_request(
                code = WebService.WEB_SERVICE_INVALID_REQUEST_CODE,
                message = "oh oh ohhh")

        test_file = request.params.get("test_file")
        if not isinstance(test_file, cgi.FieldStorage):
            return self._generic_invalid_request(
                code = WebService.WEB_SERVICE_INVALID_REQUEST_CODE,
                message = "oh oh ohhh")

        filename = test_file.filename
        f_obj = test_file.file

        valid = True
        chunk = ""
        while True:
            chunk = f_obj.read(256)
            if f_obj.read(1):
                valid = False
            break

        if not valid:
            return self._generic_invalid_request(
                code = WebService.WEB_SERVICE_INVALID_REQUEST_CODE,
                message = "bye bye")

        md5 = hashlib.md5()
        md5.update(chunk)
        response = self._api_base_response(
            WebService.WEB_SERVICE_RESPONSE_CODE_OK)
        response['r'] = md5.hexdigest()
        return self._service_render(response)

    def service_available(self):
        """
        Return whether the service is currently available.
        """
        response = self._api_base_response(
            WebService.WEB_SERVICE_RESPONSE_CODE_OK)
        response['r'] = True
        return self._service_render(response)

    def validate_credentials(self):
        """
        Validate currently provided credentials (username and password)

        NOTE: this should be used only across HTTPS
        """
        try:
            self._validate_repository_id()
        except AttributeError:
            return self._generic_invalid_request()

        try:
            username, user_id = self._try_auth_login()
        except AttributeError:
            return self._generic_invalid_request(
                code = WebService.WEB_SERVICE_INVALID_CREDENTIALS_CODE)

        response = self._api_base_response(
            WebService.WEB_SERVICE_RESPONSE_CODE_OK)
        response['r'] = user_id
        return self._service_render(response)

    def get_votes(self):
        """
        Get votes for given package names passed (in request)
        """
        try:
            self._validate_repository_id()
        except AttributeError:
            return self._generic_invalid_request()

        try:
            package_names = self._get_package_names()
        except AttributeError:
            return self._generic_invalid_request()

        ugc = None
        try:
            ugc = self._ugc()
            vote_data = ugc.get_ugc_votes(package_names)
        finally:
            if ugc is not None:
                ugc.disconnect()

        # fill unavailable packages with None value
        for package_name in package_names:
            if package_name not in vote_data:
                vote_data[package_name] = None

        # ok valid
        response = self._api_base_response(
            WebService.WEB_SERVICE_RESPONSE_CODE_OK)
        response['r'] = vote_data
        return self._service_render(response)

    def get_available_votes(self):
        """
        Get all the available votes.
        """
        try:
            self._validate_repository_id()
        except AttributeError:
            return self._generic_invalid_request()
        repository_id = self._get_repository_id()

        cached_obj = None
        cache_key = None
        if model.config.WEBSITE_CACHING:
            sha = hashlib.sha1()
            # use today date
            now = datetime.now()
            date_str = "%s-%s-%s" % (now.year, now.month, now.day)
            sha.update(repr(date_str))
            sha.update(repr(repository_id))
            cache_key = "_get_available_votes_" + sha.hexdigest()
            cached_obj = self._cacher.pop(cache_key,
                cache_dir = model.config.WEBSITE_CACHE_DIR)

        if cached_obj is None:
            ugc = None
            try:
                ugc = self._ugc()
                cached_obj = ugc.get_ugc_allvotes()
            finally:
                if ugc is not None:
                    ugc.disconnect()

            if model.config.WEBSITE_CACHING:
                self._cacher.save(cache_key, cached_obj,
                    cache_dir = model.config.WEBSITE_CACHE_DIR)

        # ok valid
        response = self._api_base_response(
            WebService.WEB_SERVICE_RESPONSE_CODE_OK)
        response['r'] = cached_obj
        return self._service_render(response)

    def add_vote(self):
        """
        Add vote for package. This method requires authentication.
        """
        try:
            self._validate_repository_id()
        except AttributeError:
            return self._generic_invalid_request()

        try:
            username, user_id = self._try_auth_login()
        except AttributeError:
            return self._generic_invalid_request(
                code = WebService.WEB_SERVICE_INVALID_CREDENTIALS_CODE)

        try:
            package_name = self._get_package_name()
        except AttributeError:
            return self._generic_invalid_request()

        # validate vote
        vote = (request.params.get("vote") or "").strip()
        try:
            vote = int(vote)
            if vote not in ClientWebService.VALID_VOTES:
                raise ValueError()
        except ValueError:
            return self._generic_invalid_request()

        ugc = None
        try:
            ugc = self._ugc()
            voted = ugc.do_vote(package_name, user_id, vote)
            if voted:
                ugc.commit()
        finally:
            if ugc is not None:
                ugc.disconnect()

        response = self._api_base_response(
            WebService.WEB_SERVICE_RESPONSE_CODE_OK)
        response['r'] = voted
        return self._service_render(response)

    def get_downloads(self):
        """
        Get downloads for given package names passed (in request)
        """
        try:
            self._validate_repository_id()
        except AttributeError:
            return self._generic_invalid_request()

        try:
            package_names = self._get_package_names()
        except AttributeError:
            return self._generic_invalid_request()

        ugc = None
        try:
            ugc = self._ugc()
            down_data = ugc.get_ugc_downloads(package_names)
        finally:
            if ugc is not None:
                ugc.disconnect()

        # fill unavailable packages with None value
        for package_name in package_names:
            if package_name not in down_data:
                down_data[package_name] = None

        # ok valid
        response = self._api_base_response(
            WebService.WEB_SERVICE_RESPONSE_CODE_OK)
        response['r'] = down_data
        return self._service_render(response)

    def add_downloads(self):
        """
        Add vote for package. This method requires authentication.
        """
        try:
            self._validate_repository_id()
        except AttributeError:
            return self._generic_invalid_request()

        try:
            package_names = self._get_package_names()
        except AttributeError:
            return self._generic_invalid_request()

        # validate branch
        branch = (request.params.get('branch') or "").strip()
        if not branch:
            return self._generic_invalid_request()
        if not entropy.tools.validate_branch_name(branch):
            return self._generic_invalid_request()

        # validate release_string
        release_string = (request.params.get('release_string') or "").strip()
        if not release_string:
            return self._generic_invalid_request()
        if not entropy.tools.is_valid_string(release_string):
            return self._generic_invalid_request()

        # validate hw_hash
        hw_hash = (request.params.get('hw_hash') or "").strip()
        if not hw_hash:
            return self._generic_invalid_request()
        if not entropy.tools.is_valid_string(hw_hash):
            return self._generic_invalid_request()

        ip_addr = request.environ.get('REMOTE_ADDR')

        ugc = None
        try:
            ugc = self._ugc()
            added = ugc.do_download_stats(branch, release_string, hw_hash,
                package_names, ip_addr)
            if added:
                ugc.commit()
        finally:
            if ugc is not None:
                ugc.disconnect()

        response = self._api_base_response(
            WebService.WEB_SERVICE_RESPONSE_CODE_OK)
        response['r'] = added
        return self._service_render(response)

    def get_available_downloads(self):
        """
        Get all the available downloads.
        """
        try:
            self._validate_repository_id()
        except AttributeError:
            return self._generic_invalid_request()
        repository_id = self._get_repository_id()

        cached_obj = None
        cache_key = None
        if model.config.WEBSITE_CACHING:
            sha = hashlib.sha1()
            # use today date
            now = datetime.now()
            date_str = "%s-%s-%s" % (now.year, now.month, now.day)
            sha.update(repr(date_str))
            sha.update(repr(repository_id))
            cache_key = "_get_available_downloads_" + sha.hexdigest()
            cached_obj = self._cacher.pop(cache_key,
                cache_dir = model.config.WEBSITE_CACHE_DIR)

        if cached_obj is None:
            ugc = None
            try:
                ugc = self._ugc()
                cached_obj = ugc.get_ugc_alldownloads()
            finally:
                if ugc is not None:
                    ugc.disconnect()

            if model.config.WEBSITE_CACHING:
                self._cacher.save(cache_key, cached_obj,
                    cache_dir = model.config.WEBSITE_CACHE_DIR)

        # ok valid
        response = self._api_base_response(
            WebService.WEB_SERVICE_RESPONSE_CODE_OK)
        response['r'] = cached_obj
        return self._service_render(response)

    def add_document(self):
        """
        Add Document object to the repository. Document data is in the request
        header and body. Files are base64 encoded.
        """
        try:
            self._validate_repository_id()
        except AttributeError:
            return self._generic_invalid_request()

        try:
            package_name = self._get_package_name()
        except AttributeError:
            return self._generic_invalid_request()

        # validate repository id from document
        repository_id = request.params.get(Document.DOCUMENT_REPOSITORY_ID)
        try:
            self._validate_repository_id(repository_id = repository_id)
        except AttributeError:
            return self._generic_invalid_request()

        # document id is ignored, since this is an "add"
        # get document_type_id
        try:
            document_type_id = self._get_document_type_id()
        except AttributeError:
            return self._generic_invalid_request()

        try:
            username, user_id = self._try_auth_login()
        except AttributeError:
            return self._generic_invalid_request(
                code = WebService.WEB_SERVICE_INVALID_CREDENTIALS_CODE)

        action_map = {
            Document.COMMENT_TYPE_ID: self._add_comment,
            Document.IMAGE_TYPE_ID: self._add_generic_file_document,
            Document.FILE_TYPE_ID: self._add_generic_file_document,
            Document.VIDEO_TYPE_ID: self._add_generic_file_document,
            Document.ICON_TYPE_ID: self._add_generic_file_document,
        }

        func = action_map.get(document_type_id)
        if func is None:
            # unsupported !
            return self._generic_invalid_request()
        return func(package_name, document_type_id, username, user_id)

    def _add_document_get_comment(self, req_field):
        """
        Get comment data from HTTP request, specific to add_document call.

        @raise AttributeError: if comment is invalid
        """
        comment = (request.params.get(req_field) or "").strip()
        if not comment:
            raise AttributeError("no comment")
        if len(comment) < 5:
            raise AttributeError("comment too short")
        return self._htmlencode(comment)

    def _add_document_get_title(self, req_field):
        """
        Get title data from HTTP request, specific to add_document call.

        @raise AttributeError: if comment is invalid
        """
        title = (request.params.get(req_field) or "").strip()
        if not title:
            raise AttributeError("no title")
        return self._htmlencode(title)

    def _add_document_get_description(self, req_field):
        """
        Get description data from HTTP request, specific to add_document call.

        @raise AttributeError: if comment is invalid
        """
        desc = (request.params.get(req_field) or "").strip()
        if not desc:
            raise AttributeError("no description")
        if len(desc) < 5:
            raise AttributeError("description too short")
        return self._htmlencode(desc)

    def _add_comment(self, package_name, document_type_id, username, user_id):
        """
        Add comment, reading data from request.
        """
        try:
            comment = self._add_document_get_comment(Document.DOCUMENT_DATA_ID)
        except AttributeError:
            return self._generic_invalid_request()

        try:
            title = self._add_document_get_title(Document.DOCUMENT_TITLE_ID)
        except AttributeError:
            return self._generic_invalid_request()

        try:
            keywords = self._api_get_keywords()
        except AttributeError:
            # invalid keywords
            return self._generic_invalid_request()

        doc = None
        ugc = None
        try:
            ugc = self._ugc()
            # commit is very important
            status, iddoc = ugc.insert_comment(package_name, user_id,
                username, comment, title, keywords)
            if status:
                ugc.commit()
                raw_docs = ugc.get_ugc_metadata_by_identifiers([iddoc])
                try:
                    docs = self._ugc_document_data_to_document(raw_docs)
                except AttributeError:
                    return self._generic_invalid_request()
                doc = docs[0]
        finally:
            if ugc is not None:
                ugc.disconnect()

        response = self._api_base_response(
            WebService.WEB_SERVICE_RESPONSE_CODE_OK)
        response['r'] = doc
        return self._service_render(response)

    def _add_document_get_payload_file(self):
        """
        Read from HTTP POST request, the file at payload parameter.

        @raise AttributeError: if payload data is not available or invalid
        """
        payload = request.params.get(DocumentFactory.DOCUMENT_PAYLOAD_ID)
        if payload is None:
            raise AttributeError("no payload")

        if not hasattr(payload, "filename"):
            raise AttributeError("invalid payload")
        try:
            orig_filename = os.path.basename(payload.filename.lstrip(os.sep))
        except AttributeError:
            # wtf?
            raise AttributeError("invalid payload (2)")

        tmp_fd, tmp_file = tempfile.mkstemp(dir = model.config.WEBSITE_TMP_DIR)
        with os.fdopen(tmp_fd, "wb") as tmp_f:
            shutil.copyfileobj(payload.file, tmp_f)
            payload.file.close()
            tmp_f.flush()
            fsize = tmp_f.tell()

        # we already check this server side, in
        # middleware.py, two is better than none
        if fsize > model.config.UGC_MAX_UPLOAD_FILE_SIZE:
            try:
                os.remove(tmp_file)
            except OSError as err:
                if err.errno != errno.ENOENT:
                    raise
            raise AttributeError("payload is fat")

        return tmp_file, orig_filename

    def _add_generic_file_document(self, package_name, document_type, username,
        user_id):
        """
        Add Generic file-based (with payload in HTTP Request parameters)
        Document to the repo.
        """
        try:
            title = self._add_document_get_title(Document.DOCUMENT_TITLE_ID)
        except AttributeError:
            return self._generic_invalid_request()

        try:
            description = self._add_document_get_description(
                Document.DOCUMENT_DESCRIPTION_ID)
        except AttributeError:
            return self._generic_invalid_request()

        try:
            keywords = self._api_get_keywords()
        except AttributeError:
            # invalid keywords
            return self._generic_invalid_request()

        # get payload data
        try:
            payload_tmp_file, orig_filename = \
                self._add_document_get_payload_file()
        except AttributeError as err:
            return self._generic_invalid_request(message = str(err))

        doc = None
        ugc = None
        message = None
        try:
            ugc = self._ugc()
            file_name = os.path.join(package_name, orig_filename)
            status, iddoc = ugc.insert_document_autosense(package_name,
                document_type, user_id, username, None, payload_tmp_file,
                file_name, orig_filename, title, description, keywords)
            if not status:
                if isinstance(iddoc, const_get_stringtype()):
                    return self._generic_invalid_request(message = iddoc)
                return self._generic_invalid_request()

            ugc.commit()
            raw_docs = ugc.get_ugc_metadata_by_identifiers([iddoc])
            try:
                docs = self._ugc_document_data_to_document(raw_docs)
            except AttributeError:
                return self._generic_invalid_request()
            doc = docs[0]
        finally:
            # not really atomic actually
            try:
                os.remove(payload_tmp_file)
            except OSError as err:
                if err.errno != errno.ENOENT:
                    raise
            if ugc is not None:
                ugc.disconnect()

        response = self._api_base_response(
            WebService.WEB_SERVICE_RESPONSE_CODE_OK,
            message = message)
        response['r'] = doc
        return self._service_render(response)

    def get_documents(self):
        """
        Get Document objects for given package_names. Filtering them out
        using "filter" directive.
        """
        try:
            self._validate_repository_id()
        except AttributeError:
            return self._generic_invalid_request()

        try:
            package_names = self._get_package_names()
        except AttributeError:
            return self._generic_invalid_request()

        # validate type filters
        try:
            document_types = self._get_document_type_filter()
        except AttributeError:
            return self._generic_invalid_request()

        if not document_types:
            # get all the docs, if no filter is set
            document_types.extend(Document.SUPPORTED_TYPES)

        # validate offset, if any
        offset = request.params.get("offset")
        if not offset:
            offset = 0
        else:
            try:
                offset = int(offset)
            except (TypeError, ValueError):
                offset = 0

        chunk_size = 15

        data = {}
        ugc = None
        try:
            ugc = self._ugc()
            for package_name in package_names:
                total, pkg_data_list = ugc.get_ugc_metadata_doctypes(
                    package_name, document_types, offset = offset,
                    length = chunk_size)
                total = len(pkg_data_list)
                try:
                    docs = self._ugc_document_data_to_document(pkg_data_list)
                except AttributeError:
                    return self._generic_invalid_request()
                data[package_name] = {
                    'total': total,
                    'docs': docs,
                }
        finally:
            if ugc is not None:
                ugc.disconnect()

        response = self._api_base_response(
            WebService.WEB_SERVICE_RESPONSE_CODE_OK)
        response['r'] = data
        return self._service_render(response)

    def get_documents_by_id(self):
        """
        Get Document objects given their identifier.
        """
        try:
            document_ids = self._get_document_ids()
        except AttributeError:
            return self._generic_invalid_request()

        ugc = None
        try:
            ugc = self._ugc()
            raw_docs = ugc.get_ugc_metadata_by_identifiers(document_ids)
        finally:
            if ugc is not None:
                ugc.disconnect()

        docs = self._ugc_document_data_to_document(raw_docs)
        data = dict((doc.document_id(), doc) for doc in docs)
        response = self._api_base_response(
            WebService.WEB_SERVICE_RESPONSE_CODE_OK)
        response['r'] = data
        return self._service_render(response)

    def remove_document(self):
        """
        Remove a Document given its identifier
        """
        try:
            document_id = self._get_document_id()
        except AttributeError:
            return self._generic_invalid_request()

        ugc = None
        try:
            ugc = self._ugc()
            # get document type
            document_type_id = ugc.get_iddoctype(document_id)
            if document_type_id == -1:
                # document_id not available
                return False
            status, r_id = ugc.remove_document_autosense(document_id,
                document_type_id)
            if status:
                ugc.commit()
        finally:
            if ugc is not None:
                ugc.disconnect()

        response = self._api_base_response(
            WebService.WEB_SERVICE_RESPONSE_CODE_OK)
        response['r'] = status
        return self._service_render(response)

    def report_error(self):

        subject = 'Entropy Error Reporting Handler'
        sender_email_fallback = os.environ.get('ETP_SENDER_EMAIL_FALLBACK',
            'www-data@sabayon.org')
        error_report_mail = os.environ.get('ETP_ERROR_REPORT_MAIL',
            'entropy.errors@sabayon.org')

        sender_email = request.params.get('email') or sender_email_fallback
        if not self._is_valid_email(sender_email):
            sender_email = sender_email_fallback
        keys_to_file = ['errordata', 'processes', 'lspci', 'dmesg', 'locale',
            'lsof', 'repositories.conf', 'client.conf']

        # call it over
        mail_txt = ''
        for key in sorted(request.params):
            if key in keys_to_file:
                continue
            mail_txt += '%s: %s\n' % (key, request.params.get(key),)

        date = datetime.fromtimestamp(time.time())

        # add ip address
        ip_addr = request.environ.get('REMOTE_ADDR')
        mail_txt += 'ip_address: %s\n' % (ip_addr,)
        mail_txt += 'date: %s\n' % (date,)

        files = []
        rm_paths = []
        for key in keys_to_file:
            if key not in request.params:
                continue

            fd, path = tempfile.mkstemp(suffix = "__%s.txt" % (key,))
            try:
                with os.fdopen(fd, "wb") as f_path:
                    f_path.write(request.params.get(key, ''))
                    f_path.flush()
            except IOError:
                continue
            finally:
                rm_paths.append(path)

            files.append(path)

        sender = EmailSender()
        try:
            sender.send_mime_email(sender_email, [error_report_mail],
                subject, mail_txt, files)
        finally:
            for rm_path in rm_paths:
                os.remove(rm_path)

        response = self._api_base_response(
            WebService.WEB_SERVICE_RESPONSE_CODE_OK)
        response['r'] = True
        return self._service_render(response)

