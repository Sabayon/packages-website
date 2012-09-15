# -*- coding: utf-8 -*-
import os
import config
try:
    from entropy.services.exceptions import ServiceConnectionError
except ImportError:
    ServiceConnectionError = Exception

from www.lib.mysql import Database

class Mirrors(Database):

    def __init__(self):
        Database.__init__(self)
        self.set_connection_data(config.mirror_connection_data)
        self.connect()
        self.dbconn.set_character_set('utf8')

    def continent_mirrors(self, continent):
        """
        Return the list of mirrors for the given continent.
        """
        self.execute_query("""
        SELECT
            http_t.field_mirror_http_uri_url as http_url
        FROM
            field_data_field_mirror_http_uri as http_t,
            field_data_field_use_in_router as router_t,
            field_data_field_continent as continent_t
        WHERE
            continent_t.field_continent_value = %s AND
            http_t.entity_id = router_t.entity_id AND
            http_t.entity_id = continent_t.entity_id AND
            router_t.field_use_in_router_value = "1" AND
            router_t.deleted = "0"
        """, (continent,))
        return [x['http_url'] for x in self.fetchall()]
