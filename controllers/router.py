"""
Sabayon Best Mirror Router API

Routes ISO and Packages requests to the closest mirror.
"""
import os
import random

from pylons import request
from pylons.controllers import WSGIController
from pylons.controllers.util import redirect, abort

from www.lib.geoip import EntropyGeoIP
from www.lib.exceptions import ServiceConnectionError

from www.model import config
from www.model.Mirrors import Mirrors

class RouterController(WSGIController):

    def __init__(self):
        self._geoip_path = config.GEOIP_DB_PATH

    def _get_ip_address(self, request):
        ip_addr = request.environ.get('HTTP_X_FORWARDED_FOR')
        if not ip_addr:
            ip_addr = request.environ.get('REMOTE_ADDR')
        return ip_addr

    def route(self, target):
        if not target:
            return abort(404)
        ip_address = self._get_ip_address(request)
        geoip = EntropyGeoIP(self._geoip_path)
        data = geoip.get_geoip_record_from_ip(ip_address)
        country = geoip.get_geoip_country_code_from_ip(ip_address)
        continent = geoip.COUNTRY_CONTINENT.get(country)
        fallback_continent = "EU"

        if continent is None:
            continent = fallback_continent # fallback continent

        mrs = None
        try:
            mrs = Mirrors()
            mirrors = mrs.continent_mirrors(continent)
            if not mirrors and continent != fallback_continent:
                mirrors = mrs.continent_mirrors(fallback_continent)
            if not mirrors:
                return abort(404)
        except ServiceConnectionError:
            return abort(404)
        finally:
            if mrs is not None:
                mrs.disconnect()

        # pick one random mirror
        mirror = random.choice(mirrors)
        url = os.path.join(mirror, target)
        return redirect(url)

    def __call__(self, environ, start_response):
        """Invoke the Controller"""
        # WSGIController.__call__ dispatches to the Controller method
        # the request is routed to. This routing information is
        # available in environ['pylons.routes_dict']
        return WSGIController.__call__(self, environ, start_response)
