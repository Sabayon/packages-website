"""
Sabayon Best Mirror Router API

Routes ISO and Packages requests to the closest mirror.
"""
import os
import random

from pylons import request
from pylons.controllers import WSGIController
from pylons.controllers.util import redirect

from www.lib.geoip import EntropyGeoIP

from www.model import config

class RouterController(WSGIController):

    # Africa
    _AF_MIRRORS = [
        "http://sabayon.mirror.ac.za",
        "http://mirror.freelydifferent.com/sabayon",
        "http://na.mirror.garr.it/mirrors/sabayonlinux",
        ]

    # Asia
    _AS_MIRRORS = [
        "http://ftp.kddilabs.jp/Linux/packages/sabayonlinux",
        "http://ftp.yz.yamagata-u.ac.jp/pub/linux/sabayonlinux",
        "http://sulawesi.idrepo.or.id/sabayon",
        "http://sabayon.idrepo.or.id/sabayon",
        "http://ftp.riken.jp/Linux/sabayon",
        "http://mirror.yandex.ru/sabayon",
        ]

    # Europe
    _EU_MIRRORS = [
        "http://na.mirror.garr.it/mirrors/sabayonlinux",
        "http://ftp.nluug.nl/pub/os/Linux/distr/sabayonlinux",
        "http://gd.tuwien.ac.at/linux/sabayonlinux",
        "http://ftp.klid.dk/sabayonlinux",
        "http://mirror.yandex.ru/sabayon",
        ]

    # North America
    _NA_MIRRORS = [
        "http://cross-lfs.sabayonlinux.org",
        "http://mirror.clarkson.edu/sabayon",
        "http://mirror.umd.edu/sabayonlinux",
        ]

    # Oceania
    _OC_MIRRORS  = [
        "http://mirror.optusnet.com.au/sabayon",
        "http://mirror.internode.on.net/pub/sabayon",
        "http://ftp.yz.yamagata-u.ac.jp/pub/linux/sabayonlinux",
        "http://ftp.kddilabs.jp/Linux/packages/sabayonlinux",
        ]

    # South America
    _SA_MIRRORS  = [
        "http://sabayon.c3sl.ufpr.br",
        "http://mirrors.coopvgg.com.ar/sabayon",
        ] + _NA_MIRRORS

    # Arctic
    _AN_MIRRORS = _NA_MIRRORS

    _CONTINENTS_MAP = {
        "AF": _AF_MIRRORS, # Africa
        "AN": _AN_MIRRORS, # Arctic
        "AS": _AS_MIRRORS, # Aia
        "EU": _EU_MIRRORS, # Europe
        "NA": _NA_MIRRORS, # North America
        "OC": _OC_MIRRORS, # Oceania
        "SA": _SA_MIRRORS, # South America
        "--": _EU_MIRRORS, # fallback
        }

    def __init__(self):
        self._geoip_path = config.GEOIP_DB_PATH

    def _get_ip_address(self, request):
        ip_addr = request.environ.get('HTTP_X_FORWARDED_FOR')
        if not ip_addr:
            ip_addr = request.environ.get('REMOTE_ADDR')
        return ip_addr

    def route(self, target):
        ip_address = self._get_ip_address(request)
        geoip = EntropyGeoIP(self._geoip_path)
        data = geoip.get_geoip_record_from_ip(ip_address)
        country = geoip.get_geoip_country_code_from_ip(ip_address)
        continent = geoip.COUNTRY_CONTINENT.get(country)
        if continent is None:
            continent = "--" # fallback continent
        mirrors = self._CONTINENTS_MAP.get(continent)
        if mirrors is None:
            mirrors = self._CONTINENTS_MAP.get("--")

        # pick one random mirror
        while True:
            # TODO: make sure url exists?
            rand_idx = random.randint(0, len(mirrors) - 1)
            mirror = mirrors[rand_idx]
            url = mirror + "/" + target
            break
        return redirect(url)

    def __call__(self, environ, start_response):
        """Invoke the Controller"""
        # WSGIController.__call__ dispatches to the Controller method
        # the request is routed to. This routing information is
        # available in environ['pylons.routes_dict']
        return WSGIController.__call__(self, environ, start_response)
