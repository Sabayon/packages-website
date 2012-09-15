import os

class EntropyGeoIP:

    """
    Entropy geo-tagging interface containing useful methods to ease
    metadata management and transformation.
    It's a wrapper over GeoIP at the moment dev-python/geoip-python
    required.

    Sample code:

        >>> geo = EntropyGeoIp("mygeoipdb.dat")
        >>> geo.get_geoip_record_from_ip("123.123.123.123")
        { dict() metadata }

    """

    # ISO-3166 Country -> Continent Map
    COUNTRY_CONTINENT = {
        "A1": "--",
        "A2": "--",
        "AD": "EU",
        "AE": "AS",
        "AF": "AS",
        "AG": "NA",
        "AI": "NA",
        "AL": "EU",
        "AM": "AS",
        "AN": "NA",
        "AO": "AF",
        "AP": "AS",
        "AQ": "AN",
        "AR": "SA",
        "AS": "OC",
        "AT": "EU",
        "AU": "OC",
        "AW": "NA",
        "AX": "EU",
        "AZ": "AS",
        "BA": "EU",
        "BB": "NA",
        "BD": "AS",
        "BE": "EU",
        "BF": "AF",
        "BG": "EU",
        "BH": "AS",
        "BI": "AF",
        "BJ": "AF",
        "BL": "NA",
        "BM": "NA",
        "BN": "AS",
        "BO": "SA",
        "BR": "SA",
        "BS": "NA",
        "BT": "AS",
        "BV": "AN",
        "BW": "AF",
        "BY": "EU",
        "BZ": "NA",
        "CA": "NA",
        "CC": "AS",
        "CD": "AF",
        "CF": "AF",
        "CG": "AF",
        "CH": "EU",
        "CI": "AF",
        "CK": "OC",
        "CL": "SA",
        "CM": "AF",
        "CN": "AS",
        "CO": "SA",
        "CR": "NA",
        "CU": "NA",
        "CV": "AF",
        "CX": "AS",
        "CY": "AS",
        "CZ": "EU",
        "DE": "EU",
        "DJ": "AF",
        "DK": "EU",
        "DM": "NA",
        "DO": "NA",
        "DZ": "AF",
        "EC": "SA",
        "EE": "EU",
        "EG": "AF",
        "EH": "AF",
        "ER": "AF",
        "ES": "EU",
        "ET": "AF",
        "EU": "EU",
        "FI": "EU",
        "FJ": "OC",
        "FK": "SA",
        "FM": "OC",
        "FO": "EU",
        "FR": "EU",
        "FX": "EU",
        "GA": "AF",
        "GB": "EU",
        "GD": "NA",
        "GE": "AS",
        "GF": "SA",
        "GG": "EU",
        "GH": "AF",
        "GI": "EU",
        "GL": "NA",
        "GM": "AF",
        "GN": "AF",
        "GP": "NA",
        "GQ": "AF",
        "GR": "EU",
        "GS": "AN",
        "GT": "NA",
        "GU": "OC",
        "GW": "AF",
        "GY": "SA",
        "HK": "AS",
        "HM": "AN",
        "HN": "NA",
        "HR": "EU",
        "HT": "NA",
        "HU": "EU",
        "ID": "AS",
        "IE": "EU",
        "IL": "AS",
        "IM": "EU",
        "IN": "AS",
        "IO": "AS",
        "IQ": "AS",
        "IR": "AS",
        "IS": "EU",
        "IT": "EU",
        "JE": "EU",
        "JM": "NA",
        "JO": "AS",
        "JP": "AS",
        "KE": "AF",
        "KG": "AS",
        "KH": "AS",
        "KI": "OC",
        "KM": "AF",
        "KN": "NA",
        "KP": "AS",
        "KR": "AS",
        "KW": "AS",
        "KY": "NA",
        "KZ": "AS",
        "LA": "AS",
        "LB": "AS",
        "LC": "NA",
        "LI": "EU",
        "LK": "AS",
        "LR": "AF",
        "LS": "AF",
        "LT": "EU",
        "LU": "EU",
        "LV": "EU",
        "LY": "AF",
        "MA": "AF",
        "MC": "EU",
        "MD": "EU",
        "ME": "EU",
        "MF": "NA",
        "MG": "AF",
        "MH": "OC",
        "MK": "EU",
        "ML": "AF",
        "MM": "AS",
        "MN": "AS",
        "MO": "AS",
        "MP": "OC",
        "MQ": "NA",
        "MR": "AF",
        "MS": "NA",
        "MT": "EU",
        "MU": "AF",
        "MV": "AS",
        "MW": "AF",
        "MX": "NA",
        "MY": "AS",
        "MZ": "AF",
        "NA": "AF",
        "NC": "OC",
        "NE": "AF",
        "NF": "OC",
        "NG": "AF",
        "NI": "NA",
        "NL": "EU",
        "NO": "EU",
        "NP": "AS",
        "NR": "OC",
        "NU": "OC",
        "NZ": "OC",
        "O1": "--",
        "OM": "AS",
        "PA": "NA",
        "PE": "SA",
        "PF": "OC",
        "PG": "OC",
        "PH": "AS",
        "PK": "AS",
        "PL": "EU",
        "PM": "NA",
        "PN": "OC",
        "PR": "NA",
        "PS": "AS",
        "PT": "EU",
        "PW": "OC",
        "PY": "SA",
        "QA": "AS",
        "RE": "AF",
        "RO": "EU",
        "RS": "EU",
        "RU": "EU",
        "RW": "AF",
        "SA": "AS",
        "SB": "OC",
        "SC": "AF",
        "SD": "AF",
        "SE": "EU",
        "SG": "AS",
        "SH": "AF",
        "SI": "EU",
        "SJ": "EU",
        "SK": "EU",
        "SL": "AF",
        "SM": "EU",
        "SN": "AF",
        "SO": "AF",
        "SR": "SA",
        "ST": "AF",
        "SV": "NA",
        "SY": "AS",
        "SZ": "AF",
        "TC": "NA",
        "TD": "AF",
        "TF": "AN",
        "TG": "AF",
        "TH": "AS",
        "TJ": "AS",
        "TK": "OC",
        "TL": "AS",
        "TM": "AS",
        "TN": "AF",
        "TO": "OC",
        "TR": "EU",
        "TT": "NA",
        "TV": "OC",
        "TW": "AS",
        "TZ": "AF",
        "UA": "EU",
        "UG": "AF",
        "UM": "OC",
        "US": "NA",
        "UY": "SA",
        "UZ": "AS",
        "VA": "EU",
        "VC": "NA",
        "VE": "SA",
        "VG": "NA",
        "VI": "NA",
        "VN": "AS",
        "VU": "OC",
        "WF": "OC",
        "WS": "OC",
        "YE": "AS",
        "YT": "AF",
        "ZA": "AF",
        "ZM": "AF",
        "ZW": "AF",
    }
    CONTINENTS = sorted(set(COUNTRY_CONTINENT.values()))

    def __init__(self, geoip_dbfile):

        """
        EntropyGeoIP constructor.

        @param geoip_dbfile: valid GeoIP (Maxmind) database file (.dat) path
            (download from:
            http://www.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz)
        @type geoip_dbfile: string
        """

        import GeoIP
        self.__geoip = GeoIP
        # http://www.maxmind.com/download/geoip/database/GeoLiteCity.dat.gz
        if not (os.path.isfile(geoip_dbfile) and \
            os.access(geoip_dbfile, os.R_OK)):
            raise AttributeError(
                "expecting a valid filepath for geoip_dbfile, got: %s" % (
                    repr(geoip_dbfile),
                )
            )
        self.__geoip_dbfile = geoip_dbfile

    def __get_geo_ip_generic(self):
        """ Private method """
        return self.__geoip.new(self.__geoip.GEOIP_MEMORY_CACHE)

    def __get_geo_ip_open(self):
        """ Private method """
        return self.__geoip.open(self.__geoip_dbfile,
            self.__geoip.GEOIP_STANDARD)

    def get_geoip_country_name_from_ip(self, ip_address):
        """
        Get country name from IP address.

        @param ip_address: ip address string
        @type ip_address: string
        @return: country name or None
        @rtype: string or None
        """
        gi_a = self.__get_geo_ip_generic()
        return gi_a.country_name_by_addr(ip_address)

    def get_geoip_country_code_from_ip(self, ip_address):
        """
        Get country code from IP address.

        @param ip_address: ip address string
        @type ip_address: string
        @return: country code or None
        @rtype: string or None
        """
        gi_a = self.__get_geo_ip_generic()
        return gi_a.country_code_by_addr(ip_address)

    def get_geoip_record_from_ip(self, ip_address):
        """
        Get GeoIP record from IP address.

        @param ip_address: ip address string
        @type ip_address: string
        @return: GeoIP record data
        @rtype: dict
        """
        go_a = self.__get_geo_ip_open()
        return go_a.record_by_addr(ip_address)

    def get_geoip_record_from_hostname(self, hostname):
        """
        Get GeoIP record from hostname.

        @param hostname: ip address string
        @type hostname: string
        @return: GeoIP record data
        @rtype: dict
        """
        go_a = self.__get_geo_ip_open()
        return go_a.record_by_name(hostname)
