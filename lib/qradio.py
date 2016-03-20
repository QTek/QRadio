# -*- coding: utf-8 -*-
import sys, os
sys.path.append(os.path.abspath(os.path.join('..')))
# Import all stations
from stations.blacklists.station import *
from stations.cymon.station import *
from stations.fortiguard.station import *
from stations.hostsfile.station import *
from stations.ibmxforceex.station import *
from stations.malwr.station import *
from stations.metascan.station import *
from stations.threatcrowd.station import *
from stations.threatexpert.station import *
from stations.totalhash.station import *
from stations.virustotal.station import *
import helpers


##### DOMAIN SECTION ######
class From_domain(object):
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.ip_dict = {}
        self.hash_dict = {}
        self.score_dict = {}
        self.url_dict = {}
        self.blacklist_dict = {}

    ########################################
    # Searches to IP
    def to_ipv4(self, search_value):
        if search_value:
            self.ip_dict.update({'Cymon': Cymon().domain_to_ipv4(search_value)})
            self.ip_dict.update({'FortiGuard': Fortiguard().domain_to_ipv4(search_value)})
            self.ip_dict.update({'Hostsfile': Hostsfile().domain_to_ipv4(search_value)})
            self.ip_dict.update({'IBM': Ibmxforce().domain_to_ipv4(search_value)})
            self.ip_dict.update({'Threatcrowd': Threatcrowd().domain_to_ipv4(search_value)})
            self.ip_dict.update({'Virustotal': Virustotal().domain_to_ipv4(search_value)})

            if self.verbose:
                return helpers.Common().verbose_output(search_value, From_domain.__name__, self.to_ipv4.__name__,
                                                       self.ip_dict)
            else:
                return helpers.Common().nonverbose_output(search_value, From_domain.__name__, self.to_ipv4.__name__,
                                                          self.ip_dict)

    ########################################
    # Searches to HASH
    def to_hash(self, search_value):
        if search_value:
            self.hash_dict.update({'Malwr': Malwr().domain_to_hash(search_value)})
            self.hash_dict.update({'IBM': Ibmxforce().domain_to_hash(search_value)})
            self.hash_dict.update({'Threatexpert': Threatexpert().domain_to_hash(search_value)})
            self.hash_dict.update({'Totalhash': Totalhash().domain_to_hash(search_value)})
            self.hash_dict.update({'Threatcrowd': Threatcrowd().domain_to_hash(search_value)})

            if self.verbose:
                return helpers.Common().verbose_output(search_value, From_domain.__name__, self.to_hash.__name__,
                                                       self.hash_dict)
            else:
                return helpers.Common().nonverbose_output(search_value, From_domain.__name__, self.to_hash.__name__,
                                                          self.hash_dict)

    ########################################
    # Searches to SCORE
    def to_score(self, search_value):
        if search_value:
            self.score_dict.update({'Malwr': Malwr().domain_to_score(search_value)})
            self.score_dict.update({'IBM': Ibmxforce().domain_to_score(search_value)})

            if self.verbose:
                return helpers.Common().verbose_output(search_value, From_domain.__name__, self.to_score.__name__,
                                                       self.score_dict)
            else:
                return helpers.Common().nonverbose_output(search_value, From_domain.__name__, self.to_score.__name__,
                                                          self.score_dict)

    ########################################
    # Searches to URL
    def to_url(self, search_value):
        if search_value:
            self.url_dict.update({'Malwr': Malwr().domain_to_url(search_value)})
            self.url_dict.update({'Totalhash': Totalhash().domain_to_url(search_value)})

            if self.verbose:
                return helpers.Common().verbose_output(search_value, From_domain.__name__, self.to_url.__name__,
                                                       self.url_dict)
            else:
                return helpers.Common().nonverbose_output(search_value, From_domain.__name__, self.to_url.__name__,
                                                          self.url_dict)

    ########################################
    # Searches to BLACKLISTS
    def to_blacklist(self, search_value):
        if search_value:
            if self.verbose:
                self.blacklist_dict.update({'McAfee': Mcafee().domain_to_blacklist(search_value)})

                return helpers.Common().verbose_output(search_value, From_domain.__name__, self.to_blacklist.__name__,
                                                       self.blacklist_dict)
            else:
                return helpers.Common().nonverbose_output(search_value, From_domain.__name__, self.to_blacklist.__name__,
                                                          str(Blacklist().domain_blacklist_check(search_value)))



##### IP SECTION ######
class From_ipv4(object):
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.domain_dict = {}
        self.hash_dict = {}
        self.score_dict = {}
        self.url_dict = {}
        self.blacklist_dict = {}

    ########################################
    # Searches to DOMAIN
    def to_domain(self, search_value):
        if search_value:
            self.domain_dict.update({'Cymon': Cymon().ipv4_to_domain(search_value)})
            self.domain_dict.update({'Hostsfile': Hostsfile().ipv4_to_domain(search_value)})
            self.domain_dict.update({'IBM': Ibmxforce().ipv4_to_domain(search_value)})
            self.domain_dict.update({'Threatcrowd': Threatcrowd().ipv4_to_domain(search_value)})
            self.domain_dict.update({'Virustotal': Virustotal().ipv4_to_domain(search_value)})

            if self.verbose:
                return helpers.Common().verbose_output(search_value, From_ipv4.__name__, self.to_domain.__name__,
                                                       self.domain_dict)
            else:
                return helpers.Common().nonverbose_output(search_value, From_ipv4.__name__, self.to_domain.__name__,
                                                          self.domain_dict)

    ########################################
    # Searches to HASH
    def to_hash(self, search_value):
        if search_value:
            self.hash_dict.update({'Cymon': Cymon().ipv4_to_hash(search_value)})
            self.hash_dict.update({'Malwr': Malwr().ipv4_to_hash(search_value)})
            self.hash_dict.update({'IBM': Ibmxforce().ipv4_to_hash(search_value)})
            self.hash_dict.update({'Threatcrowd': Threatcrowd().ipv4_to_hash(search_value)})
            self.hash_dict.update({'Threatexpert': Threatexpert().ipv4_to_hash(search_value)})
            self.hash_dict.update({'Totalhash': Totalhash().ipv4_to_hash(search_value)})
            self.hash_dict.update({'Virustotal': Virustotal().ipv4_to_hash(search_value)})

            if self.verbose:
                return helpers.Common().verbose_output(search_value, From_ipv4.__name__, self.to_hash.__name__,
                                                       self.hash_dict)
            else:
                return helpers.Common().nonverbose_output(search_value, From_ipv4.__name__, self.to_hash.__name__,
                                                          self.hash_dict)

    ########################################
    # Searches to SCORE
    def to_score(self, search_value):
        if search_value:
            self.score_dict.update({'Malwr': Malwr().ipv4_to_score(search_value)})
            self.score_dict.update({'Metascan': Metascan().ipv4_to_score(search_value)})
            self.score_dict.update({'IBM': Ibmxforce().ipv4_to_score(search_value)})

            if self.verbose:
                return helpers.Common().verbose_output(search_value, From_ipv4.__name__, self.to_score.__name__,
                                                       self.score_dict)
            else:
                return helpers.Common().nonverbose_output(search_value, From_ipv4.__name__, self.to_score.__name__,
                                                          self.score_dict)

    ########################################
    # Searches to URL
    def to_url(self, search_value):
        if search_value:
            self.url_dict.update({'Cymon': Cymon().ipv4_to_url(search_value)})
            self.url_dict.update({'Malwr': Malwr().ipv4_to_url(search_value)})
            self.url_dict.update({'Totalhash': Totalhash().ipv4_to_url(search_value)})

            if self.verbose:
                return helpers.Common().verbose_output(search_value, From_ipv4.__name__, self.to_url.__name__,
                                                       self.url_dict)
            else:
                return helpers.Common().nonverbose_output(search_value, From_ipv4.__name__, self.to_url.__name__,
                                                          self.url_dict)

    ########################################
    # Searches to BLACKLISTS
    def to_blacklist(self, search_value):
        if search_value:
            if self.verbose:
                self.blacklist_dict.update({'Asprox': Asprox().ipv4_to_blacklist(search_value)})
                self.blacklist_dict.update({'Feodo': Feodo().ipv4_to_blacklist(search_value)})
                self.blacklist_dict.update({'Malc0de': Malc0de().ipv4_to_blacklist(search_value)})
                self.blacklist_dict.update({'Zeustracker': Zeustracker().ipv4_to_blacklist(search_value)})
                self.blacklist_dict.update({'McAfee': Mcafee().ipv4_to_blacklist(search_value)})

                return helpers.Common().verbose_output(search_value, From_ipv4.__name__, self.to_blacklist.__name__,
                                                       self.blacklist_dict)
            else:
                return helpers.Common().nonverbose_output(search_value, From_ipv4.__name__, self.to_blacklist.__name__,
                                                          str(Blacklist().ipv4_blacklist_check(search_value)))


##### HASH SECTION ######
class From_hash(object):
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.ip_dict = {}
        self.score_dict = {}
        self.imphash_dict = {}
        self.url_dict = {}
        self.domain_dict = {}

    ########################################
    # Searches to IP
    def to_ipv4(self, search_value):
        if search_value:
            self.ip_dict.update({'IBM': Ibmxforce().hash_to_ipv4(search_value)})
            self.ip_dict.update({'Malwr': Malwr().hash_to_ipv4(search_value)})
            self.ip_dict.update({'Threatexpert': Threatexpert().hash_to_ipv4(search_value)})
            self.ip_dict.update({'Totalhash': Totalhash().hash_to_ipv4(search_value)})
            self.ip_dict.update({'Threatcrowd': Threatcrowd().hash_to_ipv4(search_value)})

            if self.verbose:
                return helpers.Common().verbose_output(search_value, From_hash.__name__, self.to_ipv4.__name__,
                                                       self.ip_dict)
            else:
                return helpers.Common().nonverbose_output(search_value, From_hash.__name__, self.to_ipv4.__name__,
                                                          self.ip_dict)

    ########################################
    # Searches to DOMAIN
    def to_domain(self, search_value):
        if search_value:
            self.domain_dict.update({'Threatexpert': Threatexpert().hash_to_domain(search_value)})
            self.domain_dict.update({'Totalhash': Totalhash().hash_to_domain(search_value)})
            self.domain_dict.update({'Threatcrowd': Threatcrowd().hash_to_domain(search_value)})


            if self.verbose:
                return helpers.Common().verbose_output(search_value, From_hash.__name__, self.to_domain.__name__,
                                                       self.domain_dict)
            else:
                return helpers.Common().nonverbose_output(search_value, From_hash.__name__, self.to_domain.__name__,
                                                          self.domain_dict)

    ########################################
    # Searches to SCORE
    def to_score(self, search_value):
        if search_value:
            self.score_dict.update({'Malwr': Malwr().hash_to_score(search_value)})
            self.score_dict.update({'Metascan': Metascan().hash_to_score(search_value)})
            self.score_dict.update({'IBM': Ibmxforce().hash_to_score(search_value)})
            self.score_dict.update({'Virustotal': Virustotal().hash_to_score(search_value)})

            if self.verbose:
                return helpers.Common().verbose_output(search_value, From_hash.__name__, self.to_score.__name__,
                                                       self.score_dict)
            else:
                return helpers.Common().nonverbose_output(search_value, From_hash.__name__, self.to_score.__name__,
                                                          self.score_dict)

    ########################################
    # Searches to URL
    def to_url(self, search_value):
        if search_value:
            self.url_dict.update({'Cymon': Cymon().hash_to_url(search_value)})
            self.url_dict.update({'Malwr': Malwr().hash_to_url(search_value)})
            self.url_dict.update({'Threatexpert': Threatexpert().hash_to_url(search_value)})
            self.url_dict.update({'Totalhash': Totalhash().hash_to_url(search_value)})
            self.url_dict.update({'Virustotal': Virustotal().hash_to_url(search_value)})
            self.url_dict.update({'Threatcrowd': Threatcrowd().hash_to_url(search_value)})

            if self.verbose:
                return helpers.Common().verbose_output(search_value, From_hash.__name__, self.to_url.__name__,
                                                       self.url_dict)
            else:
                return helpers.Common().nonverbose_output(search_value, From_hash.__name__, self.to_url.__name__,
                                                          self.url_dict)

    ########################################
    # Searches to IMPHASH
    def to_imphash(self, search_value):
        if search_value:
            self.imphash_dict.update({'Malwr': Malwr().hash_to_imphash(search_value)})
            self.imphash_dict.update({'Metascan': Metascan().hash_to_imphash(search_value)})
            self.imphash_dict.update({'Totalhash': Totalhash().hash_to_imphash(search_value)})

            if self.verbose:
                return helpers.Common().verbose_output(search_value, From_hash.__name__, self.to_imphash.__name__,
                                                       self.imphash_dict)
            else:
                return helpers.Common().nonverbose_output(search_value, From_hash.__name__, self.to_imphash.__name__,
                                                          self.imphash_dict)



##### IMPHASH SECTION ######
class From_imphash(object):
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.hash_dict = {}

    ########################################
    # Searches to HASH
    def to_hash(self, search_value):
        if search_value:
            self.hash_dict.update({'Threatexpert': Threatexpert().imphash_to_hash(search_value)})
            self.hash_dict.update({'Totalhash': Totalhash().imphash_to_hash(search_value)})

            if self.verbose:
                return helpers.Common().verbose_output(search_value, From_imphash.__name__, self.to_hash.__name__,
                                                       self.hash_dict)
            else:
                return helpers.Common().nonverbose_output(search_value, From_imphash.__name__, self.to_hash.__name__,
                                                          self.hash_dict)
##### MUTEX SECTION ######
class From_mutex(object):
    def __init__(self, verbose=False):
        self.verbose = verbose
        self.hash_dict = {}

    ########################################
    # Searches to HASH
    def to_hash(self, search_value):
        if search_value:
            self.hash_dict.update({'Threatexpert': Threatexpert().mutex_to_hash(search_value)})
            self.hash_dict.update({'Totalhash': Totalhash().mutex_to_hash(search_value)})

            if self.verbose:
                return helpers.Common().verbose_output(search_value, From_mutex.__name__, self.to_hash.__name__,
                                                       self.hash_dict)
            else:
                return helpers.Common().nonverbose_output(search_value, From_mutex.__name__, self.to_hash.__name__,
                                                          self.hash_dict)
