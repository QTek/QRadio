#################################################################
#                                                               #
#   Blacklist stations for QRadio                               #
#                       ~ Tune In                               #
#   Tuned to:                                                   #
#            Asprox                                             #
#            Feodo                                              #
#            Malc0de                                            #
#            Zeustracker                                        #
#            Mcafee                                             #
#                                                               #
#       Author: 10TOHH                                          #
#                                                               #
#   Tunes:                                                      #
#   ipv4_to_blacklist       -   Return True/False               #
#   domain_to_blacklist     -   Return True/False               #
#                                                               #
#################################################################

from lib import helpers
import re

# Use this class for global search
class Blacklist(object):

    def __init__(self):
        # List of all current blacklists tunes
        self.a = Asprox()
        self.f = Feodo()
        self.m = Malc0de()
        self.z = Zeustracker()
        self.ma = Mcafee()

    # Check IPv4 in blacklist tunes
    def ipv4_blacklist_check(self, ip_address):
        if self.a.ipv4_to_blacklist(ip_address):
            return True
        elif self.f.ipv4_to_blacklist(ip_address):
            return True
        elif self.m.ipv4_to_blacklist(ip_address):
            return True
        elif self.z.ipv4_to_blacklist(ip_address):
            return True
        elif self.ma.ipv4_to_blacklist(ip_address):
            return True
        else:
            return False
    # Check Domain in blacklist tunes
    def domain_blacklist_check(self, domain_name):
        if self.ma.domain_to_blacklist(domain_name):
            return True
        else:
            return False

#########################################################
# Station tunes

class Asprox(object):

    def __init__(self):
        # get helping functions
        self.api = helpers.Common()

        # static station settings
        self.station_name = 'Asprox'
        self.endpoint = 'http://atrack.h3x.eu/c2'
        self.response_format = 'bs'

    def ipv4_to_blacklist(self, ip_address):
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           response_format=self.response_format)

        if response:
            table = response.findAll('div', {'class': 'code'})
            if table:
                for key in table:
                    match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', str(key.text))
                    if match.group() == ip_address:
                        return True
                    else:
                        return False

############################

class Feodo(object):

    def __init__(self):
        # get helping functions
        self.api = helpers.Common()

        # static station settings
        self.station_name = 'Feodo'
        self.endpoint = 'https://feodotracker.abuse.ch/blocklist/?download=ipblocklist'

    def ipv4_to_blacklist(self, ip_address):
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get')


        match = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', response.text)
        for i in match:
            if ip_address == str(i):
                return True
        return False

############################

class Malc0de(object):

    def __init__(self):
        # get helping functions
        self.api = helpers.Common()

        # static station settings
        self.station_name = 'Malc0de'
        self.endpoint = 'http://malc0de.com/bl/IP_Blacklist.txt'

    def ipv4_to_blacklist(self, ip_address):
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get')


        match = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', response.text)
        for i in match:
            if ip_address == str(i):
                return True
        return False

############################

class Zeustracker(object):

    def __init__(self):
        # get helping functions
        self.api = helpers.Common()

        # static station settings
        self.station_name = 'Zeustracker'
        self.endpoint = 'https://zeustracker.abuse.ch/blocklist.php?download=ipblocklist'

    def ipv4_to_blacklist(self, ip_address):
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get')


        match = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', response.text)
        for i in match:
            if ip_address == str(i):
                return True
        return False

class Mcafee(object):

    def __init__(self):
        # get helping functions
        self.api = helpers.Common()

        # static station settings
        self.station_name = 'McAfee'
        self.endpoint = 'http://www.siteadvisor.com/sites/'
        self.response_format = 'bs'

    def to_blacklist(self, search_value):
        url_path = search_value
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           url_path=url_path, response_format=self.response_format)


        if response:
            table = response.findAll('p', {'class': 'intro'})
            if table:
                for key in table:
                    match = re.search(r'dangerous', str(key.text))
                    match_2 = re.search(r'suspicious', str(key.text))

                    if match or match_2:
                        return True
                    else:
                        return False

    def ipv4_to_blacklist(self, ip_address):
        return self.to_blacklist(ip_address)

    def domain_to_blacklist(self, domain_name):
        return self.to_blacklist(domain_name)

if __name__ == '__main__':
    test_ip = '8.8.8.8'
    test_domain = 'abc.com'
    #print 'ipv4', Blacklist().ipv4_blacklist_check(test_ip)
    #print 'domain', Blacklist().domain_blacklist_check(test_domain)