#################################################################
#   Cymon station for QRadio                                    #
#                       ~ Tune In                               #
#   Tuned to:                                                   #
#            https://cymon.io                                   #
#                                                               #
#   API Documentation:                                          #
#       http://docs.cymon.io/                                   #
#                                                               #
#       Author: 10TOHH                                          #
#                                                               #
#   Tunes:                                                      #
#   domain_to_ipv4  -   Resolves IP to <Domain>                 #
#   ipv4_to_domain  -   Resolves Domain to <IP>                 #
#   ipv4_to_hash    -   Return Hash associated with <IP>        #
#   ipv4_to_url     -   Return URL to report for given <IP>     #
#   hash_to_url     -   Return URL to report for given <Hash>   #
#################################################################

from lib import config, helpers

class Cymon(object):

    def __init__(self):
        # lists of values that can be returned
        self.ip_list = []
        self.domain_list = []
        self.hash_list = []
        self.url_list = []
        self.score_list = []
        self.imphash_list = []

        # get helping functions
        self.api = helpers.Common()
        self.error_log = helpers.IO()

        # static station settings
        self.station_name = 'Cymon'
        self.endpoint = 'https://cymon.io/api/nexus/v1/'
        self.url_path = ''
        self.parameters = {'limit': '1000'}
        self.headers = {'content-type': 'application/json',
            'accept': 'application/json',
            }
        self.user_agent = {}
        self.return_format = 'json'

        # Check for api key
        if config.cymon_api_key:
            self.headers.update({'Authorization': 'Token %s' %config.cymon_api_key})
        else:
            error_msg = 'API Key NOT provided'
            self.error_log.error_log(error_msg, self.station_name)

### Station tunes

    def domain_to_ipv4(self, domain_name):
        self.url_path = '/domain/' + domain_name
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.url_path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.return_format)
        if response:
            for key in response['ips']:
                self.ip_list.append(key.split('/')[-1])
        return self.ip_list

    def ipv4_to_domain(self, ip_address):
        self.url_path = '/ip/' + ip_address + '/domains'
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.url_path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.return_format)
        if response:
            for name in response['results']:
                self.domain_list.append(name['name'])
        return self.domain_list


    def ipv4_to_hash(self, ip_address):
        self.url_path = '/ip/' + ip_address + '/malware/'
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.url_path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.return_format)
        if response:
            for key in response['results']:
                if key['hash_type'] != 'SSDEEP': # Exclude SSDEEP
                    self.hash_list.append(key['hash_value'])
        return self.hash_list

    def ipv4_to_url(self, ip_address):
        self.url_path = '/ip/' + ip_address + '/events'
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.url_path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.return_format)
        if response:
            for key in response['results']:
                if key['details_url']:
                    self.url_list.append(key['details_url'])
        return list(set(self.url_list))

    def hash_to_url(self, hash_value):
        self.url_path = '/malware/' + hash_value + '/events/'
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.url_path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.return_format)
        if response:
            for key in response['results']:
                self.url_list.append(key['details_url'])
        return list(set(self.url_list))

### MAIN ###
if __name__ == '__main__':

    c = Cymon()
    ##print c.domain_to_ipv4('google.com')
    ##print c.ipv4_to_domain('216.58.219.14')
    ##print c.ipv4_to_hash('216.58.219.14')
    ##print c.ipv4_to_url('216.58.219.14')
    ##print c.hash_to_url('c1bed909e40f97a923eda3b738c58a6a8238bd3b')


