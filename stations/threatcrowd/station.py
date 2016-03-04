#################################################################
#   Threatcrowd station for QRadio                              #
#                       ~ Tune In                               #
#   Tuned to:                                                   #
#            http://www.threatcrowd.org/ API v2                 #
#                                                               #
#   API Documentation:                                          #
#       https://github.com/threatcrowd/ApiV2                    #
#                                                               #
#       Author: 10TOHH                                          #
#                                                               #
#   Tunes:                                                      #
#   domain_to_ipv4  -   Resolves IP to <Domain>                 #
#   ipv4_to_domain  -   Resolves Domain to <IP>                 #
#   ipv4_to_hash    -   Return Hash associated with <IP>        #
#################################################################

from lib import helpers

class Threatcrowd(object):

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

        # static station settings
        self.station_name = 'Threatcrowd'
        self.endpoint = 'http://www.threatcrowd.org/searchApi/v2'
        self.path = ''
        self.parameters = {}
        self.headers = {'content-type': 'application/json',
                        'accept': 'application/json'}
        self.user_agent = {}
        self.response_format = 'json'

### Station tunes

    def domain_to_ipv4(self, domain_name):
        self.path = '/domain/report/'
        self.parameters = {'domain': domain_name }
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.response_format)
        if response:
            if 'resolutions' in response:
                for key in response['resolutions']:
                    if key['ip_address'] != '-' and key['ip_address'] !='0.0.0.0':
                        self.ip_list.append(key['ip_address'])
        return self.ip_list

    def ipv4_to_domain(self, ip_address):
        self.path = '/ip/report/'
        self.parameters = {'ip': ip_address }
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.response_format)
        if response:
            if 'resolutions' in response:
                for key in response['resolutions']:
                    if key['domain'] != '-':
                        self.domain_list.append(key['domain'])
        return self.domain_list

    def ipv4_to_hash(self, ip_address):
        self.path = '/ip/report/'
        self.parameters = {'ip': ip_address }
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.response_format)
        if response:
            if 'hashes' in response:
                for key in response['hashes']:
                    self.hash_list.append(key)

        return self.hash_list





if __name__ == '__main__':
    test_domain = 'trivika.com'
    test_ip = '198.57.201.75'
    ##print Threatcrowd().domain_to_ipv4(test_domain)
    ##print Threatcrowd().ipv4_to_domain(test_ip)
    ##print Threatcrowd().ipv4_to_hash(test_ip)