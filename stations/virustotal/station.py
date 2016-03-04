#################################################################
#   Virustotal station for QRadio                               #
#                       ~ Tune In                               #
#   Tuned to:                                                   #
#            https://www.virustotal.com/ API v2                 #
#                                                               #
#   API Documentation:                                          #
#       https://www.virustotal.com/en/documentation/public-api/ #
#                                                               #
#       Author: 10TOHH                                          #
#                                                               #
#                                                               #
#   Tunes:                                                      #
#   domain_to_ipv4  -   Resolves IP to <Domain>                 #
#                                                               #
#   ipv4_to_domain  -   Resolves Domain to <IP>                 #
#   ipv4_to_hash    -   Return Hash associated with <IP>        #
#                                                               #
#   hash_to_score   -   Return Score to given <Hash>            #
#   hash_to_url     -   Return URL to report for given <Hash>   #
#################################################################

from lib import config, helpers


class Virustotal(object):

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
        self.station_name = 'Virustotal'
        self.endpoint = 'https://www.virustotal.com/vtapi/v2'
        self.path = ''
        self.parameters = {}
        self.headers = {}
        self.user_agent = {}
        self.response_format = 'json'

        if config.virustotal_api_key:
            self.parameters = {'apikey': config.virustotal_api_key}
        else:
            msg = 'API key is missing'
            helpers.IO().error_log(msg, self.station_name)
            return

#################
# helpers

    def ip_response(self, ip_address):
        self.parameters.update({'ip': ip_address})
        self.path = '/ip-address/report'
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.response_format)
        if response:
            return response

    def domain_response(self, ip_address):
        self.parameters.update({'domain': ip_address})
        self.path = '/domain/report'
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.response_format)
        if response:
            return response


    def hash_response(self, ip_address):
        self.parameters.update({'resource': ip_address})
        self.path = '/file/report'
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.response_format)
        if response:
            return response

### Station tunes

    def domain_to_ipv4(self, domain_name):
        response = self.domain_response(domain_name)
        if response:
            if 'resolutions' in response:
                for key in response['resolutions']:
                    self.ip_list.append(key['ip_address'])
        return self.ip_list


    def ipv4_to_domain(self, ip_address):
        response = self.ip_response(ip_address)
        if response:
            if 'resolutions' in response:
                for key in response['resolutions']:
                    self.domain_list.append(key['hostname'])
        return self.domain_list

    def ipv4_to_hash(self, ip_address):
        response = self.ip_response(ip_address)
        if response:
            if 'detected_communicating_samples' in response:
                for urls in response['detected_communicating_samples']: ## DETECTED
                    if 'sha256' in urls:
                        self.hash_list.append(urls['sha256'])
            if 'undetected_communicating_samples' in response:
                for urls in response['undetected_communicating_samples']: ## UNDETECTED
                    if 'sha256' in urls:
                        self.hash_list.append(urls['sha256'])
        return self.hash_list

    def hash_to_score(self, hash_value):
        response = self.hash_response(hash_value)
        if response:
            if 'positives' in response:
                self.score_list.append(str(response['positives'])+'/'+str(response['total']))
        return self.score_list

    def hash_to_url(self, hash_value):
        response = self.hash_response(hash_value)
        if response:
            if 'permalink' in response:
                self.url_list.append(response['permalink'])
        return self.url_list

if __name__ == '__main__':

    test_domain = 'pastebin.com'
    test_ip = '104.20.64.56'
    test_hash = 'f99d5c59d082636fb97d71d7340e3ecd8d041bacde46b4d30841f14953945e2f'

    #print 'domain_to_ipv4', Virustotal().domain_to_ipv4(test_domain)
    #print 'ipv4_to_domain', Virustotal().ipv4_to_domain(test_ip)
    #print 'ipv4_to_hash', Virustotal().ipv4_to_hash(test_ip)
    #print 'hash_to_score', Virustotal().hash_to_score(test_hash)
    #print 'hash_to_url', Virustotal().hash_to_url(test_hash)