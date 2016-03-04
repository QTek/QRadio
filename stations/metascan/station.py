#################################################################
#   Metascan station for QRadio                                 #
#                       ~ Tune In                               #
#   Tuned to:                                                   #
#            https://www.metascan-online.com                    #
#                                                               #
#   API Documentation:                                          #
#       https://www.metascan-online.com/public-api#!/           #
#                                                               #
#       Author: 10TOHH                                          #
#                                                               #
#   Tunes:                                                      #
#   ipv4_to_score   -   Return Score to <IP>                    #
#                                                               #
#   hash_to_imphash -   Return Imphash associated with <Hash>   #
#   hash_to_score   -   Return Score to given <Hash>            #
#################################################################

from lib import config, helpers

class Metascan(object):

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
        self.station_name = 'Metascan'
        self.endpoint = 'https://metascan-online.com'   # different subdomains for search
                                                        # hashlookup and ipscan
        self.url_path = ''
        self.parameters = {}
        self.headers = {'content-type': 'application/json',
                'accept': 'application/json',
                'file_metadata': 1}
        self.user_agent = {}
        self.response_format = 'json'

        if config.metascan_api_key:
            self.headers.update({'apikey': config.metascan_api_key})
        else:
            msg = 'API Key NOT provided'
            helpers.IO().error_log(msg,self.station_name)
            return

#######################

    def hash_enrich(self, hash_value):
        self.endpoint = 'https://hashlookup.metascan-online.com'
        self.url_path = '/v2/hash/' + hash_value
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.url_path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.response_format)
        return response

    def ip_enrich(self, ip_address):
        self.endpoint = 'https://ipscan.metascan-online.com'
        self.url_path = '/v1/scan/' + ip_address
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.url_path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.response_format)
        return response


#########################

### Station tunes

    def ipv4_to_score(self, ip_address):
        enriched = Metascan().ip_enrich(ip_address)
        if enriched:
            self.score_list.append(str(enriched['detected_by'])+'/12') # 12 - number of Metascan sources
            return self.score_list

    def hash_to_score(self, hash_value):
        infected = 0
        enriched = Metascan().hash_enrich(hash_value)
        if len(enriched) > 1:
            if 'scan_results' in enriched:
                if 'total_avs' in enriched['scan_results']:
                    total_avs = enriched['scan_results']['total_avs']
                    if 'scan_details' in enriched['scan_results']:
                        for key in enriched['scan_results']['scan_details'].values():
                            # https://www.metascan-online.com/public-api#!/definitions
                            # 1 = Infected/Known, 2 = Suspicious, 3 = Failed To Scan
                            # 6 = Quarantined, 8 = Skipped Dirty, 9 = Exceeded Archive Depth, 12 = Encrypted
                            if key['scan_result_i'] == 1 or \
                            key['scan_result_i'] == 2 or \
                            key['scan_result_i'] == 3 or \
                            key['scan_result_i'] == 6 or \
                            key['scan_result_i'] == 8 or \
                            key['scan_result_i'] == 9 or \
                            key['scan_result_i'] == 12:
                                infected += 1
                        self.score_list.append(str(infected)+'/'+str(total_avs))  # Infected\Number_of_AV
        return self.score_list


    def hash_to_imphash(self, hash_value):
        response = Metascan().hash_enrich(hash_value)
        if len(response) > 1:
            if 'file_info' in response:
                if 'pe_info' in response['file_info']:
                    if 'imphash' in response['file_info']['pe_info']:
                        self.imphash_list.append(response['file_info']['pe_info']['imphash'])
        return self.imphash_list

#if __name__ == '__main__':
    ##print Metascan().ipv4_to_score('8.8.8.8')
    ##print Metascan().hash_to_score('7a29752205392b2a952d3f8bf2a886b3')
    ##print Metascan().hash_to_imphash('7a29752205392b2a952d3f8bf2a886b3')