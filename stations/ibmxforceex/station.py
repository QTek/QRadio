#################################################################
#   Ibmxforce station for QRadio                                #
#                       ~ Tune In                               #
#   Tuned to:                                                   #
#            https://exchange.xforce.ibmcloud.com               #
#                                                               #
#   API Documentation:                                          #
#       https://xforce-api.mybluemix.net/doc/                   #
#                                                               #
#       Author: 10TOHH                                          #
#                                                               #
#   Tunes:                                                      #
#   domain_to_ipv4  -   Resolves IP to <Domain>                 #
#   domain_to_hash  -   Return Hash to <Domain>                 #
#   domain_to_score -   Return Score to <Domain>                #
#                                                               #
#   ipv4_to_domain  -   Resolves Domain to <IP>                 #
#   ipv4_to_score   -   Return Score to <IP>                    #
#   ipv4_to_hash    -   Return Hash associated with <IP>        #
#                                                               #
#   hash_to_ipv4    -   Return IP associated with <Hash>        #
#   hash_to_score   -   Return Score to given <Hash>            #
#################################################################

from lib import config, helpers


class Ibmxforce(object):

    def __init__(self):
        # lists of values that can be returned
        self.ipv4_list = []
        self.ipv6_list = []
        self.domain_list = []
        self.hash_list = []
        self.url_list = []
        self.score_list = []
        self.imphash_list = []

        # get helping functions
        self.api = helpers.Common()

        # static station settings
        self.station_name = 'IBM X-Force'
        self.endpoint = 'https://xforce-api.mybluemix.net:443'
        self.url_path = ''
        self.parameters = {}
        self.headers = {'Accept': 'application/json'}
        self.user_agent = {}
        self.response_format = 'json'

        if config.ibmxforce_token:
            self.headers.update({'Authorization': 'Bearer ' + config.ibmxforce_token})
        else:
            self.token = self.get_token()

    # return anonymous authenication token
    def get_token(self):
        self.url_path = '/auth/anonymousToken'
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.url_path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.response_format)
        if response:
            return self.headers.update({'Authorization': 'Bearer ' + response['token']})

    # Resolve IP or Domain names
    def resolver(self, ip_address):
        domain_list = []
        ipv4_list = []

        self.url_path = '/resolve/' + ip_address
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.url_path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.response_format)
        # Domain
        if response:
            if 'Passive' in response:
                if 'records' in response['Passive']:
                    for key in response['Passive']['records']:
                        domain_list.append(key['value'])
            # IP
            elif 'A' in response:
                ipv4_list.extend(response['A'])

        return domain_list or ipv4_list

    def malware_hash_parser(self, json_input):
        ipv4_list = []

        ## Find IP to hash
        if json_input:
            if 'malware' in json_input:
                if 'origins' in json_input['malware']:
                    if 'subjects' in json_input['malware']['origins']:
                        if 'rows' in json_input['malware']['origins']['subjects']:
                            for key in json_input['malware']['origins']['subjects']['rows']:
                                ipv4_list.extend(key['ips'])
                    if 'CnCServers' in json_input['malware']['origins']:
                        if 'rows' in json_input['malware']['origins']['CnCServers']:
                            for key in json_input['malware']['origins']['CnCServers']['rows']:
                                ipv4_list.append(key['ip'])
                    if 'downloadServers' in json_input['malware']['origins']:
                        if 'rows' in json_input['malware']['origins']['downloadServers']:
                            for key in json_input['malware']['origins']['downloadServers']['rows']:
                                ipv4_list.append(key['ip'])
                    if 'emails' in json_input['malware']['origins']:
                        if 'rows' in json_input['malware']['origins']['emails']:
                            for key in json_input['malware']['origins']['emails']['rows']:
                                ipv4_list.append(key['ip'])
        return ipv4_list


    def score_json_parser(self,json_input):
        score_list = []
        if json_input:
            if 'malware' in json_input:
                if 'origins' in json_input['malware']:
                    if 'external' in json_input['malware']['origins']:
                        if 'detectionCoverage' in json_input['malware']['origins']['external']:
                            hash_score = str(round(json_input['malware']['origins']['external']['detectionCoverage'], -1))[0] +'/10'
                            score_list.append(hash_score)
        elif 'result' in json_input:
            if 'score' in json_input['result']:
                score = str(json_input['result']['score'])+'/10'
                score_list.append(score)
        return score_list

### Station tunes

    def domain_to_ipv4(self, domain_name):
        ipv4_list = list(self.resolver(domain_name))
        return ipv4_list

    def domain_to_hash(self, domain_name):
        self.url_path = '/url/malware/' + domain_name
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.url_path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.response_format)
        # Find Hash
        if response:
            if response['count'] != 0:
                for key in response['malware']:
                    self.hash_list.append(key['md5'])
        return self.hash_list


    def domain_to_score(self, domain_name):
        score_list = []
        self.url_path = '/url/' + domain_name
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.url_path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.response_format)
        if response:
            score_list.extend(self.score_json_parser(response))
        return score_list



#################################
    def ipv4_to_domain(self, ip_address):
        self.domain_list.extend(self.resolver(ip_address))
        return self.domain_list


    def ipv4_to_hash(self, ip_address):
        self.url_path = '/ipr/malware/' + ip_address
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.url_path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.response_format)
        if response:
            self.hash_list.extend(self.malware_hash_parser(response))
        return self.hash_list

    def ipv4_to_score(self, ip_address):
        score_list = []
        self.url_path = '/ipr/' + ip_address
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.url_path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.response_format)
        if response:
            if 'score' in response:
                score_list.append(str(response['score'])+'/10')
        return score_list


#################################


    def hash_to_ipv4(self, hash_value):
        ipv4_list = []
        self.url_path = '/malware/' + hash_value
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.url_path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.response_format)
        if response:
            ipv4_list.extend(self.malware_hash_parser(response))
        return ipv4_list

    def hash_to_score(self, hash_value):
        score_list = []
        self.url_path = '/malware/' + hash_value
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.url_path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.response_format)
        if response:
            score_list.extend(self.score_json_parser(response))
        return score_list


##### MAIN #####
if __name__ == '__main__':
    ibm = Ibmxforce()
    test_ip = '198.57.201.75'
    test_domain = 'trivika.com'
    test_hash = '474B9CCF5AB9D72CA8A333889BBB34F0'

    ##print 'dom-to-ip', ibm.domain_to_ipv4(test_domain)
    ##print 'dom-to-hash', ibm.domain_to_hash(test_domain)
    ##print 'dom-to-score', ibm.domain_to_score(test_domain)

    ##print 'ip-to-dom', ibm.ipv4_to_domain(test_ip)
    ##print 'ip-to-has', ibm.ipv4_to_hash(test_ip)
    ##print 'ip-to-score', ibm.ipv4_to_score(test_ip)

    print 'hash-to-ip', ibm.hash_to_ipv4(test_hash)
    ##print 'hash-to-score', ibm.hash_to_score(test_hash)
