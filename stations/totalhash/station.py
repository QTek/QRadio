#################################################################
#   Totalhash station for QRadio                                #
#                       ~ Tune In                               #
#   Tuned to:                                                   #
#            https://totalhash.cymru.com/                       #
#                                                               #
#   API Documentation:                                          #
#       https://totalhash.cymru.com/wp-content/uploads/2015/06/ #
#                               Totalhash-API-Documentation.pdf #
#                                                               #
#       Author: 10TOHH                                          #
#                                                               #
#                                                               #
#   Tunes:                                                      #
#   domain_to_hash  -   Return Hash to <Domain>                 #
#   domain_to_url   -   Return URL to report for given <Domain> #
#                                                               #
#   ipv4_to_hash    -   Return Hash associated with <IP>        #
#   ipv4_to_url     -   Return URL to report for given <IP>     #
#                                                               #
#   hash_to_ipv4    -   Return IP associated with <Hash>        #
#   hash_to_imphash -   Return Imphash associated with <Hash>   #
#   hash_to_url     -   Return URL to report for given <Hash>   #
#   hash_to_domain  -   Return Domain associated with  <Hash>   #
#                                                               #
#   imphash_to_hash -   Return Hash associated with <Imphash>   #
#   mutex_to_hash   -   Return Hash associated with <Mutex>     #
#################################################################

import hmac
import hashlib
import xmltodict
import re

from lib import config, helpers

class Totalhash(object):

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
        self.station_name = 'Totalhash'
        self.endpoint = 'https://api.totalhash.com/search/'
        self.path = ''
        self.parameters = {}
        self.headers = {}
        self.user_agent = {}
        self.response_format = ''

    def signature(self, searching_query):
        if config.totalhash_api_key:
            api_key = config.totalhash_api_key
        else:
            error_msg = 'API Key NOT provided'
            self.error_log.error_log(error_msg, self.station_name)
            return

        sign = hmac.new(api_key, searching_query, hashlib.sha256).hexdigest()
        return sign

    def search(self, searching_query):
        if config.totalhash_uid:
            uid = config.totalhash_uid
            self.path = searching_query+'&id='+uid+'&sign='+self.signature(searching_query)
        else:
            error_msg = 'User Name NOT provided'
            self.error_log.error_log(error_msg, self.station_name)
            return

        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.response_format)
        if response:
            return response

    def parser(self, response):
        if response:
            match = re.findall(r'API limit', response.text) #
            if match:
                self.error_log.error_log('Sorry API Limit reached (300 q/month). Get new: https://totalhash.cymru.com/contact-us/',
                                         self.station_name)
                return []

            xml_dict = xmltodict.parse(response.text)
            if 'response' in xml_dict:
                if 'result' in xml_dict['response']:
                    if 'doc' in xml_dict['response']['result']:
                        try:
                            response = xml_dict['response']['result'] # Unpacking xmltodict
                            for records in response['doc']:
                                self.hash_list.append(records['str']['#text']) # Append hash_values
                        except: pass
        return self.hash_list # Return empty


    def combinator(self, searching_query):
        hash_list = []
        hash_list.extend(self.parser(self.search(searching_query)))
        return hash_list

### Station tunes

    def ipv4_to_hash(self, ip_address):
        searching_query = 'ip:' + ip_address
        self.hash_list.extend(self.parser(self.search(searching_query)))
        return self.hash_list

    def ipv4_to_url(self, ip_address):
        hash = self.ipv4_to_hash(ip_address)
        if len(hash) > 0:
            for i in hash:
                self.url_list.append('https://totalhash.cymru.com/analysis/?'+i)
        return self.url_list
###################
    def domain_to_hash(self, domain_name):
        searching_query = 'dnsrr:' + domain_name
        self.hash_list.extend(self.parser(self.search(searching_query)))
        return self.hash_list

    def domain_to_url(self, domain_name):
        hash = self.domain_to_hash(domain_name)
        if len(hash) > 0:
            for i in hash:
                self.url_list.append('https://totalhash.cymru.com/analysis/?'+i)
        return self.url_list

###################

    def imphash_to_hash(self, imphash):
        searching_query = 'hash:' + imphash
        self.hash_list.extend(self.parser(self.search(searching_query)))
        return self.hash_list

    def mutex_to_hash(self, mutex):
        searching_query = 'mutex:' + mutex
        self.hash_list.extend(self.parser(self.search(searching_query)))
        return self.hash_list

###################

    def hash_to_ipv4(self, hash_value):
        request_url = 'https://totalhash.cymru.com/analysis/?' + hash_value
        response = self.api.session_helper(station_name=self.station_name, method_type='get', endpoint=self.endpoint,
                                               response_format='bs', go_to_url=request_url)

        if response:
            table = response.findAll('a')
            for cell in table:
                match = re.search(r'ip:\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', str(cell))
                if match:
                    ip_address = match.group().split(':')[1]
                    self.ip_list.append(ip_address)
            return list(set(self.ip_list))


    def hash_to_url(self, hash_value):
        request_url = 'https://totalhash.cymru.com/analysis/?' + hash_value
        response = self.api.session_helper(station_name=self.station_name, method_type='get', endpoint=self.endpoint,
                                               response_format='bs', go_to_url=request_url)

        if response:
            table = response.findAll('div', {'class': 'entry-content'})
            if table:
                match = re.search(r'Sorry something went wrong', table[0].text)
                if not match:
                    self.url_list.append(request_url)
        return self.url_list

    def hash_to_domain(self, hash_value):
        request_url = 'https://totalhash.cymru.com/analysis/?' + hash_value
        response = self.api.session_helper(station_name=self.station_name, method_type='get', endpoint=self.endpoint,
                                               response_format='bs', go_to_url=request_url)

        if response:
            table = response.findAll('a')
            for cell in table:
                match = re.search(r'dnsrr:.*\"\>', str(cell))
                if match:
                    split_1 = match.group().split(':')[1]
                    split_2 = split_1.split('"')[0]
                    split_3 = split_2.split('.')[-1]
                    if not split_3.isdigit():
                        self.domain_list.append(split_2)
        return list(set(self.domain_list))

    def hash_to_imphash(self, hash_value):
        request_url = 'https://totalhash.cymru.com/analysis/?' + hash_value
        response = self.api.session_helper(station_name=self.station_name, method_type='get', endpoint=self.endpoint,
                                               response_format='bs', go_to_url=request_url)

        if response:
            table = response.findAll('span', {'class': 'fixed'})
            for cell in table:
                match = re.search(r'hash:.*\"\>', str(cell))
                if match:
                    split_1 = match.group().split(':')[1]
                    split_2 = split_1.split('"')[0]
                    if len(split_2) == 32:
                        self.imphash_list.append(split_2)
        return self.imphash_list


if __name__ == '__main__':
    test_ip = '64.182.208.185'
    test_domain = 'yaplakal.com'
    test_imphash = '111e1a29238f230f1857b5836aa533d6'
    test_mutex = 'WininetConnectionMutex'
    test_hash = 'f4c029619efd51dfc51f39e5cad4dfb39147c851'
    #print 'ipv4_to_hash', Totalhash().ipv4_to_hash(test_ip)
    #print 'ipv4_to_url', Totalhash().ipv4_to_url(test_ip)

    #print 'domain_to_hash', Totalhash().domain_to_hash(test_domain)
    #print 'domain_to_url', Totalhash().domain_to_url(test_domain)

    #print 'imphash_to_hash', Totalhash().imphash_to_hash(test_imphash)
    #print 'mutex_to_hash', Totalhash().mutex_to_hash(test_mutex)

    #print 'hash_to_ipv4', Totalhash().hash_to_ipv4(test_hash)
    #print 'hash_to_imphash', Totalhash().hash_to_imphash(test_hash)
    #print 'hash_to_domain', Totalhash().hash_to_domain(test_hash)
    #print 'hash_to_url', Totalhash().hash_to_url(test_hash)
