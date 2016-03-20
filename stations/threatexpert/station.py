#################################################################
#   Threatexpert station for QRadio                             #
#                       ~ Tune In                               #
#   Tuned to:                                                   #
#            http://www.threatexpert.com/reports.aspx?find=     #
#                                                               #
#       Author: 10TOHH                                          #
#                                                               #
#                                                               #
#   Tunes:                                                      #
#   domain_to_hash  -   Return Hash to <Domain>                 #
#                                                               #
#   ipv4_to_hash    -   Return Hash associated with <IP>        #
#                                                               #
#   hash_to_ipv4    -   Return IP associated with <Hash>        #
#   hash_to_domain  -   Return Domain associated with <Hash>    #
#   hash_to_url     -   Return URL to report for given <Hash>   #
#   hash_to_score   -   Return Score to given <Hash>            #
#                                                               #
#   imphash_to_hash -   Return Hash associated with <Imphash>   #
#           -   Not in QRadio main                              #
#   mutex_to_hash   -   Return Hash associated with <Mutex>     #
#           -   Not in QRadio main                              #
#################################################################

from lib import helpers
import re

class Threatexpert(object):

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
        self.station_name = 'Threatexpert'
        self.endpoint = 'http://www.threatexpert.com/reports.aspx'
        self.path = ''
        self.parameters = {}
        self.headers = {}
        self.user_agent = {}
        self.response_format = 'bs'

############################################

    def splitter(self, url_list):
        output = []
        if url_list:
            for key in url_list:
                output.append(key.split('=')[1])
        return output

    def url_parser(self, response):
        url_list = []
        # search for href of reports with no base
        lines = response.findAll('a', {'target': '_blank'}) # Search for results
        for link in lines:
            url_list.append('http://www.threatexpert.com/' + link.get('href'))
        # return URL to analyse
        return url_list


    def single_search(self, search_value, params=None):
        if search_value:
            parameters = {'find': search_value}
            if params:
                parameters.update(params)

            response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                               data_to_send=None, url_path=self.path, parameters=parameters,
                                               headers=self.headers, user_agent=self.user_agent,
                                               response_format=self.response_format)
            if response:
                parsed_url = self.url_parser(response)
                return parsed_url
        else:
            return []

    def main_search(self, search_value):
        url_list = []
        if search_value:
            self.parameters = {'find': search_value}
            response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                               data_to_send=None, url_path=self.path, parameters=self.parameters,
                                               headers=self.headers, user_agent=self.user_agent,
                                               response_format=self.response_format)

            if response:
                if response.findAll('table', {'align': 'center'}): # More than 1 page
                    pages = response.findAll('td', {'class': 'page_btn'}) # find all other pages
                    if pages:
                        for number in pages[:-1]: # Exclude 'Next' from page numbers
                            params = {'page': number.text} # set page number as parameter
                            sub_response = self.single_search(search_value, params=params)
                            if sub_response:
                                url_list.extend(sub_response)
                            return url_list
                else:
                    return self.single_search(search_value)
        else:
            return url_list

### Station tunes

    def hash_to_url(self, hash_value):
        self.url_list.extend(self.main_search(hash_value))
        return self.url_list

    def ipv4_to_hash(self, ip_address):
        url_list = self.main_search(ip_address)
        hash_list = self.splitter(url_list)
        hash_list.extend(hash_list)
        return hash_list

    def domain_to_hash(self, domain_name):
        url_list = self.main_search(domain_name)
        splited_list = self.splitter(url_list)
        return splited_list

    def imphash_to_hash(self, imphash):
        url_list = self.main_search(imphash)
        splited_list = self.splitter(url_list)
        return splited_list

    def mutex_to_hash(self, imphash):
        url_list = self.main_search(imphash)
        splited_list = self.splitter(url_list)
        return splited_list


    def hash_to_ipv4(self, hash_value):
        bs_result_list = []
        url_list = self.main_search(hash_value)
        if url_list:
            for request_url in url_list:
                response = self.api.session_helper(station_name=self.station_name, method_type='get', endpoint=self.endpoint,
                                                   response_format=self.response_format, go_to_url=request_url)
                if response:
                    bs_result_list.append(response)
        if bs_result_list:
            for li in bs_result_list:
                line = li.findAll('li') # Search for list items
                for i in line:
                    match = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', i.text) # IP address
                    if match:
                        self.ip_list.extend(match)
            for elements in bs_result_list:
                tables = elements.findAll('table', {'class': 'tbl'}) # Search all tables with data
                match = re.findall(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', str(tables)) # IP address
                if match:
                    self.ip_list.extend(match)

        return list(set(self.ip_list))

    def hash_to_domain(self, hash_value):
        bs_result_list = []
        table_list = []
        url_list = self.main_search(hash_value)
        if url_list:
            for request_url in url_list:
                response = self.api.session_helper(station_name=self.station_name, method_type='get', endpoint=self.endpoint,
                                                   response_format=self.response_format, go_to_url=request_url)
                if response:
                    bs_result_list.append(response)


        for elements in bs_result_list:
            tables = elements.findAll('table', {'class': 'tbl'}) # Search all tables with data
            table_list.extend(tables) # get tables in the list

        for elem in table_list:
            host = elem.findAll('td', {'class': 'cell_1'}) # Search all cells
            for i in host:
                match = re.search(r'(([a-z0-9]+\.)*[a-z0-9]+\.[a-z]+[0-9]+)', i.text) # Search for domains
                if match:
                    dom = match.group().strip('1234567890.') # Remove port number from domain name string
                    self.domain_list.append(dom) # Create list of domains with ports in the end
        return list(set(self.domain_list))

if __name__ == '__main__':
    test_ip = '88.198.69.43'
    test_domain = 'google.com'
    test_hash = '171c4c62ab2001c2f2394c3ec021dfa3'
    test_imphash = ''
    test_mutex = ''
    #print 'hash_to_url', Threatexpert().hash_to_url(test_hash) - Not in qradio
    ##print 'ipv4_to_hash', Threatexpert().ipv4_to_hash(test_ip)
    ##print 'domain_to_hash', Threatexpert().domain_to_hash(test_domain)
    #print 'imphash_to_hash', Threatexpert().imphash_to_hash(test_imphash)  - Not in qradio
    #print 'mutex_to_hash', Threatexpert().mutex_to_hash(test_mutex)  - Not in qradio
    ##print 'hash_to_ipv4', Threatexpert().hash_to_ipv4(test_hash)
    ##print 'hash_to_domain', Threatexpert().hash_to_domain(test_hash)














