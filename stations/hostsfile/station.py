#################################################################
#   Hostsfile station for QRadio                                #
#                       ~ Tune In                               #
#   Tuned to:                                                   #
#            http://hosts-file.net/default.asp                  #
#                                                               #
#       Author: 10TOHH                                          #
#                                                               #
#   Tunes:                                                      #
#   domain_to_ipv4  -   Resolves IP to <Domain>                 #
#   ipv4_to_domain  -   Resolves Domain to <IP>                 #
#################################################################

from lib import helpers

class Hostsfile(object):

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
        self.station_name = 'HostsFile'
        self.endpoint = 'http://hosts-file.net/'
        self.url_path = ''
        self.parameters = {}
        self.headers = {}
        self.user_agent = {}
        self.response_format = 'bs'

### Station tunes

    def domain_to_ipv4(self, data):
        self.parameters = {'s': data,
                           'view': 'history'}
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, parameters=self.parameters, headers=self.headers,
                                           response_format=self.response_format)
        if response:
            table = response.findAll('td', {'width': '15%'})
            if len(table) > 1:
                for cell in table[1:]:
                    ip = ''.join(c for c in cell.text if c not in '\t\n\r')
                    self.ip_list.append(ip)
        return self.ip_list

    def ipv4_to_domain(self, data):
        self.parameters = {'s': data, 'view': 'history'} # s = search
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, parameters=self.parameters, headers=self.headers,
                                           response_format=self.response_format)
        if response:
            table = response.findAll('a', {'class': 'main_normal_noborder'})
            for cell in table:
                 if cell.text:
                     self.domain_list.append(cell.text)
            return self.domain_list[9:]

################################################################################################

### MAIN ####
if __name__ == '__main__':

    h = Hostsfile()
    ##print h.domain_to_ipv4('google.com')
    ##print h.ipv4_to_domain('74.125.53.100')