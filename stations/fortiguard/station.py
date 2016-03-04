#################################################################
#   Fortiguard station for QRadio                               #
#                           ~ Tune In                           #
#   Tuned to:                                                   #
#            http://www.fortiguard.com/iprep/index.php          #
#                                                               #
#       Author: 10TOHH                                          #
#                                                               #
#   Tunes:                                                      #
#   domain_to_ipv4  -   Resolves IP to <Domain>                 #
#################################################################

from lib import helpers

class Fortiguard(object):

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
        self.station_name = 'Foriguard'
        self.endpoint = 'http://www.fortiguard.com/iprep/index.php'
        self.url_path = ''
        self.parameters = {}
        self.headers = {}
        self.user_agent = {}
        self.response_format = 'bs'

### Station tunes

    def domain_to_ipv4(self, domain_name):
        self.parameters = {'data': domain_name}
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.url_path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.response_format)
        if response:
            try:
                table = response.findAll('table', {'class': 'large'})
                if len(table) != 0:
                    self.ip_list.extend(table[1].text.split()) # first element of dict, .text = values, .split = make a list
                return self.ip_list
            except:
                return self.ip_list
        else:
            return self.ip_list

##### MAIN #####
if __name__ == '__main__':
    f = Fortiguard()
    ##print f.domain_to_ipv4('alfred.1gb.ru')