from lib import config, helpers
import re

class Station_name(object):

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
        self.station_name = 'Station_name'
        self.endpoint = 'www.station_endpoint.com/api/index.php'
        self.path = ''
        self.parameters = {}
        self.headers = {}
        self.user_agent = {}
        self.response_format = ''

### Station tunes

    def domain_to_ipv4(self, data):
        response = self.api.session_helper(station_name=self.station_name, endpoint=self.endpoint, method_type='get',
                                           data_to_send=None, url_path=self.path, parameters=self.parameters,
                                           headers=self.headers, user_agent=self.user_agent,
                                           response_format=self.response_format)

        if self.response_format == 'bs' and response:
            table = response.findAll('class', {'table': 'ip'})
            for cell in table:
                match = re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', cell.text)
                if match:
                    self.ip_list.append(match.group())
                return self.ip_list

        elif self.response_format == 'json' and response:
            for key in response['ip']:
                self.ip_list.append(key)
            return self.ip_list