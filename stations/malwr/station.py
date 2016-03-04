#################################################################
#   Malwr station for QRadio                                    #
#                       ~ Tune In                               #
#   Tuned to:                                                   #
#            https://malwr.com/                                 #
#                                                               #
#   Cloned from:                                                #
#       https://github.com/PaulSec/API-malwr.com                #
#                                                               #
#       Author: 10TOHH                                          #
#                                                               #
#   Note: Does NOT use /lib/helpers.py.Common().session_helper  #
#                                                               #
#   Tunes:                                                      #
#   domain_to_hash  -   Return Hash to <Domain>                 #
#   domain_to_score -   Return Score to <Domain>                #
#   domain_to_url   -   Return URL to report for given <Domain> #
#                                                               #
#   ipv4_to_score   -   Return Score to <IP>                    #
#   ipv4_to_hash    -   Return Hash associated with <IP>        #
#   ipv4_to_url     -   Return URL to report for given <IP>     #
#                                                               #
#   hash_to_ipv4    -   Return IP associated with <Hash>        #
#   hash_to_imphash -   Return Imphash associated with <Hash>   #
#   hash_to_url     -   Return URL to report for given <Hash>   #
#   hash_to_score   -   Return Score to given <Hash>            #
#################################################################

from lib import config, helpers

import requests
from bs4 import BeautifulSoup


class Malwr(object):
    logged = False

    url = "https://malwr.com"
    headers = {
        'User-Agent': "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:41.0) " +
                      "Gecko/20100101 Firefox/41.0"
    }

    def __init__(self):
        # lists of values that can be returned
        self.ip_list = []
        self.domain_list = []
        self.hash_list = []
        self.url_list = []
        self.score_list = []
        self.imphash_list = []
        self.drop_hash = []

        self.error_log = helpers.IO()
        self.station_name = 'Malwr'

        self.session = requests.session()

        # Authenticate and store the session
        if config.malwr_login and config.malwr_passwd:
            soup = self.request_to_soup(self.url + '/account/login')
            if soup:
                csrf_input = soup.find(attrs=dict(name='csrfmiddlewaretoken'))
                if csrf_input:
                    if 'value' in csrf_input:
                        csrf_token = csrf_input['value']
                        payload = {
                            'csrfmiddlewaretoken': csrf_token,
                            'username': u'{0}'.format(config.malwr_login),
                            'password': u'{0}'.format(config.malwr_passwd)
                        }
                else:
                        return
                try:
                    login_request = self.session.post("https://malwr.com/account/login/",
                                                      data=payload, headers=self.headers)

                    if login_request.status_code == 200:
                        self.logged = True
                except:
                    return
        else:
            error_msg = 'Login and Password NOT provided'
            self.error_log.error_log(error_msg, self.station_name)
            return


    def request_to_soup(self, url=None):

        if url:
            try:
                req = self.session.get(url, headers=self.headers)
                soup = BeautifulSoup(req.content, "html.parser")
                return soup
            except:
                return

    def search(self, search_word):
        # Do nothing if not logged in
        if not self.logged:
            return []

        search_url = self.url + '/analysis/search/'
        c = self.request_to_soup(search_url)

        csrf_input = c.find(attrs=dict(name='csrfmiddlewaretoken'))
        csrf_token = csrf_input['value']
        payload = {
            'csrfmiddlewaretoken': csrf_token,
            'search': u'{}'.format(search_word)
        }
        sc = self.session.post(search_url, data=payload, headers=self.headers)
        ssc = BeautifulSoup(sc.content, "html.parser")

        res = []
        submissions = ssc.findAll('div', {'class': 'box-content'})
        if len(submissions) > 0:
            submissions = submissions[0]
            sub = submissions.findAll('tbody')[0]
            for submission in sub.findAll('tr'):
                infos = submission.findAll('td')
                infos_to_add = {
                    'submission_time': infos[0].string, # Date
                    'hash': infos[1].find('a').string, # MD5 Hash
                    'submission_url': self.url+infos[1].find('a')['href'], # URI
                    'score': infos[4].string, #Score
                }
                res.append(infos_to_add)
        return res
####################################################################################
    def ip_enrich(self, ip_address):
        res = Malwr().search('ip:'+ip_address)
        return res

    def domain_enrich(self, domain_name):
        res = Malwr().search('domain:'+domain_name)
        return res

################################################################################################

    def ipv4_to_hash(self, ip_address):
        res = Malwr().ip_enrich(ip_address)
        for element in res:
            self.hash_list.append(element['hash'])
        return self.hash_list


    def ipv4_to_url(self, ip_address):
        res = Malwr().ip_enrich(ip_address)
        for element in res:
            self.url_list.append(element['submission_url'])
        return self.url_list

    def ipv4_to_score(self, ip_address):
        res = Malwr().ip_enrich(ip_address)
        for element in res:
            if element['score'] != 'n/a':
                self.score_list.append(element['score'])
        return self.score_list

################################################################################################

    def domain_to_hash(self, domain_name):
        res = Malwr().domain_enrich(domain_name)
        if res:
            for element in res:
                self.hash_list.append(element['hash'])
        return self.hash_list

    def domain_to_url(self, domain_name):
        res = Malwr().domain_enrich(domain_name)
        if res:
            for element in res:
                self.url_list.append(element['submission_url'])
        return self.url_list

    def domain_to_score(self, domain_name):
        res = Malwr().domain_enrich(domain_name)
        if res:
            for element in res:
                if element['score'] != 'n/a':
                    self.score_list.append(element['score'])
        return self.score_list

################################################################################################

    def hash_to_score(self, hash_value):
        res = Malwr().search(hash_value)
        if res:
            for element in res:
                if element['score'] != 'n/a':
                    self.score_list.append(element['score'])
        return self.score_list

    def hash_to_url(self, hash_value):
        res = Malwr().search(hash_value)
        if res:
            for element in res:
                self.url_list.append(element['submission_url'])
        return self.url_list


    def hash_to_ipv4(self, hash_value):
        uri = []
        res = Malwr().search(hash_value)
        if res:
            for element in res:
                uri.append(element['submission_url'])
            for value in uri:
                res = Malwr().request_to_soup(value)
                submissions = res.findAll('section', {'id': 'hosts'})[0]
                for elements in submissions.findAll('td'):
                    self.ip_list.append(elements.string)
        return list(set(self.ip_list))


    def hash_to_imphash(self, hash_value):
        uri = []
        res = Malwr().search(hash_value)
        imphash_value = ''
        if res:
            for element in res:
                uri.append(element['submission_url'])
            for value in uri:
                results = Malwr().request_to_soup(value)
                submissions = results.findAll('section', {'id': 'static_analysis'})
                if submissions:
                    submissions = submissions[0]
                    imphash_value = submissions.findAll('div', {'class': 'well'})
                if imphash_value:
                    imphash_value = imphash_value[0].string
                    self.imphash_list.append(hash_value)
        return list(set(self.imphash_list))


if __name__ == '__main__':

    test_ip = '146.255.37.1'
    test_domain = 'yandex.ru'
    ##print Malwr().ipv4_to_score(test_ip)
    ##print Malwr().ipv4_to_hash(test_ip)
    ##print Malwr().ipv4_to_url(test_ip)

    ##print Malwr().domain_to_hash(test_domain)
    ##print Malwr().domain_to_score(test_domain)
    ##print Malwr().domain_to_url(test_domain)

    ##print Malwr().hash_to_ipv4('a871e4d2dd2aa51da4ca863739b51ccb')
    ##print Malwr().hash_to_imphash('a871e4d2dd2aa51da4ca863739b51ccb')
    ##print Malwr().hash_to_url('a871e4d2dd2aa51da4ca863739b51ccb')
    ##print Malwr().hash_to_score('a871e4d2dd2aa51da4ca863739b51ccb')
