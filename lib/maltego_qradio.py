import sys

from helpers import api_qradio as q
from helpers import MaltegoTransform


##############################################################
## ENRICH Section
def ipv4_enrich(mt, ip_address):
    enrich_list = q.ipv4_enrich(ip_address)
    for domain in enrich_list['domains']:
        mt.addEntity("maltego.Domain", domain)
    for hash in enrich_list['hash']:
        mt.addEntity("maltego.Hash", hash)
    for score in enrich_list['score']:
        mt.addEntity("maltego.Score", score)
    mt.addEntity("maltego.Blacklist", str(enrich_list['blacklist']))
    return mt


def domain_enrich(mt, domain_name):
    enrich_list = q.domain_enrich(domain_name)
    for ip_address in enrich_list['ip_address']:
        mt.addEntity("maltego.IPv4Address", ip_address)
    for hash in enrich_list['hash']:
        mt.addEntity("maltego.Hash", hash)
    for score in enrich_list['score']:
        mt.addEntity("maltego.Score", score)
    return mt


def hash_enrich(mt, hash_value):
    enrich_list = q.hash_enrich(hash_value)
    for score in enrich_list:
        mt.addEntity("maltego.Score", score['score'])
    for ip_address in enrich_list:
        mt.addEntity("maltego.IPv4Address", ip_address['ip_address'])
    for imphash in enrich_list:
        mt.addEntity("maltego.Imphash", imphash['imphash'])
    for uri in enrich_list:
        mt.addEntity("maltego.URI", uri['uri'])
    return mt



##############################################################
## IP section
def ipv4_to_domain(mt, ip_address):
    domain_list = q.ipv4_to_domain(ip_address)
    for domain in domain_list:
        mt.addEntity("maltego.Domain", domain)
    return mt

def ipv4_to_hash(mt, ip_address):
    hash_list = q.ipv4_to_hash(ip_address)
    for hash in hash_list:
        mt.addEntity("maltego.Hash", hash)
    return mt

def ipv4_to_blacklist(mt, ip_address):
    blacklisted = q.ipv4_to_blacklist(ip_address)
    mt.addEntity("maltego.Blacklist", blacklisted)
    return mt

def ipv4_to_score(mt, ip_address):
    score_list = q.ipv4_to_score(ip_address)
    for score in score_list:
        mt.addEntity("maltego.Score", score)
    return mt

##############################################################
## Domain section
def domain_to_ipv4(mt, domain_name):
    ip_list = q.domain_to_ipv4(domain_name)
    for ip_address in ip_list:
        mt.addEntity("maltego.IPv4Address", ip_address)
    return mt

def domain_to_hash(mt, domain_name):
    hash_list = q.domain_to_hash(domain_name)
    for hash in hash_list:
        mt.addEntity("maltego.Hash", hash)
    return mt

def domain_to_score(mt, domain_name):
    score_list = q.domain_to_score(domain_name)
    for score in score_list:
        mt.addEntity("maltego.Score", score)
    return mt

##############################################################
## Hash section
def hash_to_score(mt, hash_valuse):
    score_list = q.hash_to_score(hash_valuse)
    for score in score_list:
        mt.addEntity("maltego.Score", score)
    return mt

def hash_to_imphash(mt, hash_valuse):
    imphash_list = q.hash_to_imphash(hash_valuse)
    for imphash in imphash_list:
        mt.addEntity("maltego.Imphash", imphash)
    return mt

def hash_to_ipv4(mt, hash_valuse):
    ip_list = q.hash_to_ipv4(hash_valuse)
    for ip_address in ip_list:
        mt.addEntity("maltego.IPv4Address", ip_address)
    return mt

def hash_to_uri(mt, hash_valuse):
    uri_list = q.hash_to_uri(hash_valuse)
    for uri in uri_list:
        mt.addEntity("maltego.URI", uri)
    return mt

##############################################################
## Imphash section
def imphash_to_hash(mt, imphash):
    hash_list = q.imphash_to_hash(imphash)
    for hash in hash_list:
        mt.addEntity("maltego.Hash", hash)
    return mt

##############################################################

functions = {
    'ipv4_enrich': ipv4_enrich,
    'domain_enrich': domain_enrich,
    'hash_enrich': hash_enrich,

    'ipv4_to_domain': ipv4_to_domain,
    'ipv4_to_hash': ipv4_to_hash,
    'ipv4_to_blacklist': ipv4_to_blacklist,
    'ipv4_to_score': ipv4_to_score,

    'domain_to_ipv4': domain_to_ipv4,
    'domain_to_hash': domain_to_hash,
    'domain_to_score': domain_to_score,

    'hash_to_score': hash_to_score,
    'hash_to_imphash': hash_to_imphash,
    'hash_to_ipv4': hash_to_ipv4,
    'hash_to_uri': hash_to_uri,

    'imphash_to_hash': imphash_to_hash,
    }

##### MAIN #####
if __name__ == '__main__':
    transform = sys.argv[1]
    data = sys.argv[2]

    mt = MaltegoTransform()

    result = functions[transform](mt, data)
    result.returnOutput()