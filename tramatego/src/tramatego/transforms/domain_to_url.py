#!/usr/bin/env python

from canari.maltego.utils import debug, progress
from canari.framework import configure #, superuser
from canari.maltego.entities import Domain, Phrase
from common.launchers import get_qradio_data


__author__ = 'Zappus'
__copyright__ = 'Copyright 2016, TramaTego Project'
__credits__ = []

__license__ = 'GPL'
__version__ = '0.1'
__maintainer__ = 'Zappus'
__email__ = 'zappus@protonmail.com'
__status__ = 'Development'

__all__ = [
    'dotransform',
    #'onterminate' # comment out this line if you don't need this function.
]


#@superuser
@configure(
    label='Domain to Source URL',
    description='',
    uuids=[ 'TramaTego.v1.DomainToSourceURL' ],
    inputs=[ ( 'TramaTego', Domain ) ],
    debug=True
)
def dotransform(request, response, config):
    command = "--domain_to_url " + request.value
    qradio_output = get_qradio_data(command, 4)
    for entry in qradio_output:
        response += Phrase(entry)
    return response


def onterminate():
    """
    TODO: Write your cleanup logic below or delete the onterminate function and remove it from the __all__ variable
    """
    pass