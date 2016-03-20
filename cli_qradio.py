# -*- coding: utf-8 -*-
from argparse import ArgumentParser, FileType, RawTextHelpFormatter
from lib.qradio import *
import time

# Parses arguments, search data and produce output
class Command_line_parser(object):

    def __init__(self):

        self.parser = ArgumentParser(description='QRadio - "Firegun" Edition', add_help=True)


        # QRadio version
        self.version = '1.4.1'

        # Provide description and parameters for arguments
        self.parser = ArgumentParser(
                description=''
                             'QRadio can search and match different types of cyber threat information\n'
                             '\t     Info types: Domain, IPv4, Hash, Imphash, Mutex\n'
                             '',
                # Append message in the end of help
                epilog='Thanks for listening! ;)\n'
                    'QRadio v. {}'.format(self.version),

                usage='%(prog)s domain|IPv4|hash [imphash|mutex] [station name|station#]\n',
                # Show '-h, --help' as addition option
                add_help=False,
                # Ability use \n \t...
                formatter_class=RawTextHelpFormatter)

        # Create group 'Searching' for help message

        self.search_group = self.parser.add_argument_group('Searching')
        # Add positional argument 'search_value' to store input values
        self.search_group.add_argument('search_value',
                           # Accept zero or more input values
                           nargs='*',
                           # Append all input values into a list as string ['val','val2','val3',...]
                           action='append',
                           # Create help message description
                           # Data types:
                           # 1 = Domain
                           # 2 = IPv4
                           # 3 = Hash
                           # 4 = Score
                           # 5 = URL to Analysis
                           # 6 = Blacklist
                           # 7 = Imphash
                           # 8 = Mutex
                           help= 'search values:  domain | IPv4 | hash | imphash | mutex\n'
                            'SONAR - 100 | 200 | 300  is used if no station supplied') # Search value(s) go first

        # Create group for help message
        self.output_group = self.parser.add_argument_group('Output verbosity')
        # Add optional argument for verbosity
        # Note: (--)Long_name, (-)Short_name
        self.output_group.add_argument('-v', '--verbose', required=False,
                                       # If specified returns True
                                       action='store_true',
                                       # Create help message description
                                       help='Show verbose output')

        # Create group for help message
        self.domain_group = self.parser.add_argument_group('DNS Tunes')
        # Add optional arguments for different searches in group. Return True if used
        # 100 - SONAR - Search to all available data types.
        # 102 - From Domain to IPv4
        # 103 - From Domain to Hash
        # 104 - From Domain to Score
        # 105 - From Domain to URL
        # 106 - Domain to Blacklist
        self.domain_group.add_argument('-100',
                                       '--sonar_domain',  action='store_true', required=False,
                                       help='SONAR to IPv4, Hash, Score, URL, Blacklist\n ')

        self.domain_group.add_argument('-102',
                                       '--domain_to_ipv4', action='store_true', required=False,
                                       help='Resolve IPv4 to <domain>')

        self.domain_group.add_argument('-103',
                                       '--domain_to_hash', action='store_true', required=False,
                                       help='Search Hash for <domain>')

        self.domain_group.add_argument('-104',
                                       '--domain_to_score', action='store_true', required=False,
                                       help='Detection score for <domain>')

        self.domain_group.add_argument('-105',
                                       '--domain_to_url', action='store_true', required=False,
                                       help='URL to analysis for <domain>')

        self.domain_group.add_argument('-106',
                                       '--domain_to_blacklist', action='store_true', required=False,
                                       help='Search <domain> in blacklists')

        # Add optional arguments for different searches in group. Return True if used
        # 200 - SONAR - Search to all available data types.
        # 201 - From IPv4 to Domain
        # 203 - From IPv4 to Hash
        # 204 - From IPv4 to Score
        # 206 - IPv4 to Blacklist
        self.ip_group = self.parser.add_argument_group('IPv4 Tunes')
        self.ip_group.add_argument('-200',
                                   '--sonar_ipv4', action='store_true', required=False,
                                   help='SONAR to Domain, Hash, Score, Blacklist\n ')
        self.ip_group.add_argument('-201',
                                   '--ipv4_to_domain', action='store_true', required=False,
                                   help='Resolve Domain to <IPv4>')
        self.ip_group.add_argument('-203',
                                   '--ipv4_to_hash', action='store_true', required=False,
                                   help='Search Hash for <IPv4>')
        self.ip_group.add_argument('-204',
                                   '--ipv4_to_score', action='store_true', required=False,
                                   help='Detection score for <IPv4>')
        self.ip_group.add_argument('-206',
                                   '--ipv4_to_blacklist', action='store_true', required=False,
                                   help='Search <IPv4> in blacklists')

        # Add optional arguments for different searches in group. Return True if used
        # 300 - SONAR - Search to all available data types.
        # 301 - From Hash to Domain
        # 302 - From Hash to IPv4
        # 304 - From Hash to Score
        # 305 - Hash to URL
        # 307 - Hash to Imphash
        self.hash_group = self.parser.add_argument_group('Hash Tunes')
        self.hash_group.add_argument('-300',
                                     '--sonar_hash', action='store_true', required=False,
                                     help='SONAR to Domain, IPv4, Score, URL, Imphash\n ')
        self.hash_group.add_argument('-301',
                                     '--hash_to_domain', action='store_true', required=False
                                     , help='Search Domain for <hash>')
        self.hash_group.add_argument('-302',
                                     '--hash_to_ipv4', action='store_true', required=False,
                                     help='Search IP for <hash>')
        self.hash_group.add_argument('-304',
                                     '--hash_to_score', action='store_true', required=False,
                                     help='Detection score for <hash>')
        self.hash_group.add_argument('-305',
                                     '--hash_to_url', action='store_true', required=False,
                                     help='URL to analysis for <hash>')
        self.hash_group.add_argument('-307',
                                     '--hash_to_imphash', action='store_true', required=False,
                                     help='Search Imphash for <hash>')

        # Add optional arguments for different searches in group. Return True if used
        # 401 - From Imphash to Hash
        # 402 - From Mutex to Hash
        self.misc_group = self.parser.add_argument_group('Miscellaneous Tunes') # 400
        self.misc_group.add_argument('-401',
                                     '--imphash_to_hash', action='store_true', required=False,
                                     help='Search Hash with <imphash>')
        self.misc_group.add_argument('-402',
                                     '--mutex_to_hash', action='store_true', required=False,
                                     help='Search Hash with <mutex>')

        #self.file_group = self.parser.add_argument_group('File')
        #self.file_group.add_argument('-r', '--read_file',  required=False, type=FileType('r'), help='Read values from file')
        #self.file_group.add_argument('-w', '--write_file',  required=False, type=FileType('w'), help='Write results to file')

        # Store all created arguments
        self.arguments = self.parser.parse_args()

        # No search value provided
        if not self.arguments.search_value:
            # Print help message
            self.parser.print_help()
            return

        # If input values is provided
        if len(self.arguments.search_value[0]) != 0:

            # s_value = 'search_value' from list of values
            for s_value in self.arguments.search_value[0]:
                # Store search value in self.
                self.value_to_search = s_value
                # Validate and categorize the input
                # Can be: is_ip, is_domain, is_hash, is_invalid
                self.value_type = helpers.IO().input_validator(self.value_to_search)
                # If search value valid
                #if self.value_type != 'is_invalid':

                ##################################
                # Run search with flags and values
                self.form_header()
                self.flag_checker()
                self.searcher()

                #else:
                    ## If search value is invalid show help message
                    #self.parser.print_help()
                    #return

    # Form output output header according to verbosity
    # TODO: Move to helpers.py
    def form_header(self):
        # Set verbose flag
        self.verbose = False

        # If -v, --verbose = True
        # Create verbose output header
        if self.arguments.verbose:
            self.verbose = True

            # If the script runs with multiple search values or multiple times put only one header
            try:
                # Check is the variable exist
                len(self.header_output)
                # If it exist we remove header
                self.header_output = ''

            # If the script runs first time, create according header
            except AttributeError:
                # Verbose header
                self.header_output = '''
#     ________                                   \\\\   ||   //
#    /   __   \                                   \\\\  ||  //
#   |   /  \   |   .______      _____     ______      __     _____
#   |  |  _ |  |   |   _  \    /  _  \   |   _  \    |__|   /  _  \\
#   |  | / \|  |   |  |_)  )  |  / \  |  |  | \  \    __   |  / \  |
#   |  | \  |  |   |      /   |  |_|  |  |  |  )  )  |  |  | (   ) |
#   |   \_\    |   |  |\  \   |   _   |  |  |_/  /   |  |  |  \_/  |
#    \_______  \   |__| \__\  |__| |__|  |______/    |__|   \_____/
#            \__\\
#                                            ~ Tune In\n'''

                time_stamp = '#DATE ' + time.asctime(time.localtime(time.time())) + '\n'
                self.header_output += time_stamp
        # If -v, --verbose = False
        # Create CSV header
        else:
            # If the script runs with multiple search values or multiple times put only one header
            try:
                # Check is the variable exist
                len(self.header_output)
                # If it exist we remove header
                self.header_output = ''

            # If the script runs first time, create according header
            except AttributeError:
                # CSV Header
                # Domain , IPv4 , Hash , Score , URL , Blacklist , Imphash , Mutex
                #   [1]     [2]   [3]     [4]    [5]      [6]        [7]      [8]
                self.header_output = 'Domain,IPv4,Hash,Score,URL,Blacklist,Imphash,Mutex' +'\n'


    def flag_checker(self):
        # Flag check
        self.flag_cheked = False

        # Convert command line arguments in to dict to able access the values
        arguments_dict = vars(self.arguments)

        # i = key, argumets_dict[i] = value
        for i in arguments_dict:
            a = arguments_dict[i]
            # Find if any arguments are set
            if isinstance(arguments_dict[i], bool):
                # Skip 'verbose' argument
                if arguments_dict[i] and i != 'verbose':
                    self.flag_cheked = True

        # If no arguments specified run SONAR according to value type provided
        if not self.flag_cheked:
            if self.value_type == 'is_domain':
                arguments_dict['sonar_domain'] = True
            elif self.value_type == 'is_ip':
                arguments_dict['sonar_ipv4'] = True
            elif self.value_type == 'is_hash':
                arguments_dict['sonar_hash'] = True


    # Search according to arguments
    def searcher(self):
        self.output_former_result = ''

        # SONAR for Domain
        if self.arguments.sonar_domain:
            self.output_former_result += str(From_domain(verbose=self.verbose).to_ipv4(self.value_to_search))
            self.output_former_result += str(From_domain(verbose=self.verbose).to_hash(self.value_to_search))
            self.output_former_result += str(From_domain(verbose=self.verbose).to_score(self.value_to_search))
            self.output_former_result += str(From_domain(verbose=self.verbose).to_url(self.value_to_search))
            self.output_former_result += str(From_domain(verbose=self.verbose).to_blacklist(self.value_to_search))

        # From Domain to IPv4
        if self.arguments.domain_to_ipv4:
            self.output_former_result += str(From_domain(verbose=self.verbose).to_ipv4(self.value_to_search))

        # From Domain to Hash
        if self.arguments.domain_to_hash:
            self.output_former_result += str(From_domain(verbose=self.verbose).to_hash(self.value_to_search))

        # From Domain to Score
        if self.arguments.domain_to_score:
            self.output_former_result += str(From_domain(verbose=self.verbose).to_score(self.value_to_search))

        # From Domain to URL
        if self.arguments.domain_to_url:
            self.output_former_result += str(From_domain(verbose=self.verbose).to_url(self.value_to_search))

        # Domain to Blacklist
        if self.arguments.domain_to_blacklist:
            self.output_former_result += str(From_domain(verbose=self.verbose).to_blacklist(self.value_to_search))



        # SONAR for IPv4
        if self.arguments.sonar_ipv4:
            self.output_former_result += str(From_ipv4(verbose=self.verbose).to_domain(self.value_to_search))
            self.output_former_result += str(From_ipv4(verbose=self.verbose).to_hash(self.value_to_search))
            self.output_former_result += str(From_ipv4(verbose=self.verbose).to_score(self.value_to_search))
            self.output_former_result += str(From_ipv4(verbose=self.verbose).to_blacklist(self.value_to_search))

        # From IPv4 to Domain
        if self.arguments.ipv4_to_domain:
            self.output_former_result += str(From_ipv4(verbose=self.verbose).to_domain(self.value_to_search))

        # From IPv4 to Hash
        if self.arguments.ipv4_to_hash:
            self.output_former_result += str(From_ipv4(verbose=self.verbose).to_hash(self.value_to_search))

        # From IPv4 to Score
        if self.arguments.ipv4_to_score:
            self.output_former_result += str(From_ipv4(verbose=self.verbose).to_score(self.value_to_search))

        # IPv4 to Blacklist
        if self.arguments.ipv4_to_blacklist:
            self.output_former_result += str(From_ipv4(verbose=self.verbose).to_blacklist(self.value_to_search))



        # SONAR for Hash
        if self.arguments.sonar_hash:
            self.output_former_result += str(From_hash(verbose=self.verbose).to_domain(self.value_to_search))
            self.output_former_result += str(From_hash(verbose=self.verbose).to_ipv4(self.value_to_search))
            self.output_former_result += str(From_hash(verbose=self.verbose).to_score(self.value_to_search))
            self.output_former_result += str(From_hash(verbose=self.verbose).to_url(self.value_to_search))
            self.output_former_result += str(From_hash(verbose=self.verbose).to_imphash(self.value_to_search))

        # From Hash to Domain
        if self.arguments.hash_to_domain:
            self.output_former_result += str(From_hash(verbose=self.verbose).to_domain(self.value_to_search))

        # From Hash to IPv4
        if self.arguments.hash_to_ipv4:
            self.output_former_result += str(From_hash(verbose=self.verbose).to_ipv4(self.value_to_search))

        # From Hash to Score
        if self.arguments.hash_to_score:
            self.output_former_result += str(From_hash(verbose=self.verbose).to_score(self.value_to_search))

        # Hash to URL
        if self.arguments.hash_to_url:
            self.output_former_result += str(From_hash(verbose=self.verbose).to_url(self.value_to_search))

        # Hash to Imphash
        if self.arguments.hash_to_imphash:
            self.output_former_result += str(From_hash(verbose=self.verbose).to_imphash(self.value_to_search))


        # Imphashto Hash
        if self.arguments.imphash_to_hash:
            self.output_former_result += str(From_imphash(verbose=self.verbose).to_hash(self.value_to_search))


        # Mutex to Hash
        if self.arguments.mutex_to_hash:
            self.output_former_result += str(From_mutex(verbose=self.verbose).to_hash(self.value_to_search))


        # TODO: add File input/output
        # IO
        #if self.arguments.read_file:
        #    output_former_result += str(From_domain(verbose=self.verbose).to_hash(self.arguments.search_value))

        #if self.arguments.write_file:
        #    output_former_result += str(From_domain(verbose=self.verbose).to_hash(self.arguments.search_value))


        # Print the results with a header for csv or verbose
        if self.output_former_result:
            print self.header_output+self.output_former_result

if __name__ == '__main__':
    if len(sys.argv) > 1:
        Command_line_parser()
    else:
        Command_line_parser().parser.print_help()
