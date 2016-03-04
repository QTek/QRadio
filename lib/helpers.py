import time
import os.path, sys
import re
import requests
from bs4 import BeautifulSoup


class Common(object):

    # Help to make a requests to websites
    def session_helper(self, station_name=None, # station_name - REQUIRE - 'Station_name'
                       endpoint=None, # 'https://station.com/api/search/index.php'
                       method_type=None, # GET/POST
                       data_to_send=None, # Data to sent in POST
                       url_path=None, # '/api/search/google.com'
                       parameters=None, # {'limit': '1000'}
                       headers=None, # {'api_key': 'api_key_value'}
                       user_agent=None, # {'User-agent': 'VxStream Sandbox'}
                       response_format=None, # json or bs(BeautifulSoup)
                       go_to_url=None): # https://www.station.com/index.php?a=somethins&d=something

        self.session = requests.Session()
        self.station_name = station_name

        # change default user_agent to:
        if user_agent:
            self.user_agent = user_agent
        else:
            # Firefox is default User-Agent
            self.session.headers = {'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:41.0) ' +
                                                  'Gecko/20100101 Firefox/41.0'}

        # append custom values. e.g. {'search': 'this'}
        if headers:
            self.session.headers.update(headers)

        # Path additionally to endpoint
        # e.g. /api/search/domain/google.com
        if url_path:
            self.url_path = url_path
        else:
            self.url_path = ''

        # e.g. ...?search=domain_name&value=full_history
        if parameters:
            self.parameters = parameters
        else:
            self.parameters = ''

        # Make request only if endpoint, station and get/post specified
        if station_name and endpoint and method_type:
            if go_to_url:
                # If URL provided
                url = go_to_url
            else:
                # Create URL for request
                url = endpoint + str(self.url_path)
            try:
                # Disable warning for SSL key trust
                requests.packages.urllib3.disable_warnings()

                # Make request with GET
                if method_type == 'get':
                    get_request = self.session.get(url, params=self.parameters, verify=False)
                    #if get_request.status_code == 200 or get_request.status_code == 400 or get_request.status_code == 404:
                    self.html_results = get_request

                # Make request with POST
                elif method_type == 'post':
                    post_request = self.session.post(url, params=self.parameters, data=data_to_send)
                    # Check if return code is 200
                    if post_request.status_code == 200:
                        self.html_results = post_request

                # Return BeautifulSoup, JSON or raw output
                if response_format == 'bs' and self.html_results:
                    return BeautifulSoup(self.html_results.text, 'html.parser')
                elif response_format == 'json' and self.html_results:
                    return self.html_results.json()
                else:
                    return self.html_results

            # Catch errors
            except requests.ConnectionError as e:
                # network problem (e.g. DNS failure, refused connection, etc) in e
                IO().error_log(e, self.station_name)
                return
            except requests.exceptions.Timeout as e:
                #Request Time out in e
                IO().error_log(e, self.station_name)
                return
            except requests.exceptions.TooManyRedirects as e:
                #Invalid URL in e
                IO().error_log(e, self.station_name)
                return
            except requests.exceptions.RequestException as e:
                # Return the other errors in e
                IO().error_log(e, self.station_name)
                return
            except:
                return None
        # endpoint, station or get/post NOT specified
        else:
            return None



    # Return output for every station with its result
    def verbose_output(self, search_value, search_from, search_to, dictionary):
        #time_stamp = time.asctime(time.localtime(time.time()))
        #time_stamb_output = '#'+'DATE: ' + time_stamp

        # e.g. #FROM_HASH_TO_DOMAIN
        header_output = ('#'+search_from+'_'+search_to).upper() + '\n'

        # e.g. #SEARCH: 8.8.8.8
        search_output = '#SEARCH: ' + search_value
        full_results = ''
        unique_values = ''

        for packed_values in dictionary:
            if dictionary is None:
                return

            # Search values, but not Blacklist
            elif not isinstance(dictionary[packed_values], bool):
                try:
                    # Unpack list of values from dictionary and return as list. e.g. from [[...]] to [...]
                    unpack = [item for sublist in dictionary.values() if sublist for item in sublist]
                    # Make unique list
                    unique_list = list(set(unpack))
                except:
                    unique_list = []


            # Blacklist has bool as value
            if isinstance(dictionary[packed_values], bool):
                unique_values = ''

            # Unique values
            elif len(unique_list) > 0:
                unique_values = '\n#UNIQUE: ' + str(len(unique_list)) + '\n  ' + ' '.join(unique_list)
            # No result from station
            else:
                unique_values = '\n#NO RESULTS'


        for station in dictionary:
            station_info_output = ''
            results = ''
            #
            if isinstance(dictionary[station], list):
                if dictionary[station].__len__() != 0:
                    station_info_output = ('#'+station+' FIND: '+str(dictionary[station].__len__())).upper()+'\n  '
                    results += '\n  '.join(dictionary[station])+'\n'

            # Blacklist has bool as value
            elif isinstance(dictionary[station], bool):
                station_info_output = '#'+station+': '+str(dictionary[station])+'\n'

            full_results += station_info_output+results

        footer_output = '##############################\n'

        verbose_output_results = '%s%s%s\n%s%s' % (header_output, search_output, unique_values, full_results, footer_output)
        return verbose_output_results



    # Return CSV from station results
    def nonverbose_output(self, search_value, search_from, search_to, dictionary):

        if isinstance(dictionary, str):
            unique_list = dictionary
        else:
            for packed_values in dictionary:
                if dictionary is None:
                    return

                # Search values, but not Blacklist
                elif not isinstance(dictionary[packed_values], bool):
                    try:
                        # Unpack list of values from dictionary and return as list. e.g. from [[...]] to [...]
                        unpack = [item for sublist in dictionary.values() if sublist for item in sublist]
                        # Make unique list
                        unique_list = list(set(unpack))
                    except:
                        unique_list = []

        # Domain | IP | Hash | Score | URL | Blacklist | Imphash | Mutex
        #   [1]   [2]    [3]    [4]    [5]     [6]         [7]      [8]

        msg = ''

        ##########################################################################
        # Domain
        if search_from == 'From_domain': # [1]
            if search_to == 'to_ipv4': # [2]
                for i in unique_list:
                    msg += search_value + ',' + i + ',,,,,,' + '\n'

            if search_to == 'to_hash': # [3]
                for i in unique_list:
                    msg += search_value + ',,' + i + ',,,,,' + '\n'

            if search_to == 'to_score': # [4]
                for i in unique_list:
                    msg += search_value + ',,,' + i + ',' + ',,,\n'

            if search_to == 'to_url': # [5]
                for i in unique_list:
                    msg += search_value + ',,,,' + i + ',,,\n'

            if search_to == 'to_blacklist': # [6]
                msg += search_value + ',,,,,' + str(unique_list) + ',,\n'

        ##########################################################################
        # IP
        if search_from == 'From_ipv4': # [2]
            if search_to == 'to_domain': # [1]
                for i in unique_list:
                    msg += i + ',' + search_value + ',,,,,,\n'

            if search_to == 'to_hash': # [3]
                for i in unique_list:
                    msg += ',' + search_value + ',' + i + ',,,,,\n'

            if search_to == 'to_score': # [4]
                for i in unique_list:
                    msg += ',' + search_value + ',,' + i + ',,,,\n'

            if search_to == 'to_blacklist': # [6]
                msg += ',' + search_value + ',,,,' + str(unique_list) + ',,\n'

        ##########################################################################
        # Hash
        if search_from == 'From_hash': # [3]
            if search_to == 'to_domain': # [1]
                for i in unique_list:
                    msg += i + ',,' + search_value + ',,,,,\n'

            if search_to == 'to_ipv4': # [2]
                for i in unique_list:
                    msg += ',' + i + ',' + search_value + ',,,,,\n'

            if search_to == 'to_score': # [4]
                for i in unique_list:
                    msg += ',,' + search_value + ',' + i + ',,,,\n'

            if search_to == 'to_url': # [5]
                for i in unique_list:
                    msg += ',,' + search_value + ',,' + i + ',,,\n'

            if search_to == 'to_imphash': # [7]
                for i in unique_list:
                    msg += ',,' + search_value + ',,,,' + i + ',\n'


        ##########################################################################
        # Miscelanous
        if search_from == 'From_imphash': # [7]
            if search_to == 'to_hash': # [3]
                for i in unique_list:
                    msg += ',,' + i + ',,,,' + search_value + ',\n'

        if search_from == 'From_mutex': # [8]
            if search_to == 'to_hash': # [3]
                for i in unique_list:
                    msg += ',,' + i + ',,,,,' + search_value + '\n'

        return msg



class IO(object):


    def error_log(self, error, station_name=None):
        if os.path.isfile('error_log.txt'):
            file = open('error_log.txt', 'a')
        else:
            file = open('error_log.txt', 'w')

        if not station_name:
            station_name = 'NO-STATION-NAME'


        # Create time stamp
        time_stamp = time.asctime(time.localtime(time.time()))

        # Form error message 'Station == Time == Error'
        error_msg = str(station_name) + '\t' + time_stamp + '\t' + str(error) + '\n'
        file.write(error_msg)
        file.close()

    def process_file(self, file_path):
        try:
            log_file = open(file_path, 'r')
            log_data = log_file.readlines()
            for item in log_data:
                print(item.strip('\n'))
        except:
            print('failed to open file')
            return False
        return True


    # Validate input
    def input_validator(self,input_value):
        is_ip = re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', input_value)
        is_domain = re.match(r'[a-zA-Z0-9]*\.[a-zA-Z0-9]*', input_value)
        is_hash = re.match(r'^\w{32,}$', input_value)

        if is_ip: # If input is IP address
            return 'is_ip'
        elif is_domain: # If input is domain
            return 'is_domain'
        elif is_hash and len(input_value) >= 32: # Is input is hash
            return 'is_hash'
        else:
            return 'is_invalid'











class MaltegoEntity(object):

    #######################################################
    # Maltego Python Local Transform Helper               #
    #   Version 0.2				                          #
    #                                                     #
    # Local transform specification can be found at:      #
    #    http://ctas.paterva.com/view/Specification	      #
    #                                                     #
    # For more help and other local transforms            #
    # try the forum or mail me:                           #
    #                                                     #
    #   http://www.paterva.com/forum                      #
    #                                                     #
    #  Andrew MacPherson [ andrew <<at>> Paterva.com ]    #
    #                                                     #
    #######################################################

    BOOKMARK_COLOR_NONE="-1"
    BOOKMARK_COLOR_BLUE="0"
    BOOKMARK_COLOR_GREEN="1"
    BOOKMARK_COLOR_YELLOW="2"
    BOOKMARK_COLOR_ORANGE="3"
    BOOKMARK_COLOR_RED="4"

    LINK_STYLE_NORMAL="0"
    LINK_STYLE_DASHED="1"
    LINK_STYLE_DOTTED="2"
    LINK_STYLE_DASHDOT="3"

    UIM_FATAL='FatalError'
    UIM_PARTIAL='PartialError'
    UIM_INFORM='Inform'
    UIM_DEBUG='Debug'

    value = ""
    weight = 100
    displayInformation = None
    additionalFields = []
    iconURL = ""
    entityType = "Phrase"

    def __init__(self,eT=None,v=None):
        if (eT is not None):
            self.entityType = eT
        if (v is not None):
            self.value = MaltegoTransform().sanitise(v)
        self.additionalFields = []
        self.displayInformation = None

    def setType(self,eT=None):
        if (eT is not None):
            self.entityType = eT

    def setValue(self,eV=None):
        if (eV is not None):
            self.value = MaltegoTransform().sanitise(eV)

    def setWeight(self,w=None):
        if (w is not None):
            self.weight = w

    def setDisplayInformation(self,di=None):
        if (di is not None):
            self.displayInformation = di

    def addAdditionalFields(self,fieldName=None,displayName=None,matchingRule='',value=None):
        self.additionalFields.append([MaltegoTransform().sanitise(fieldName),MaltegoTransform().sanitise(displayName),matchingRule,MaltegoTransform().sanitise(value)])

    def setIconURL(self,iU=None):
        if (iU is not None):
            self.iconURL = iU

    def setLinkColor(self,color):
        self.addAdditionalFields('link#maltego.link.color','LinkColor','',color)

    def setLinkStyle(self,style):
        self.addAdditionalFields('link#maltego.link.style','LinkStyle','',style)

    def setLinkThickness(self,thick):
        self.addAdditionalFields('link#maltego.link.thickness','Thickness','',str(thick))

    def setLinkLabel(self,label):
        self.addAdditionalFields('link#maltego.link.label','Label','',label)

    def setBookmark(self,bookmark):
        self.addAdditionalFields('bookmark#','Bookmark','',bookmark)

    def setNote(self,note):
        self.addAdditionalFields('notes#','Notes','',note)

    def returnEntity(self):
        print "<Entity Type=\"" + str(self.entityType) + "\">"
        print "<Value>" + str(self.value) + "</Value>"
        print "<Weight>" + str(self.weight) + "</Weight>"
        if (self.displayInformation is not None):
            print "<DisplayInformation><Label Name=\"\" Type=\"text/html\"><![CDATA[" + str(self.displayInformation) + "]]></Label></DisplayInformation>"
        if (len(self.additionalFields) > 0):
            print "<AdditionalFields>"
            for i in range(len(self.additionalFields)):
                if (str(self.additionalFields[i][2]) <> "strict"):
                    print "<Field Name=\"" + str(self.additionalFields[i][0]) + "\" DisplayName=\"" + str(self.additionalFields[i][1]) + "\">" + str(self.additionalFields[i][3]) + "</Field>"
                else:
                    print "<Field MatchingRule=\"" + str(self.additionalFields[i][2]) + "\" Name=\"" + str(self.additionalFields[i][0]) + "\" DisplayName=\"" + str(self.additionalFields[i][1]) + "\">" + str(self.additionalFields[i][3]) + "</Field>"
            print "</AdditionalFields>"
        if (len(self.iconURL) > 0):
            print "<IconURL>" + self.iconURL + "</IconURL>"
        print "</Entity>"

class MaltegoTransform(object):
    #######################################################
    # Maltego Python Local Transform Helper               #
    #   Version 0.2				                          #
    #                                                     #
    # Local transform specification can be found at:      #
    #    http://ctas.paterva.com/view/Specification	      #
    #                                                     #
    # For more help and other local transforms            #
    # try the forum or mail me:                           #
    #                                                     #
    #   http://www.paterva.com/forum                      #
    #                                                     #
    #  Andrew MacPherson [ andrew <<at>> Paterva.com ]    #
    #                                                     #
    #######################################################

    entities = []
    exceptions = []
    UIMessages = []
    values = {}

    def __init__(self):
        values = {}
        value = None

    def parseArguments(self,argv):
        if (argv[1] is not None):
            self.value = argv[1]

        if (len(argv) > 2):
            if (argv[2] is not None):
                vars = argv[2].split('#')
                for x in range(0,len(vars)):
                    vars_values = vars[x].split('=')
                    if (len(vars_values) == 2):
                        self.values[vars_values[0]] = vars_values[1]

    def getValue(self):
        if (self.value is not None):
            return self.value

    def getVar(self,varName):
        if (varName in self.values.keys()):
            if (self.values[varName] is not None):
                return self.values[varName]

    def addEntity(self,enType,enValue):
        me = MaltegoEntity(enType,enValue)
        self.addEntityToMessage(me)
        return self.entities[len(self.entities)-1]

    def addEntityToMessage(self,maltegoEntity):
        self.entities.append(maltegoEntity)

    def addUIMessage(self,message,messageType="Inform"):
        self.UIMessages.append([messageType,message])

    def addException(self,exceptionString):
        self.exceptions.append(exceptionString)

    def throwExceptions(self):
        print "<MaltegoMessage>"
        print "<MaltegoTransformExceptionMessage>"
        print "<Exceptions>"

        for i in range(len(self.exceptions)):
            print "<Exception>" + self.exceptions[i] + "</Exception>"
        print "</Exceptions>"
        print "</MaltegoTransformExceptionMessage>"
        print "</MaltegoMessage>"
        exit()

    def returnOutput(self):
        print "<MaltegoMessage>"
        print "<MaltegoTransformResponseMessage>"

        print "<Entities>"
        for i in range(len(self.entities)):
            self.entities[i].returnEntity()
        print "</Entities>"

        print "<UIMessages>"
        for i in range(len(self.UIMessages)):
            print "<UIMessage MessageType=\"" + self.UIMessages[i][0] + "\">" + self.UIMessages[i][1] + "</UIMessage>"
        print "</UIMessages>"

        print "</MaltegoTransformResponseMessage>"
        print "</MaltegoMessage>"

    def writeSTDERR(self,msg):
        sys.stderr.write(str(msg))

    def heartbeat(self):
        self.writeSTDERR("+")

    def progress(self,percent):
        self.writeSTDERR("%" + str(percent))

    def debug(self,msg):
        self.writeSTDERR("D:" + str(msg))

    def sanitise(self, value):
        replace_these = ["&",">","<"]
        replace_with = ["&amp","&gt","&lt"]
        tempvalue = value
        for i in range(0,len(replace_these)):
            tempvalue = tempvalue.replace(replace_these[i],replace_with[i])
        return tempvalue