#! /usr/bin/env python
# Apologies to digininja.
#
# jnw@cise.ufl.edu
'''Use Burp Suite Professional's output to generate a password list

'''

import time
from burp2xml import burp_to_xml
from optparse import OptionParser
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO
from httplib import HTTPResponse

class StringSocket(StringIO):
    ''' StringSocket
    provides interface necessary for HTTPResponse
    to treat data from a string as if it came from a socket.
    '''
    
    def makefile(self, *args, **kw):
        return self

def httpparse(str):
    socket = StringSocket(str)
    response = HTTPResponse(socket)
    response.begin()

    return response
    
class HTTPRequest(BaseHTTPRequestHandler):
    '''HTTPRequest
    provides code necessary to parse an HTTPRequest
    from a string rather than a url
    '''
    
    def __init__(self, request_text):
        self.rfile = StringIO(request_text)
        self.raw_requestline = self.rfile.readline()
        self.error_code = self.error_message = None
        self.parse_request()

    def send_error(self, code, message):
        self.error_code = code
        self.error_message = message


class Namespace: pass

def vprint(arg):
    if globals.VERBOSE:
        print arg

def main():
    REQUEST_OPEN_TAG = '<request>'
    REQUEST_CLOSE_TAG = '</request>'
    RESPONSE_OPEN_TAG = '<response>'
    RESPONSE_CLOSE_TAG = '</response>'
    
    usage = ("%prog [options] burp-session-file\n"
             "  minese a burp session file for possible passwords\n"
             "  motiviated by digininja's cewl")
    parser = OptionParser()
    parser.add_option("-d","--depth",
                      action="store_const", const=2, dest="depth",
                      help="depth to spider to, default 2")
    parser.add_option("-m","--min_word_length",
                      action="store_const", const=3, dest="min_word_length",
                      help="minimum word length, default 3")
    parser.add_option("-e","--email",
                      action="store_true",dest="EMAIL", default=False,
                      help="output email addresses")
    parser.add_option("--email_file",
                      action="store", dest="email_file",
                      help="output file for email addresses")
    parser.add_option("-a", "--meta",
                      action="store_true",dest="META", default=False,
                      help="output metadata")
    parser.add_option("--meta-file",
                      action="store", dest="meta_file",
                      help="output file for meta data")
    parser.add_option("-n","--no-words",
                      action="store_true",dest="NO_WORDS", default=False,
                      help="do not output the wordlist")
    parser.add_option("-w","--write",
                      dest="output_file",
                      help="write the words to file")
    parser.add_option("-c","--count",
                      action="store_true", dest="COUNT", default=False,
                      help="show the count for each of the words found")
    parser.add_option("-v","--verbose",
                      action="store_true", dest="VERBOSE", default=False,
                      help="verbose")
    parser.add_option("--meta-temp-dir",
                      action="store", dest="meta_temp_dir",
                      help="temporary directory used by exiftool when parsing file, default /tmp")
    (options,args) = parser.parse_args()

    global globals
    globals = Namespace()
    globals.VERBOSE = options.VERBOSE
    
    if len(args) != 1:
        parser.print_usage()
    else:
        vprint("Converting burp session file to xml")
        burp_xml_string = burp_to_xml(args[0])

        # First Get the Request
        while 1:
            rq_begin_index = burp_xml_string.find(REQUEST_OPEN_TAG)
            if rq_begin_index < 0:
                break
            rq_end_index = burp_xml_string.find(REQUEST_CLOSE_TAG)
            if rq_end_index < 0:
                # throw exception for bad formatting
                break
            request_string = burp_xml_string[rq_begin_index +
                                             len(REQUEST_OPEN_TAG):
                                             rq_end_index]
            
            request = HTTPRequest(request_string)
            print request.headers['Host'] + request.path
            
            burp_xml_string = burp_xml_string[rq_end_index +
                                              len(REQUEST_CLOSE_TAG):]
            

    
if __name__ == '__main__':
    main()
