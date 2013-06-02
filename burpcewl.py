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
import ElementSoup
import re

class StringSocket(StringIO):
    ''' StringSocket
    provides interface necessary for HTTPResponse
    to treat data from a string as if it came from a socket.
    '''
    
    def makefile(self, *args, **kw):
        return self

def http_parse(str):
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
    if OPTIONS.VERBOSE:
        print arg
    
def get_tag_content(str,tag):
            begin_index = str.find('<' + tag + '>')
            if begin_index < 0:
                raise LookupError
            end_index = str.find('</' + tag + '>')
            if end_index < 0:
                raise LookupError
            return (str[end_index + len(tag) + 3:],
                        str[begin_index + len(tag) + 2 : end_index])

def remove_CDATA(str):
    CDATA_START = '<![CDATA['
    CDATA_END = ']]>'
    if str.find(CDATA_START) == 0:
        if str[-3:] == CDATA_END:
            str = str[len(CDATA_START):-len(CDATA_END)]
        else:
            raise LookupError
    return str

def html_get_words(str):
    tree = ElementSoup.parse(StringIO(str))   
    for text in tree.itertext():
        for word in re.sub("[^\w]", " ",  text).split():
            if len(word) >= OPTIONS.min_word_length:
                try:
                    DICTIONARY[word] = DICTIONARY[word] + 1
                except:
                    DICTIONARY[word] = 1
def do_pass(str):
    pass

def main():
    usage = ("%prog [options] burp-session-file\n"
             "  mine a burp session file for possible passwords\n"
             "  motiviated by digininja's cewl\n")
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

    global OPTIONS
    global DICTIONARY

    (OPTIONS,args) = parser.parse_args()
    DICTIONARY = {}

    if len(args) != 1:
        parser.print_usage()
    else:
        vprint("Converting burp session file to xml")
        try:
            burp_xml_str = burp_to_xml(args[0],True)
        except:
            print 'burp2xml.py failed to parse session file'
            raise

        action_map = {
            'application/pdf':do_pass,
            'application/x-gzip':do_pass,
            'application/x-shockwave-flash':do_pass,
            'audio/x-wav':do_pass,
            'image/jpeg':do_pass,
            'image/gif':do_pass,
            'image/png':do_pass,
            'image/x-bitmap':do_pass,
            'text/css':do_pass,
            'text/html':html_get_words,
            'text/plain':do_pass,
        }

        # First Get the Request
        while 1:
            try:
                (burp_xml_str, rq_str) = get_tag_content(burp_xml_str,'request')
                request = HTTPRequest(rq_str)
  #              print request.headers['Host'] + request.path
            except LookupError:
                break
            try:
                (burp_xml_str, rsp_str) = get_tag_content(burp_xml_str,'response')
                rsp_str = remove_CDATA(rsp_str)
                response = http_parse(rsp_str)
                type_str = response.getheader('Content-Type')
                semi_index = type_str.find(';')
                if semi_index >= 0:
                    type_str = type_str[0:semi_index].lower()
#                print ' ' + type_str
                body_str = response.read()
                try:
                    action_map[type_str](body_str)
                except:
                    pass


            except LookupError:
 #               print "Missing response"
                raise 

        for word in sorted(DICTIONARY.keys()):
            print word + ':' + str(DICTIONARY[word])
    
if __name__ == '__main__':
    main()
