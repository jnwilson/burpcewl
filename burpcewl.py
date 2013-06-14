#! /usr/bin/env python
# Apologies to digininja.
#
#
# Depends on the following modules:
#   burp2xml (jnwilson@github fork)
#   python_magic
#   lxml
#
## jnw@cise.ufl.edu
'''Use Burp Suite Professional's output to generate a password list

'''

import time
from optparse import OptionParser
from BaseHTTPServer import BaseHTTPRequestHandler
from StringIO import StringIO
from httplib import HTTPResponse
import re
import sys
import subprocess
import operator

from burp2xml import burp_to_xml
from bs4 import BeautifulSoup
import magic


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


def vprint(arg):
    if Options.VERBOSE:
        sys.stderr.write(arg)


def get_tag_content(str, tag):
            begin_index = str.find('<' + tag + '>')
            if begin_index < 0:
                raise LookupError
            end_index = str.find('</' + tag + '>')
            if end_index < 0:
                raise LookupError
            return (str[end_index + len(tag) + 3:],
                        str[begin_index + len(tag) + 2:end_index])


def remove_CDATA(str):
    CDATA_START = '<![CDATA['
    CDATA_END = ']]>'
    if str.find(CDATA_START) == 0:
        if str[-3:] == CDATA_END:
            str = str[len(CDATA_START): - len(CDATA_END)]
        else:
            raise LookupError
    return str


def snarf(word):
    ''' Add a word to the dictionary, increase it's count by 1.
    Don't add strings of numbers.
    '''
    if (not re.match("^\d+$", word)) and len(word) >= Options.min_word_length:
        try:
            Dictionary[word] = Dictionary[word] + 1
        except:
            Dictionary[word] = 1


def text_get_words(str):
    for word in re.findall("[\w]+", str):
        snarf(word)


def html_get_words(str, url):
    soup = BeautifulSoup(str)
    text_get_words(soup.getText())


def check_plain(magic_str, url):
    if not re.match('ASCII', magic_str):
        raise TypeError


def pdf_snarf(body, url):
    result = ''
    if not pdf_snarf.OK:
        return result
    try:
        try:
            p = subprocess.Popen(['pdftotext', '-', '-'],
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 close_fds=True)
        except:
            pdf_snarf.OK = False
            sys.stderr.write('Unable to read pdf text: pdftotext not executable.\n')
            return result
        p.stdin.write(body)
        (text_output, errors) = p.communicate()
        for line in iter(text_output.splitlines()):
            for word in re.findall("[\w]+", line):
                snarf(word)
    except:
        print 'pdftotext grab failed on ' + url
    return result
pdf_snarf.OK = True


def exif_snarf(body, field_names, url):
    result = ''
    if not exif_snarf.OK:
        return result
    try:
        try:
            p = subprocess.Popen(['exiftool', '-'],
                                 stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE,
                                 close_fds=True)
        except:
            exif_snarf.OK = False
            sys.stderr.write('Unable to grab exif data: exiftool not executable.\n')
            return result
        p.stdin.write(body)
        (exif_output, errors) = p.communicate()
        for name in field_names:
            for line in iter(exif_output.splitlines()):
                m = re.match('[^:]*' + 'Comment' + '[^\n]*:([^\n]*)', line)
                if m:
                    for word in re.findall("[\w]+", m.group(1)):
                        snarf(word)
    except:
        print 'Exiftool grab failed on ' + url
    return result
exif_snarf.OK = True


def doc_get_words(body, url):
    exif_snarf(body, ['Author', 'LastSavedBy', 'Creator'], url)
    # consider adding body snarf using


def pdf_get_words(body, url):
    '''Assumes string is a coherent pdf document
    '''
    exif_snarf(body, ['Author'], url)
    pdf_snarf(body, url)


def image_get_words(body, url):
    '''Assumes string is a coherent image file
    '''
    exif_snarf(body, ['Comments'], url)


def do_pass(str):
    pass


def main():
    usage = ("%prog [options] burp-session-file\n"
             "  mine a burp session file for possible passwords\n"
             "  motiviated by digininja's cewl\n")
    parser = OptionParser()
## Depth doesn't make sense since we're not spidering
#
#    parser.add_option("-d","--depth",
#                      action="store", type="int", default = 2,
#                      dest="depth",
#                      help="depth to spider to, default 2")
    parser.add_option("-m", "--min_word_length",
                      action="store", type="int", default=3,
                      dest="min_word_length",
                      help="minimum word length, default 3")
    parser.add_option("-e", "--email",
                      action="store_true", dest="EMAIL", default=False,
                      help="output email addresses")
    parser.add_option("--email_file",
                      action="store", dest="email_file",
                      help="output file for email addresses")
    parser.add_option("-a", "--meta",
                      action="store_true", dest="META", default=False,
                      help="output metadata")
    parser.add_option("--meta-file",
                      action="store", dest="meta_file",
                      help="output file for meta data")
    parser.add_option("-n", "--no-words",
                      action="store_true", dest="no_words",
                      default=False,
                      help="do not output the wordlist")
    parser.add_option("-u", "--urls",
                      action="store_true", dest="list_urls",
                      default=False,
                      help="list visited urls to stderr")
    parser.add_option("-w", "--write",
                      dest="output_file",
                      help="write the words to file")
    parser.add_option("-c", "--count",
                      action="store_true", dest="count", default=False,
                      help="show the count for each of the words found")
    parser.add_option("-v", "--verbose",
                      action="store_true", dest="VERBOSE", default=False,
                      help="verbose")
    parser.add_option("--meta-temp-dir",
                      action="store", dest="meta_temp_dir",
                      help="temporary directory used by " +
                      "ot lineexiftool when parsing file, default /tmp")

    global Options
    global Dictionary

    (Options, args) = parser.parse_args()
    Dictionary = {}

    if len(args) != 1:
        parser.print_usage()
    else:
        vprint("Converting burp session file to xml\n")
        try:
            burp_xml_str = burp_to_xml(args[0], True)
        except:
            print 'burp2xml.py failed to parse session file'
            raise

        content_verify_map = {'text/plain': check_plain}

        action_map = {
            'application/msword': doc_get_words,
            'application/pdf': pdf_get_words,
            'application/vnd.openxmlformats-officedocument'
            '.wordprocessingml.document': doc_get_words,
            'application/x-gzip': do_pass,
            'application/x-shockwave-flash': do_pass,
            'audio/x-wav': do_pass,
            'image/jpeg': image_get_words,
            'image/gif': do_pass,
            'image/png': do_pass,
            'image/x-bitmap': do_pass,
            'text/css': do_pass,
            'text/html': html_get_words,
            'text/plain': text_get_words,
            'none': do_pass,
        }

        # First Get the Request
        while 1:
            try:
                (burp_xml_str, rq_str) = get_tag_content(burp_xml_str,
                                                         'request')
                request = HTTPRequest(rq_str)

            except LookupError:
                break
            try:
                (burp_xml_str, rsp_str) = get_tag_content(burp_xml_str,
                                                          'response')
                rsp_str = remove_CDATA(rsp_str)
                response = http_parse(rsp_str)
                url = request.headers['Host'] + request.path
                type_str = response.getheader('Content-Type','none')
                if type_str == 'none':
                    sys.stderr.write('Document has no content-type ' + url + '\n')
                semi_index = type_str.find(';')
                if semi_index >= 0:
                    type_str = type_str[0:semi_index].lower()
                body_str = response.read()
                magic_str = magic.from_buffer(body_str)
                if Options.list_urls:
                    sys.stderr.write(url + ':' + type_str + '(' +
                                     magic_str + ')\n')
                try:
                    # Check content.  If not verified, TypeError is returned
                    try:
                        content_verify_map[type_str](magic_str)
                    except KeyError:
                        pass
                    action_map[type_str](body_str, url)
                except:
                    pass


            except LookupError:
 #               print "Missing response"
                raise

        if not Options.no_words:
            sorted_words = sorted(Dictionary.iteritems(),
                                  key=operator.itemgetter(1), reverse=True)
            for word_tuple in sorted_words:
                sys.stdout.write(word_tuple[0])
                sys.stdout.write((', ' + str(word_tuple[1]))
                                 if Options.count else '')
                sys.stdout.write('\n')

if __name__ == '__main__':
    main()
