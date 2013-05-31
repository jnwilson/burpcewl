#! /usr/bin/env python
# Apologies to digininja.
#
# jnw@cise.ufl.edu
'''Use Burp Suite Professional's output to generate a password list

'''

import time
from burp2xml import burp_to_xml
from optparse import OptionParser
import xml.etree.ElementTree as ET

class Namespace: pass

def vprint(arg):
    if globals.VERBOSE:
        print arg

def main():
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
        vprint("Parsing xml file")
        burp_tree = ET.fromstring(burp_xml_string)
        del burp_xml_string # just in case that storage is needed
        requests = burp_tree.findall('request')
        print requests[0]

    
if __name__ == '__main__':
    main()
