#
# Copyright 2020 United States Government
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import os
import re
import sys
from xml.dom import minidom
from xml.parsers.expat import ExpatError

class am(object):
    def __init__(self):
        self.name = 'none'
        self.interfaces = {"interface":[]}
        self.selector_source = ''
        self.selector_path = ''
        self.privkey = ''
        self.cert = ''
        self.ca = ''
        self.metadata = {"meta":[]}
        self.user = ''
        self.group = ''
        self.work_dir = ''
        self.timeout = ''
        self.collection_name = ''
        self.contracts = {"contract":[]}
        self.entrys = []
        self.collections = { "collection":[]}
        self.rules = { "rule":[]}

def printHeader( ):
    "This Function Prints SPHINX Header to Standard Output"
    print ('.. currentmodule:: maat')
    print ('')
    return

def printAMConfig(am):

    print ('.. _' + am.name + ':\n\n' + am.name)
    print ('---------------------------------\n')
    print ('| Interfaces')
    for interfaces in iter(am.interfaces.values()):
        for i in interfaces:
            if (i["type"] == "inet"):
                print('|        type = inet address = ' + i["address"] + ' port = ' +  i["port"])
            if (i["type"] == "unix"):
                print('|        type = unix path = ' + i['path'])

    print ('| Selector: Source = ' + am.selector_source + ' Path = ' + am.selector_path)
    print ('| Credentials')
    print ('|     Private Key: ' + am.privkey )
    print ('|     Certificate: ' + am.cert )
    print ('|     CA-Certificate: ' + am.ca )
    
    for metadata in iter(am.metadata.values()):
        for m in metadata:
               print ('| Metadata type = ' + m['type'] + ' dir = ' + m['dir'])
    
    print ('| User: ' + am.user )
    print ('| Group: ' + am.group )
    print ('| Work: dir = ' + am.work_dir )
    print ('| Timeout = ' + am.timeout )
    print ('')
    
    return

def parseAMsXml( string, filename ): 
    "Parse Meas Spec XML"
    
    try: 
        parsedams = am(); 
        doc = minidom.parse(string)
        parsedams.name = re.sub(".xml", "", filename)
    except IOError as e:
        print("I/O error ({0}): {1}".format(e.errno, e.strerror))
        return None
    except ExpatError as expatError:
        print("Minidom Parse Error: " + str(expatError) + " when parsing " + filename)
        return None
    except: 
        print("Unexpected error: " + sys.exc_info()[0])
        return None
    
    parsedams = parseAMConfig(parsedams, doc)
    return parsedams

def parseAMConfig(parsedams, doc):
    "Parse AM Config"
    try:
        # Parse AM Config
        interfaces = doc.getElementsByTagName("interfaces")
        for interface in interfaces:
            itf = {}
            if (interface.hasAttribute("type")):                
                itf["type"] = interface.getAttribute("type");
                if (interface.hasAttribute("path")):
                        itf["path"] = interface.getAttribute("path");
                if (interface.hasAttribute("skip-negotiation")):
                        itf["skip-negotiation"] = interface.getAttribute("skip-negotiation");
                if (interface.hasAttribute("address")):
                        itf["address"] = interface.getAttribute("address");
                if (interface.hasAttribute("port")):
                        itf["path"] = interface.getAttribute("path");
                parsedams.interfaces["interface"].append(itf)

        metadata = doc.getElementsByTagName("metadata")
        for meta in metadata:
            m = {}
            if (meta.hasAttribute("type")):
                m["type"] = meta.getAttribute("type");
                if (meta.hasAttribute("dir")):
                        m["dir"] = meta.getAttribute("dir");
                parsedams.metadata["meta"].append(m)

        elmlist = doc.getElementsByTagName("private-key")
        if (len(elmlist) > 0): 
                parsedams.privkey = elmlist[0].firstChild.data
        elmlist = doc.getElementsByTagName("certificate")
        if (len(elmlist) > 0):
                parsedams.cert = elmlist[0].firstChild.data
        elmlist = doc.getElementsByTagName("ca-certificate")
        if (len(elmlist) > 0):
                parsedams.ca = elmlist[0].firstChild.data

        elmlist = doc.getElementsByTagName("user")
        if (len(elmlist) > 0):
                parsedams.user = elmlist[0].firstChild.data
        elmlist = doc.getElementsByTagName("group")
        if (len(elmlist) > 0):
                parsedams.group = elmlist[0].firstChild.data

        elmlist = doc.getElementsByTagName("selector")
        if (len(elmlist) > 0):
            if (elmlist[0].hasAttribute("source")):
                    parsedams.selector_source = elmlist[0].getAttribute("source")
                    paths = elmlist[0].getElementsByTagName("path")
                    if (len(paths) > 0):
                        parsedams.selector_path = paths[0].firstChild.data

        elmlist = doc.getElementsByTagName("work")
        if (elmlist[0].hasAttribute("dir")):
                parsedams.work_dir = elmlist[0].getAttribute("dir")

        elmlist = doc.getElementsByTagName("timeout")
        if (len(elmlist) > 0):
                parsedams.timeout = elmlist[0].firstChild.data

        return parsedams

    except:
        print("Unexpected error While Parsing AM Config : " + sys.exc_info()[0])
        return None


    return parsedams

# Print SPHYNX Header
printHeader()

# Variables
AMLocation = sys.argv[1] 
AMSpecs = []

# Parse and Organize ASPs
for root, directories, files in os.walk(AMLocation):
    for filename in sorted(files):
        if filename.endswith(".xml"):
            parsedams = parseAMsXml(AMLocation + filename, filename);
            if (parsedams is not None):
                AMSpecs.append(parsedams)
    break; # only top folder, break before recursively checking test folders

# Print APBs
for AMSpec in AMSpecs:
    printAMConfig(AMSpec)

