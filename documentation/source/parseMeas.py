#
# Copyright 2023 United States Government
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

class meas(object):
    def __init__(self):
        self.name = 'none'
        self.desc = ''
        self.uuid = ''
        self.measfile = ''
        self.instructions = { "instruction":[]}
        self.variables = { "variable":[]}

def printHeader( ):
    "This Function Prints SPHINX Header to Standard Output"
    print ('Maat Measurement Specifications')
    print ('===============================\n')
    print ('.. currentmodule:: maat')
    print ('')
    print ('Measurement Specifications define exactly what evidence' + 
           ' the requester requires for a specific scenario. Separating the' +
           ' evidence requirements from the protocol needed to collect and' +
           ' transmit evidence (APBs) allows the construction of generic' +
           ' APBs that can be re-used for multiple attestation scenarios.' + 
           ' Like APBs, Measurement Specifications are registered with' +
           ' the AM and are identified by a well-known UUID.')
    print ('')
    return

def printMeasInfo(meas):
    "Print Meas Info for each Type"
    print ('.. _' + meas.uuid + ':\n\n' + meas.name)
    print ('-----------------------------------\n')
    print('| UUID: ' +  meas.uuid)
    print('| Description: \n| \t' + meas.desc)
    print('| Instructions:')
    for values in iter(meas.instructions.values()):
        for value in values:
            print("|\tName: " + value["name"] + ", Type: " + value["type"])
            if (value["target_type_name"] != ''):
                print("""|\t\tTarget Type: :ref:`""" + value["target_type_name"] + """ <""" + "Magic" + value["target_type_magic"] + """>`""")
            if (value["address_type_name"] != ''):
                print("""|\t\tAddress Type: :ref:`""" + value["address_type_name"] + """ <""" + "Magic" + value["address_type_magic"] + """>`""")
            if (value["meas_type_name"] != ''):
                print("""|\t\tMeasurement Type: :ref:`""" + value["meas_type_name"] + """ <""" + "Magic" + value["meas_type_magic"]  + """>`""")
            if (value["action_feature"] != ''):
                print("|\t\t" + "Feature: " + value["action_feature"] + ", Instruction: " + value["action_instruction"])

    print('')
    print('| Variables:')
    for values in iter(meas.variables.values()):
        for value in values:
            print("|\t Instruction:" + value["instruction"] + ", Scope: " + value["scope"])
            for addr,opr in value["address"]:
                print("|\t\tAddress: " + addr + ", Operation: " + opr)

    print('')
    return

def parseMeasXml( string ): 
    "Parse Meas Spec XML"
    doc = parseXml(string);
    if (doc is not None):
        parsedmeas = parseMeasFields(doc)
        return parsedmeas

    return None

def parseXml( path ):
    "minidom xml parsing"

    try:
        doc = minidom.parse(path)
        return doc
    except IOError as e:
        print("I/O error ({0}): {1}".format(e.errno, e.strerror))
        return None
    except ExpatError as expatError:
        print("Minidom Parse Error: " + str(expatError) + " when parsing " + path)
        return None
    except:
        print("Unexpected error: " + sys.exc_info()[0])
        return None


def parseMeasFields(doc):
    parsedmeas = meas();

    parsedmeas = parseNameDesc(doc, parsedmeas);
    if (parsedmeas is not None):
        parsedmeas = parseInstr(doc, parsedmeas);
        if (parsedmeas is not None): 
            parsedmeas = parseVar(doc, parsedmeas);

    return parsedmeas;

def parseNameDesc(doc, parsedmeas):
    try:
        field = doc.getElementsByTagName("name")[0]
        name = re.sub('measurement_specification', '', field.firstChild.data)
        parsedmeas.name = re.sub('measurement specification', '', name)
        field = doc.getElementsByTagName("uuid")[0]
        parsedmeas.uuid = field.firstChild.data
        field = doc.getElementsByTagName("description")[0]
        parsedmeas.desc = field.firstChild.data
        return parsedmeas;
    except:
        print("Mesaurement Specification Error: " + sys.exc_info()[0])
        return None

def parseInstr(doc, parsedmeas):
    try: 
        instructions = doc.getElementsByTagName("instruction")
        # there can be multiple instructions, but each instruction can only have a single 
        # target type, address type, measurement type, action type
        # if there are multiple, the parsed instruction will use the last instance
        for instruction in instructions:
            entry = {}
            entry["type"] = instruction.getAttribute("type")
            entry["name"] = instruction.getAttribute("name")
            entry["target_type_name"] = ""
            entry["target_type_magic"] = ""
            targettypes = instruction.getElementsByTagName("target_type")
            for targettype in targettypes:
                entry["target_type_name"] = targettype.getAttribute("name")
                entry["target_type_magic"] = targettype.getAttribute("magic")
        
            entry["address_type_name"] = ""
            entry["address_type_magic"] = ""
            addresstypes = instruction.getElementsByTagName("address_type")
            for addresstype in addresstypes:
                entry["address_type_name"] = addresstype.getAttribute("name")
                entry["address_type_magic"] = addresstype.getAttribute("magic")
        
            entry["meas_type_name"] = ""
            entry["meas_type_magic"] = ""
            meastypes = instruction.getElementsByTagName("measurement_type")
            for meastype in meastypes:
                entry["meas_type_name"] = meastype.getAttribute("name")
                entry["meas_type_magic"] = meastype.getAttribute("magic")

            entry["action_feature"] = ""
            entry["action_instruction"] = ""
            actiontypes = instruction.getElementsByTagName("action")
            for actiontype in actiontypes:
                entry["action_feature"] = actiontype.getAttribute("feature")
                entry["action_instruction"] = actiontype.getAttribute("instruction")
            parsedmeas.instructions["instruction"].append(entry)
        return parsedmeas;
    except:
        print("Unexpected error: " + sys.exc_info()[0])
        return None;

def parseVar(doc, parsedmeas):
    try:
        variables = doc.getElementsByTagName("variable")
        for variable in variables:
            entry = {}
            entry["instruction"] = variable.getAttribute("instruction")
            entry["scope"] = variable.getAttribute("scope")

            addrlist = []
            addresstypes = variable.getElementsByTagName("address")
            for address in addresstypes:
                addr = address.firstChild.data
                opr = address.getAttribute("operation")
                addrtuple = (addr, opr)
                addrlist.append(addrtuple)

            entry["address"] = addrlist                

            parsedmeas.variables["variable"].append(entry)

    except:
        print("Unexpected error: " + sys.exc_info()[0])
        return None

    return parsedmeas

# Print SPHYNX Header
printHeader()

# Variables
MeasLocation = sys.argv[1] 
MeasSpecs = []

# Parse and Organize ASPs
for root, directories, files in os.walk(MeasLocation):
    for filename in files:
        if filename.endswith(".xml"):
            parsedmeas = parseMeasXml(MeasLocation + filename);
            if (parsedmeas is not None):
                MeasSpecs.append(parsedmeas)
    break; # only top folder, break before recursively checking test folders

# Print APBs
for MeasSpec in MeasSpecs:
    printMeasInfo(MeasSpec)

