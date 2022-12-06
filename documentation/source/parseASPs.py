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
import sys
from xml.dom import minidom
from xml.parsers.expat import ExpatError, ErrorString

class asp(object):
    def __init__(self):
        self.name = 'none'
        self.uuid = ''
        self.aspType = ''
        self.desc = ''
        self.detaileddesc = ''
        self.inpdesc = ''
        self.outdesc = ''
        self.usage = ''
        self.aspfile = ''
        self.measurers = []
        self.measurersdesc = ''
        self.targettype = ''
        self.targetmagic = ''
        self.targetdesc = ''
        self.addrtype = ''
        self.addrmagic = ''
        self.addrdesc = ''
        self.meastype = ''
        self.measmagic =''
        self.measdesc = ''
        self.feature = ''
        self.filename = ''
        self.selinuxtype = ''
        self.seealso = ''
        self.example = ''
        self.user = ''

# Variables
ASPsLocation = sys.argv[1]
allAsps = []
demoAsps = []
networkAsps = []
fileAsps = []
processAsps = []
systemAsps = []
appraisalAsps = []
kernelAsps = []


def printHeader( ):
    "This Function Prints SPHINX Header to Standard Output"
    print ('=============================================')
    print ('Attestation Service Providers (ASPs)')
    print ('=============================================')
    print ('')
    print ('.. currentmodule:: maat\n')
    print ('Attestation Service Providers (ASPs) are the basic func' + 
            'tional unit of Maat. Each ASP performs a specific, discrete' +
            ' function in evidence collection tasks. An ASP may be a' + 
            ' measurement agent responsible for gathering a specific piece' + 
            ' of evidence from the system. An ASP may also be a evaluation' + 
            ' unit that ingests some type of evidence and contributes to an' +
            ' assessment of the target\'s integrity. Other ASPs may provide' +
            ' post-processing functions such as hashing or compression, or' +
            ' call out to external components such as another AM or an' + 
            ' existing service.\n')

    return

def makeASPLink(name, uuid):
    "Helper Function to create url link giving name and magic number"
    if (name == ""):
        return "";

    return """:ref:`""" + name + """ <""" + uuid + """>`"""


def makeUrlLink(name, magic):
    "Helper Function to create url link giving name and magic number"
    if (name == ""):
        return "";
    return """:ref:`""" + name + """ <Magic""" + magic + """>`"""


def printASPsTable(title, asps):
    "Print Table of list of asps provided with Name, Description, Input and Ouptut as Columns"
    nc = 70
    dc = 50
    ic = 70
    oc = 70
    nameColumn = "=" * nc;
    descColumn = "=" * dc;
    inputColumn = "=" * ic; 
    outputColumn = "=" * oc;

    print('.. table:: ' + title + "\n" +
        '\t:widths: 1 1 1 1\n' +
        '\t:column-alignment: left left left left\n' +
        '\t:column-wrapping: true true true true\n' +
        '\t:column-dividers: single single single single single\n' +
        '\n' +
        '\t' + nameColumn + ' '  + descColumn + ' ' + inputColumn + ' ' + outputColumn + "\n" +
        '\tName' + (" " * (nc-4)) + ' ' + 'Description' + (" " * (dc -11)) + ' ' + 'Input' + (" " * (ic-5)) + ' ' + 'Output \n' + 
        '\t' + nameColumn + ' '  + descColumn + ' ' + inputColumn + ' ' + outputColumn)

    for asp in asps:       
        # Build Table contents
        # ASP has up to 4 rows
        # Row 1 -> ASP Name, Desc(0.50), graph{, graph{
        # Row 2 -> ,Desc(50,100), address_space, measurement_type
        # Row 3 -> ,Desc(100,101), target_type, }
        # Row 4 -> ,Desc(101,150), } nodeid, 
        # Sphynx may combine some of these fields to reduce rows

        # build row 1
        name = " " * nc     # Pad name field, so table lines up
        asplink = makeASPLink(asp.name, asp.uuid)
        name = asplink + name[len(asplink):] + " "
        desc = " " * dc     # Pad desc field, so table lines up
        adesc = asp.desc[0:dc].lstrip()
        adesc = adesc.replace("\n","");
        adesc = adesc.replace("\t", "");
        desc = adesc + desc[len(adesc):] + " "
        inp = " " * ic
        addr = makeUrlLink(asp.addrtype, asp.addrmagic)
        tmp = "graph {" + addr
        inp = tmp + inp[len(tmp):] + " "
        out = " " * oc
        meas = makeUrlLink(asp.meastype, asp.measmagic)
        if (meas != ""):
            tmp = "measurement: " + meas 
        else: 
            tmp = ''
        out = tmp + out[len(tmp):]        
        row1 = "\t" + name + desc + inp + out

        # build row 2
        name = " " * nc     # No Name in Row 2
        name = name + " "
        desc = " " * dc     # Pad desc field, so table lines up
        adesc = asp.desc[dc:dc*2].lstrip()
        adesc = adesc.replace("\n",""); 
        adesc = adesc.replace("\t", "");
        desc = adesc + desc[len(adesc):] + " "
        inp = " " * ic
        target = makeUrlLink(asp.targettype, asp.targetmagic)
        tmp = ", " + target + "}, nodeid"
        inp = tmp + inp[len(tmp):]
        if (meas != ""):
            out = " added to input node "
        else:
            out = ' '
        row2 = "\t" + name + desc + inp + out

        # build row 3
        name = " " * nc     # No Name in Row 3
        name = name + " "
        desc = " " * dc     # Pad desc field, so table lines up
        adesc = asp.desc[2*dc:3*dc].lstrip()
        adesc = adesc.replace("\n","");
        adesc = adesc.replace("\t","");
        desc = adesc + desc[len(adesc):] + " "
        inp = " " 
        out = " "
        row3 = "\t" + name + desc + inp + out

        # build row 4
        name = " " * nc     # No Name in Row 4
        name = name + " "
        desc = " " * dc     # Pad desc field, so table lines up
        adesc = asp.desc[3*dc:4*dc].lstrip()
        adesc = adesc.replace("\t", "");
        adesc = adesc.replace("\n","");
        desc = adesc + desc[len(adesc):] + "  "
        inp = " "
        out = " " 
        row4 = "\t" + name + desc + inp + out

        print(row1);
        print(row2);
        print(row3);
        print(row4);

    print('\t' + nameColumn + ' ' + descColumn + ' ' + inputColumn + ' ' + outputColumn + "\n");

    return

def printASPInfo(asp):
    "Print XML Info"
    
    print('.. rst-class:: html-toggle');
    print ('')
    print ('.. _' + asp.uuid + ':')
    print ('')
    #print ('========================================================')
    print (asp.name)
    print ('---------------------------------------------------------')
    if (asp.targettype != ''):
        asp.detaileddesc = asp.detaileddesc.replace(asp.targettype, """:ref:`""" + asp.targettype + """ <""" + "Magic" + asp.targetmagic + """>`""")
    if (asp.addrtype != ''):
        asp.detaileddesc = asp.detaileddesc.replace(asp.addrtype, """:ref:`""" + asp.addrtype + """ <""" + "Magic" + asp.addrmagic + """>`""")
    if (asp.meastype != ''):
        asp.detaileddesc = asp.detaileddesc.replace(asp.meastype, """:ref:`""" + asp.meastype + """ <""" + "Magic" + asp.measmagic + """>`""")                

    print("\nUsage: ");
    print(asp.usage);
    print("\nDescription: \n");
    print("\t" + asp.desc + "\n");
    print("\nInput Description: " );
    print(asp.inpdesc);
    print("\nOutput Description: ");
    print(asp.outdesc);
    if (asp.example != ''):
        print("\nExample:: ");
        print(asp.example);
    if (asp.seealso != ''):
        print("\n.. seealso::");
        print(asp.seealso);

    print("\n");
    print(".. raw:: latex");
    print("");
    print("    \clearpage")

    print('')
    return

def parseASPXml( filepath ): 
    "Parse ASP XML"
    doc = parseXml( filepath );
    if (doc is not None):
        parsedasp = parseASPFields(doc)
        return parsedasp

    return None

def getElementData(minidoc, fieldname):
    "Get first child data of element matching fieldname (if present)"
    fs = minidoc.getElementsByTagName(fieldname)
    if (fs.length > 0):
        return minidoc.getElementsByTagName(fieldname)[0].firstChild.data
        
    return ""


def parseXml( filepath ):
    "minidom xml parsing"
    try:
        doc = minidom.parse(filepath)
        return doc
    except IOError as e:
        print("I/O error ({0}): {1}".format(e.errno, e.strerror))
        return None
    except ExpatError as expatError:
        print("Minidom Parse Error: " + str(expatError) + " when parsing " + filepath)
        return None
    except AttributeError as ae:
        print("Attribute error " + str(ae) + " when parsing file " + filepath)
        print(ae)
        return None
    except:
        print("Error parsing file: " + filepath)
        print("Unexpected error: " + sys.exc_info()[0])
        return None

def parseASPFields(doc):
    "Parse ASP Fields from minidom xml object"
    parsedasp = asp(); 

    try:
        # ASP meta data
        parsedasp.name =          getElementData(doc, "name")
        parsedasp.uuid =          getElementData(doc, "uuid")
        parsedasp.aspType =       getElementData(doc, "type")
        parsedasp.filename =      getElementData(doc, "aspfile")

        # ASP documentation
        parsedasp.detaileddesc =  getElementData(doc, "detaileddescription")
        parsedasp.desc =          getElementData(doc, "description")
        parsedasp.example =       getElementData(doc, "example")
        parsedasp.usage =         getElementData(doc, "usage")
        parsedasp.inpdesc =       getElementData(doc, "inputdescription")
        parsedasp.outdesc =       getElementData(doc, "outputdescription")
        parsedasp.seealso =       getElementData(doc, "seealso").replace(" ", "\n\n\t\t")

        measurers = doc.getElementsByTagName("measurers")[0]
        satisfiers = measurers.getElementsByTagName("satisfier")
        if (satisfiers.length > 0):
            satisfier = measurers.getElementsByTagName("satisfier")[0]
            measurersdesc = measurers.getElementsByTagName("description")
            if (measurersdesc.length > 0):
                d = measurers.getElementsByTagName("description")[0]
                parsedasp.measurersdesc = d.firstChild.data
            measnames = satisfier.getElementsByTagName("value")
            for name in measnames:
                parsedasp.measurers.append(name.firstChild.data)
            capabilities = satisfier.getElementsByTagName("capability")
            for capability in capabilities:
                if (capability.hasAttribute("target_type")):
                    parsedasp.targettype = capability.getAttribute("target_type")
                    if (capability.hasAttribute("target_desc")):
                        parsedasp.targetdesc = capability.getAttribute("target_desc")
                if (capability.hasAttribute("target_magic")):
                    parsedasp.targetmagic = capability.getAttribute("target_magic")
                if (capability.hasAttribute("address_type")):
                    parsedasp.addrtype = capability.getAttribute("address_type")
                    if (capability.hasAttribute("address_desc")):
                        parsedasp.addrdesc = capability.getAttribute("address_desc")
                if (capability.hasAttribute("address_magic")):
                    parsedasp.addrmagic = capability.getAttribute("address_magic")
                if (capability.hasAttribute("measurement_type")):
                    parsedasp.meastype = capability.getAttribute("measurement_type")
                    if (capability.hasAttribute("measurement_desc")):
                        parsedasp.measdesc = capability.getAttribute("measurement_desc")
                if (capability.hasAttribute("measurement_magic")):
                    parsedasp.measmagic = capability.getAttribute("measurement_magic")
                if (capability.hasAttribute("attribute")):
                    parsedasp.feature = capability.getAttribute("attribute")

        # update links
        if (parsedasp.targettype != ''):
                parsedasp.inpdesc = parsedasp.inpdesc.replace(parsedasp.targettype, """:ref:`""" + parsedasp.targettype + """ <""" + "Magic" + parsedasp.targetmagic + """>`""")
        if (parsedasp.addrtype != ''):
                parsedasp.inpdesc = parsedasp.inpdesc.replace(parsedasp.addrtype, """:ref:`""" + parsedasp.addrtype + """ <""" + "Magic" + parsedasp.addrmagic + """>`""")

        if (parsedasp.meastype != ''):
                parsedasp.outdesc = parsedasp.outdesc.replace(parsedasp.meastype, """:ref:`""" + parsedasp.meastype + """ <""" + "Magic" + parsedasp.measmagic + """>`""")


        securitys = doc.getElementsByTagName("security_context")
        for security in securitys:
            selinux = security.getElementsByTagName("selinux")
            if (selinux.length > 0):
                selinux = security.getElementsByTagName("selinux")[0]
                types = selinux.getElementsByTagName("type")
                if (types.length > 0):
                    field = selinux.getElementsByTagName("type")[0]           
                    parsedasp.selinuxtype = field.firstChild.data
            user = security.getElementsByTagName("user")
            if (user.length > 0):
                field = security.getElementsByTagName("user")[0]
                parsedasp.user = field.firstChild.data

            return parsedasp

    except AttributeError as ae:
        print("ASP: " + parsedasp.name + " Attribute Error" + ae)
        return None
    except:
        print("ASP: " + parsedasp.name + " Unexpected error: " + sys.exc_info()[0])
        return None

    return parsedasp

# Print SPHYNX Header
printHeader()

# Variables

# Parse and Organize ASPs
for root, directories, files in os.walk(ASPsLocation):
    for filename in sorted(files):
        if filename.endswith(".xml"):
            parsedasp = parseASPXml(ASPsLocation + filename);
            if parsedasp is None:
                break;
            allAsps.append(parsedasp)
            if parsedasp.aspType == "Appraisal":
                appraisalAsps.append(parsedasp)
            if parsedasp.aspType == "Demonstration":
                demoAsps.append(parsedasp)
            if parsedasp.aspType == "Kernel":
                kernelAsps.append(parsedasp)
            if parsedasp.aspType == "Network":
                networkAsps.append(parsedasp)          
            if parsedasp.aspType == "File":
                fileAsps.append(parsedasp)
            if parsedasp.aspType == "Process":
                processAsps.append(parsedasp)
            if parsedasp.aspType == "System":
                systemAsps.append(parsedasp)
    break; # only top folder, break before recursively checking test folders

# Cloud Plugin - allows for section collapse
print('.. rst-class:: html-toggle');
print('');
#print('*******************************************')
print('Appraisal')
print('============================================')
printASPsTable("Appraisal ASPs", appraisalAsps);
for asp_object in appraisalAsps:
    printASPInfo(asp_object)

#printASPsTable("Demonstation ASPs", demoAsps);
#print("Demonstration\n-------------------------------\n")
#for asp_object in demoAsps:
#    printASPInfo(asp_object)

# Cloud Plugin - allows for section collapse
print('.. rst-class:: html-toggle');
print('');
#print('*******************************************')
print('File')
print('============================================')
printASPsTable("File ASPs", fileAsps);
for asp_object in fileAsps:
    printASPInfo(asp_object)

# Cloud Pluggin - allows for section collapse
print('.. rst-class:: html-toggle');
print('')
#print('*******************************************')
print('Kernel')
print('============================================')
printASPsTable("Kernel ASPs", kernelAsps);
for asp_object in kernelAsps:
    printASPInfo(asp_object)

# Cloud Plugin - allows for section collapse
print('.. rst-class:: html-toggle');
print('')
#print('*******************************************')
print('Network')
print('============================================')
printASPsTable("Network ASPs", networkAsps);
for asp_object in networkAsps:
    printASPInfo(asp_object)

# Cloud Plugin - allows for section collapse
print('.. rst-class:: html-toggle');
print('')
#print('*******************************************')
print('Process')
print('============================================')
printASPsTable("Process ASPs", processAsps);
for asp_object in processAsps:
    printASPInfo(asp_object)

# Cloud Plugin - allows for section collapse
print('.. rst-class:: html-toggle');
print('')
#print('*******************************************')
print('System')
print('============================================')
printASPsTable("System ASPs", systemAsps);
for asp_object in systemAsps:
    printASPInfo(asp_object)

