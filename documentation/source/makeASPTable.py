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
    print ('Attestation Service Providers (ASPs)')
    print ('_____________________________________________________\n')
    print ('')
#    print ('.. currentmodule:: maat\n')
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

def printASPTableHeader():
    nc = 20 
    dc = 70
    ic = 70
    oc = 70
    nameColumn = "=" * nc;
    descColumn = "=" * dc;
    inputColumn = "=" * ic;
    outputColumn = "=" * oc;

#    print('.. tabularcolumns:: |p{6.35cm}|p{6.35cm}|p{6.35cm}|\n');

    print('.. table:: ' + "ASPs " + "\n" +
        '\t:widths: 20, 70, 70\n' +
        '\t:column-alignment: left left left \n' +
        '\t:column-wrapping: true true true\n' +
        '\t:column-dividers: single single single single\n' +
        '\n' +
        '\t' + nameColumn + ' '  + descColumn + ' ' + inputColumn + "\n" +
        '\tType' + (" " * (nc-4)) + ' ' + 'Name' + (" " * (dc -4)) + ' Description \n' +
        '\t' + nameColumn + ' '  + descColumn + ' ' + inputColumn)



    #print('\n' +
    #    '   \t' + nameColumn + ' '  + descColumn + ' ' + inputColumn + "\n" +
    #    '   \tName' + (" " * (nc-4)) + ' ' + 'Description' + (" " * (dc -11)) + ' Type \n' +
    #    '   \t' + nameColumn + ' '  + descColumn + ' ' + inputColumn)


    return

def printASPTableFooter():
    nc = 20
    dc = 70
    ic = 70 
    oc = 70
    nameColumn = "=" * nc;
    descColumn = "=" * dc;
    inputColumn = "=" * ic;
    outputColumn = "=" * oc;

    print('   \t' + nameColumn + ' ' + descColumn + ' ' + inputColumn + "\n");

    return


def printASPsTable(title, asps):
    "Print Table of list of asps provided with Name, Description, Input and Ouptut as Columns"
    nc = 20
    dc = 70
    ic = 70
    oc = 70
    nameColumn = "=" * nc;
    descColumn = "=" * dc;
    inputColumn = "=" * ic; 
    outputColumn = "=" * oc;

#    print('.. table:: ' + title + "\n" +
#        '\t:widths: 1 1 1\n' +
#        '\t:column-alignment: left left left \n' +
#        '\t:column-wrapping: true true true\n' +
#        '\t:column-dividers: single single single single\n' +
#        '\n' +
#        '\t' + nameColumn + ' '  + descColumn + ' ' + inputColumn + "\n" +
#        '\tName' + (" " * (nc-4)) + ' ' + 'Description' + (" " * (dc -11)) + ' Type \n' + 
#        '\t' + nameColumn + ' '  + descColumn + ' ' + inputColumn)

    for asp in asps:       
        # Build Table contents
        # ASP has up to 4 rows
        # Row 1 -> ASP Name, Desc(0.50), graph{, graph{
        # Row 2 -> ,Desc(50,100), address_space, measurement_type
        # Row 3 -> ,Desc(100,101), target_type, }
        # Row 4 -> ,Desc(101,150), } nodeid, 
        # Sphynx may combine some of these fields to reduce rows

        # build row 1
        name = " " * ic     # Pad name field, so table lines up
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
        btype = " " * nc
        atype = asp.aspType + btype[len(asp.aspType):] + " "
        if (meas != ""):
            tmp = "measurement: " + meas 
        else: 
            tmp = ''
        out = tmp + out[len(tmp):]        
        row1 = "\t"+  atype + name + desc

        # build row 2
        name = " " * ic     # No Name in Row 2
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
        atype = " " * nc
        row2 = "\t" + atype + " " + name + desc

        # build row 3
        name = " " * ic     # No Name in Row 3
        name = name + " "
        desc = " " * dc     # Pad desc field, so table lines up
        adesc = asp.desc[2*dc:3*dc].lstrip()
        adesc = adesc.replace("\n","");
        adesc = adesc.replace("\t","");
        desc = adesc + desc[len(adesc):] + " "
        inp = " " 
        out = " "
        atype = " " * nc
        row3 = "\t" + atype + " " + name + desc

        # build row 4
        name = " " * ic     # No Name in Row 4
        name = name + " "
        desc = " " * dc     # Pad desc field, so table lines up
        adesc = asp.desc[3*dc:4*dc].lstrip()
        adesc = adesc.replace("\t", "");
        adesc = adesc.replace("\n","");
        desc = adesc + desc[len(adesc):] + "  "
        inp = " "
        out = " " 
        atype = " " * nc
        row4 = "\t" + atype + " " + name + desc

        print("   " + row1);
        print("   " + row2);
        print("   " + row3);
        print("   " + row4);

#    print('\t' + nameColumn + ' ' + descColumn + ' ' + inputColumn + "\n");

    return

def printASPInfo(asp):
    "Print XML Info"
    print('.. rst-class:: html-toggle');

    print ('.. _' + asp.uuid + ':\n\n' + asp.name)
    print ('*********************************************************')
    if (asp.targettype != ''):
        asp.detaileddesc = asp.detaileddesc.replace(asp.targettype, """:ref:`""" + asp.targettype + """ <""" + "Magic" + asp.targetmagic + """>`""")
    if (asp.addrtype != ''):
        asp.detaileddesc = asp.detaileddesc.replace(asp.addrtype, """:ref:`""" + asp.addrtype + """ <""" + "Magic" + asp.addrmagic + """>`""")
    if (asp.meastype != ''):
        asp.detaileddesc = asp.detaileddesc.replace(asp.meastype, """:ref:`""" + asp.meastype + """ <""" + "Magic" + asp.measmagic + """>`""")                
    print(asp.detaileddesc);

    print("Usage: ");
    print(asp.usage);
    print("Description: \n");
    print("\t" + asp.desc + "\n");
    print("Input Description: " );
    print(asp.inpdesc);
    print("Output Description: ");
    print(asp.outdesc);
    if (asp.example != ''):
        print("Example:: ");
        print(asp.example);
    print(".. seealso::");
    print(asp.seealso);

    print('| Filename: ' +  asp.filename + '.c')
    print('| UUID: ' +  asp.uuid)
    print('| Description: \n| \t' + asp.desc) 
    print('| Measurers: ')
    for name in asp.measurers:        
        print('| \t' + name)
    if (asp.measurersdesc != ''):
        print("| \t\tNote: " + asp.measurersdesc);
    print('| \tCapabilities:');
    if (asp.targetmagic != ''):
        print("| \t\tTarget Type: " + makeUrlLink(asp.targettype, asp.targetmagic));
        if (asp.targetdesc != ''):
                print("| \t\t\t\tDescription: " + asp.targetdesc)
    if (asp.addrmagic != '' ):
        print("| \t\tAddress Type: " + makeUrlLink(asp.addrtype, asp.addrmagic));
        if (asp.addrdesc != ''):
                print("| \t\t\t\tDescription: " + asp.addrdesc)
    if (asp.measmagic != ''):
        print("| \t\tMeasurement Type: " + makeUrlLink(asp.meastype, asp.measmagic));
        if (asp.measdesc != ''):
                print("| \t\t\t\tDescription: " + asp.measdesc)
        if (asp.feature != ''):
            print("| \t\t\t\tFeature: " + asp.feature)

    print("| Security: ")
    print('| \tType: ' + asp.selinuxtype)
    print('| \tUser: ' + asp.user)
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
        print("Parse ASP Error for: " + filepath)
        error_msg = ErrorString(expatError.code)
        error_msg += ' at line ' + str(expatError.lineno) + ' column ' + str(expatError.offset)
        print(error_msg);
        return None
    except AttributeError as ae:
        print(ae)
        return None
    except:
        print("Parse ASP: " + filepath + " Unexpected error:" + sys.exc_info()[0])
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
        print(ae)
        return None
    except:
        print("Unexpected error: " + sys.exc_info()[0])
        return None

    return parsedasp

# Print SPHYNX Header
printHeader()

# Parse and Organize ASPs
for root, directories, files in os.walk(ASPsLocation):
    for filename in sorted(files):
        if filename.endswith(".xml"):
            #print("Parsing File :" + filename + "\n");
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

printASPTableHeader();

printASPsTable("Appraisal ASPs", appraisalAsps);
printASPsTable("File ASPs", fileAsps);
printASPsTable("Kernel ASPs", kernelAsps);
printASPsTable("Network ASPs", networkAsps);
printASPsTable("Process ASPs", processAsps);
printASPsTable("System ASPs", systemAsps);

printASPTableFooter();
