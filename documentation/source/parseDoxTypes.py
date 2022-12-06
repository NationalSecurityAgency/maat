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
import re


class header(object):
    def __init__(self):
        self.name = 'none'
        self.structs = {"structs":[]}

def printHeader( ):
    "This Function Prints SPHINX Header to Standard Output"
    print(':tocdepth:')
    print('');
    print ('.. currentmodule:: maat')

    return

def printTypeHeader( filename ):
    "Parse Meas Spec XML"

    #remove redundant naming to keep documentation easier to read
    truncateBytes = 2
    if filename.find('type') > 1:
        truncateBytes = 6
    if filename.find('measurement') > 1:
        truncateBytes = 19

    # Cloud Plugin - allows for section collapse
    print('.. rst-class:: html-toggle');
    print('');

    # Section Header - Level 2 Heading *
    print(filename[:-truncateBytes]);
    #print('*************************************************************');
    print('@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@');
    
    return None

def parseTypes(location, instruction_type, project):
    "organize and parse type"
    for root, directories, files in os.walk(location + instruction_type + '/'):
        for filename in sorted(files):
            if filename.endswith(".h"):
                if filename == "address-spaces.h":
                   continue;    # file is used to register address spaces, not an address space itself
            
                printTypeHeader( filename )
                print('\n');
                print('    .. doxygenfile:: ' + filename);
                print('        :project: ' + project + '\n');
                print('');

                print(".. raw:: latex");
                print("");
                print("    \clearpage")
                print('');

        break; # only top folder, break before recursively checking test folders

    return None  

# Variables
DoxsLocation = sys.argv[1] 
printHeader();
print('');

print("Types");
print("######");

# Print Level 1 Heading #, and Level 1 Description
print("Address Types");
print('--------------------------');
print('');
print('An address_space is basically the type of an address.  Each address');
print('space defines access mechanisms for manipulating addresses of the');
print('space and getting at data in that space.');
print('');
print('For example, file_system would be an address_space that understands');
print('addresses describing the absolute path to a file.');
print('');

parseTypes(DoxsLocation, 'address_space', 'address_space')

print("Measurement Types");
print('-----------------------');
print('');
print('An instance of measurement_type describes how to measure something.');
print('This is used both as part of a measurement directive indicating ');
print('"measure variables of target_type T with measurement type M" and to');
print('describe how we actually measured something "I measured variable V');
print('with measurement type M"');
print('');
print('For some target_types we may only have one meaningful');
print('measurement_type, but for others (e.g., files) we may have multiple');
print('(e.g., hash, fields/lines decomposition).');
print('');
parseTypes(DoxsLocation, 'measurement', ' measurementtypes')

print("Target Types");
print('-------------------------');

print('');
print('An instance of target_type describes some type of target state that');
print('may need to be measured.  This may be a fairly high level type like');
print('"file" or a fairly granular type like "inode".');
print('');
print('A (instance of) target_type combined with an address (below)');
print('uniquely defines a particular piece of target state that may need');
print("to be measured (presumably it does need to be measured if we're");
print('bothering to represent it).  That is, target_type is a meta-type');
print('such that a pair (t : target_type, a : address) represents an');
print('instance of the type t at address a on the target. The type');
print('measurement_variable (below) represents this pair.');
print('');
parseTypes(DoxsLocation, 'target', 'targettypes')


