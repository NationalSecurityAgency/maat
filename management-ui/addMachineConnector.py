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
#

#
# addMachineConnector.py Python script to enable use of addMachineToDatabase.py
# from the UI
# 

import os
import json

import addMachineToDatabase

import cgi
import cgitb
cgitb.enable()

form = cgi.FieldStorage()
args = {}

args['name'] = form.getvalue("name", '')
args['fingerprint'] = form.getvalue("fingerprint", '')
args['ip_address'] = form.getvalue("ip", '')
args['port'] =form.getvalue("port", '')
args['extra'] = None

response = addMachineToDatabase.add_machine(args);

print("Content-type: application/json")
print("")
print(json.dumps(response))
