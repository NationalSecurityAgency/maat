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
# addMachineToDatabase.py Python script to help add machines to the MongoDB
# 

import argparse
import socket
import pymongo
import json

import attribute_utils

# Validate Ip address TODO: what's the best way to do this?
def validate_ip(ip):
        socket.inet_aton(ip)

def add_machine(attrs):
        # Make sure name and fingerprint are not empty
        attrs['name'] = attrs['name'].strip()
        if (attrs['name'] == ''):
                return {"status":"error", "message":"Error: Name of Machine cannot be empty"}
        attrs['fingerprint'] = attrs['fingerprint'].strip()
        if (attrs['fingerprint'] == ''):
                return {"status":"error", "message":"Error: Fingerprint of machine certificate cannot be empty"}

        db_entry = {
                'name': attrs['name'],
                'fingerprint':attrs['fingerprint'],
                'address': str(attrs['ip_address']),
                'port': str(attrs['port'])
        }
        if (attrs['extra'] != None) :
                db_entry = attribute_utils.parse_extra(db_entry, attrs['extra']);

        if (attribute_utils.dict_contains_html(db_entry)):
                return {"status":"error", "message":"Error: HTML not acceptable for input fields"}

        # Validate port and ip
        try:
                db_entry['port'] = db_entry['port'].strip()
                db_entry['address'] = db_entry['address'].strip()

                db_entry['port'] = int(db_entry['port'])
                validate_ip(db_entry['address'])

        except ValueError:
                return {"status":"error", "message":"Error: Port of Machine must be integer"}
        except socket.error:
                return {"status":"error", "message":"Error: Invalid IP"}

        mc = pymongo.MongoClient('localhost', 27017)
        db = mc.maatdb
        machines = db.machines
        
        # Everything good, add to db
        # XXX: Could add multiple machines with same credentials (unique _ids though)
        m_id = machines.insert(db_entry)
        
        response = {
                'status':'ok', 
                'message': "Machine with unique id: " + str(m_id) + " inserted into database"
        }

        mc.close()
        
        return response
        


if __name__ == "__main__":
        parser = argparse.ArgumentParser(description='Add a new machine to the database')
        parser.add_argument('name', metavar='n', help='name of the machine')
        parser.add_argument('fingerprint', metavar='f', help='fingerprint of machine cert')
        parser.add_argument('ip_address', metavar='a', type=str, help='ip address of the machine')
        parser.add_argument('port', metavar='p', type=int, help="port machine's AM is listening on")
        parser.add_argument('-e', '--extra', type=json.loads, help="other attributes as json (in single quotes)")
        args = vars(parser.parse_args())

        result = add_machine(args)
        
        print(result['message'])

