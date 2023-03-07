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
#

#
# addResourceToDatabase.py Python script to help add resources to the MongoDB
# 

import argparse
import pymongo
import json

import attribute_utils

def add_resource(attrs):
        # Make sure name is not empty
        attrs['name'] = attrs['name'].strip()
        if (attrs['name'] == ''):
                return {"status":"error", "message":"Error: Name of Resource cannot be empty"}

        db_entry = {
                'name': attrs['name']
        }
        if (attrs['extra'] != None) :
                db_entry = attribute_utils.parse_extra(db_entry, attrs['extra']);

        if (attribute_utils.dict_contains_html(db_entry)):
                return {"status":"error", "message":"Error: HTML not acceptable for input fields"}

        mc = pymongo.MongoClient('localhost', 27017)
        db = mc.maatdb
        resources = db.resources

        # Everything good, add to db
        m_id = resources.insert(db_entry)
        response = {
                'status': 'ok',
                'message':"Resource with unique id : " + str(m_id) + " inserted into database"
        }

        mc.close()

        return response

if __name__ == "__main__":
        parser = argparse.ArgumentParser(description='Add a new resource to the database')
        parser.add_argument('name', metavar='n', help='name of the resource')
        parser.add_argument('-e', '--extra', type=json.loads, help="other attributes as json (and in single quotes)")
        args = vars(parser.parse_args())

        result = add_resource(args)
        
        print(result['message'])
