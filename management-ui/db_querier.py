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
# db_querier.py: Python program for fetching entries from the database 
# to populate tables in the user interface.
#
import json
from bson.json_util import dumps as bdumps
import sys
import pymongo
import datetime

import cgi
import cgitb
cgitb.enable()

# Get all the contents of the machines collection of the database
# and return as element in dictionary in json form (converted from
# the bson used in mongodb)
def get_all_machines(db) :
        machines = db.machines
        machine_list = []

        # FIXME : dislike time complexity here
        for machine in machines.find():
                machine_list.append(json.loads(bdumps(machine)))

        response = {"status":"ok", "machines":machine_list}

        return response

# Get all the contents of the resources collection of the database
# and return as element in dictionary in json form (converted from
# the bson used in mongodb)
def get_all_resources(db) :
        resources = db.resources
        resource_list = []

        #FIXME time complexity
        for resource in resources.find() :
                resource_list.append(json.loads(bdumps(resource)));

        response = {"status":"ok", "resources": resource_list} 

        return response

# Get the n most recent additions to the measurments collection of the 
# database and return as element in dictionary in json form (converted 
# from the bson used in mongodb)
def get_recent_measurements(db, n) :
        measurements = db.measurements
        measurement_list = []

        # And again
        for measurement in measurements.find().limit(n).sort([("Time",-1)]):
                measurement["Time"] =  str(datetime.datetime.fromtimestamp(measurement["Time"]))
                measurement_list.append(json.loads(bdumps(measurement)));

        response = {"status":"ok", "measurements": measurement_list} 

        return response


if __name__ == "__main__":
        form = cgi.FieldStorage()
        what = form.getvalue("what", "error")

        try :
                mc = pymongo.MongoClient('localhost', 27017)
        except :
                response = {"status":"error", "message":"Connection failed"}
                print("Content-type: application/json")
                print("")
                print(json.dumps(response))
                exit()

        db = mc.maatdb
        if (what == "all_machines") :
                response = get_all_machines(db)
        elif (what == "all_resources") :
                response = get_all_resources(db)
        elif (what == "recent_measurements") :
                response = get_recent_measurements(db, 10)
        else :
                response = {'status': 'error', 'message':'unidentified request'}
        
        mc.close()

        print("Content-type: application/json")
        print("")
        print(json.dumps(response))
