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
# mq_ui_test_driver.py: Python test program for connecting the web UI to the 
# ActiveMQ message queue. Derived from src/am/mq_test_driver.py.
#
import json
import pika
import sys
import uuid
import pymongo
import bson

import cgi
import cgitb
cgitb.enable()

def exit_with_error_message(message) :
        print("Content-Type: application/json")
        print("")
        msg = json.dumps({'status':'error', 'message':message})
        print(msg)
        exit()

mq_conn = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
mq = mq_conn.channel()
mq.queue_declare(queue='maat_requests')

appraiser_address = 'localhost'
appraiser_port = 2342

# Get ids of machine and resource to be used
form = cgi.FieldStorage()
target_id = form.getvalue("machine", None)
resource_id = form.getvalue("resource", None)

if (target_id == None) :
        exit_with_error_message('Target id is Null')
if (resource_id == None) :
        exit_with_error_message('Resource id is Null')

# Get attributes out of db
mc = pymongo.MongoClient('localhost', 27017)
db = mc.maatdb
machines = db.machines
target = machines.find_one({'_id':bson.objectid.ObjectId(target_id)})

resources = db.resources
resource = resources.find_one({'_id':bson.objectid.ObjectId(resource_id)})
mc.close()

if (target == None) :
        exit_with_error_message("Target with id " + target_id + " could not be found in db")
if (resource == None) :
        exit_with_error_message("Resource with id " + resource_id + " could not be found in db")

request_id = uuid.uuid4()

try:
        request = {
                'status': 'ok',
                'request_id': str(request_id),
                'target_address': target['address'],
                'target_port': target['port'],
                'target_fingerprint' : target['fingerprint'],
                'appraiser_address': appraiser_address,
                'appraiser_port': appraiser_port,
                'resource': resource['name'] }
except:
        exit_with_error_message('Target or resource missing field(s) necessary for request contract')

def mq_callback(mq, method, prop, msg):
        mq.close()
        sys.exit(0)

mq.basic_consume(mq_callback, queue='maat_results', no_ack=True)

print("Content-Type: application/json")
print("")

msg = json.dumps(request)
mq.basic_publish(exchange='', routing_key='maat_requests', body=msg)
print(msg)

mq.start_consuming()
