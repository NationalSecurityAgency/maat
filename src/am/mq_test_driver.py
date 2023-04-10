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
# mq_test_driver.py: Python test program for generating MQ commands to
# trigger the mq_client.py script and consume its responses.
#
import json
import pika
import sys
import uuid

mq_conn = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
mq = mq_conn.channel()
mq.queue_declare(queue='maat_requests')

target_address = 'localhost'
target_port = 2342
appraiser_address = 'localhost'
appraiser_port = 2342
resource = "MQ test driver"
fingerprint = "D6:79:C4:82:6A:DE:F4:D0:97:9B:CC:0C:15:9C:37:68:BF:7E:33:34"

if len(sys.argv) > 1:
        target_address = sys.argv[1]
if len(sys.argv) > 2:
        target_port = int(sys.argv[2])
if len(sys.argv) > 3:
        appraiser_address = sys.argv[3]
if len(sys.argv) > 4:
        appraiser_port = int(sys.argv[4])
if len(sys.argv) > 5:
        resource = sys.argv[5]
if len(sys.argv) > 6:
        fingerprint = sys.argv[6]

request_id = uuid.uuid4()

request = {
        'request_id': str(request_id),
        'target_address': target_address,
        'target_port': target_port,
        'appraiser_address': appraiser_address,
        'appraiser_port': appraiser_port,
        'resource': resource, 
        'target_fingerprint': fingerprint
}

def mq_callback(mq, method, prop, msg):
        print('Received result of :', msg)
        mq.close()
        sys.exit(0)

mq.basic_consume(mq_callback, queue='maat_results', no_ack=True)

msg = json.dumps(request)
mq.basic_publish(exchange='', routing_key='maat_requests', body=msg)
print(msg)

mq.start_consuming()
