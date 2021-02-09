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
# mq_client.py Python M&A client that sends attestation request contracts 
# based on commands received from an ActiveMQ queue stores results in a MongoDB
# and publishes notifications back to MQ.
# 
import libmaat_client as maatclient
import sys
import argparse
import socket
import struct
import pika
import json
import time
import pymongo


def mq_callback(mq, method, prop, msg):

        print('Received a new request')        
        request = json.loads(msg)
        print(request)

        time_received = time.time()

        if request.get('target_address',None) == None:
                raise Exception("Target host address is not set")

        if request.get('appraiser_address',None) == None:
                raise Exception("Appraiser host address is not set")

        if request.get('resource',None) == None:
                request['resource'] = 'MQ Debug'

        print('Measuring target %s : %d' % (request['target_address'],
                                                        request['target_port']))
        print('Connecting to AM %s : %d' % (request['appraiser_address'],
                                                request['appraiser_port']))

        reqcon = maatclient.create_integrity_request(1, request['target_address'],
                        request['target_port'], resource=request['resource'],
                        fingerprint=request['target_fingerprint'])

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((request['appraiser_address'], request['appraiser_port']))
        print('Sending request.')
        print(reqcon)
        maatclient.maat_write_sz_buf(s, reqcon)
        respsz, resp = maatclient.maat_read_sz_buf(s, -1)
        if resp[-1] == '\0':
                resp = resp[:-1]
        res = maatclient.parse_integrity_response(resp)
        print(res)

        # Create and use a separate connection for this, as long measurements
        # cause the initial connection to time out. 
        mq_conn = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
        mq2 = mq_conn.channel()
        mq2.queue_declare(queue='maat_results')

        print('Sending result %s to MQ' % (res['result'],))
        j = json.dumps({'request_id': request['request_id'], 
                        'time': time_received, 'result': res['result']})
        mq2.basic_publish(exchange='', routing_key='maat_results', body=j)

        print('Send keys to DB')
        mc = pymongo.MongoClient('localhost', 27017)
        db = mc.maatdb
        msmts = db.measurements
        dbentry = {
                'request_id': request['request_id'],
                'Target': res['target_id'],
                'Result': res['result'],
                'Resource': request['resource'],
                'Time': time_received,
                'Data': res['data'],
        }
        m_id = msmts.insert(dbentry)
        mc.close()

        print('Acking')
        #try:
        mq.basic_ack(delivery_tag = method.delivery_tag)
        #except pika.exceptions.ConnectionClosed: 
        #        mq_conn = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
        #        mq = mq_conn.channel()
        #        mq.queue_declare(queue='maat_requests')
        #        mq.basic_ack(delivery_tag = method.delivery_tag)

        print('Waiting for requests...')


if __name__ == '__main__':
        while True:
                mq_conn = pika.BlockingConnection(pika.ConnectionParameters('localhost'))
                mq = mq_conn.channel()
                mq.queue_declare(queue='maat_requests')
                mq.queue_declare(queue='maat_results')

                mq.basic_consume(mq_callback, queue='maat_requests', no_ack=False)
                print('waiting for messages')

                try:
                        mq.start_consuming()
                except pika.exceptions.ConnectionClosed: 
                        print(' Connection closed.. reconencting.')
                        continue



