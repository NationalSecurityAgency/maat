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
# Demo script to in monitor for the creation of a file /pam_svp_response.raw
# and dump the results into the database.  Used for demo purposes only. 
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
import os
import uuid
import datetime

if __name__ == '__main__':
        print("Waiting for PAM/Maat results")
        while True:
            if os.path.exists("/pam_svp_response.raw"):
                with open("/pam_svp_response.raw", 'r') as pamfile:
                    raw_res = pamfile.read()
                    res = maatclient.parse_integrity_response(raw_res)
                    
                    print('Sending results to DB')
                    mc = pymongo.MongoClient('localhost', 27017)
                    db = mc.maatdb
                    msmts = db.measurements
                    dbentry = {
                            'request_id': str(uuid.uuid4()),
                            'Target': res['target_id'],
                            'Result': res['result'],
                            'Resource': 'userspace',
                            'Time': time.mktime(datetime.datetime.now().timetuple()),
                            'Data': res['data'],
                    }
                    m_id = msmts.insert(dbentry)
                    mc.close()
                os.unlink("/pam_svp_response.raw")
            else:
                time.sleep(1)



