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
# addCertToDatabase.py Python script to help add certificates to the MongoDB
# 

import argparse
import pymongo

def add_certificate(args):
    
    mc = pymongo.MongoClient('localhost', 27017)
    db = mc.maat
    certificates = db.certificates

    cert_path = args.path; 
    if (args.name):
        cert_name = args.name
    else:
        cert_name = cert_path.rsplit('/', 1)[1]
    
    f = open(cert_path)
    line = f.read()
    f.close()

    my_dict = {"name": cert_name, "certfile": line}
    my_id = certificates.insert(my_dict)
    
    print("certificate with unique id " + str(my_id) + " inserted into the database")

    mc.close()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description = 'Add a certificate to the database')
    parser.add_argument("path", type=str, help="full path of the certificate")
    parser.add_argument("-n", "--name", type=str, help="rename certificate in database")
    args = parser.parse_args()

    add_certificate(args)



    
