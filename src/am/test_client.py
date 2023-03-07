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
# test_client.py: Python test program for the libmaat_client.py
#
import libmaat_client as maatclient
import sys
import argparse
import socket
import struct


if __name__ == '__main__':
        parser = argparse.ArgumentParser(
                                description="Request an integrity measurment")
        parser.add_argument('-p','--port', type=int, default=2342)
        parser.add_argument('-t','--target-address', type=str)
        parser.add_argument('-a','--appraiser-port', type=int, default=2342)
        parser.add_argument('-l','--appraiser-address',type=str)
        parser.add_argument('-r','--resource',type=str, default="python debug")
        args = parser.parse_args()

        if args.target_address == None:
                raise Exception("Target host address is not set")

        if args.appraiser_address == None:
                raise Exception("Target host address is not set")

        print('Measuring target %s : %d\n' % (args.target_address,args.port))
        print('Connecting to AM %s : %d\n' % (args.appraiser_address,
                                                            args.appraiser_port))

        request = maatclient.create_integrity_request(1, args.target_address,
                                         args.port, args.resource)

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((args.appraiser_address, args.appraiser_port))
        print('Sending request.')
        print(request)
        #print(type(request))
        #print(len(request))
        #print(len(struct.pack("!i",len(request)+1)))
        #print(struct.pack("%ds" % (len(request)+1), request))
        maatclient.maat_write_sz_buf(s, request)
        #print(s.send(struct.pack("!i",len(request))))
        #print(s.send(struct.pack("%ds" % (len(request)+1), request)))
        print('Waiting on response.')
        respsz, resp = maatclient.maat_read_sz_buf(s, -1)
        print(resp)

        # the response contract is likely to be null terminated.
        # python's XML parser is not happy about that.
        if resp[-1] == '\0':
                resp = resp[:-1]

        print(maatclient.parse_integrity_response(resp))
