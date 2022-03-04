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
# libmaat_client.py: Python equivalent of the libmaat_client library for 
# generating request contracts/parsing response contracts.
#
import xml.etree.ElementTree as ET
from io import StringIO
import struct
import base64

MAAT_CONTRACT_VERSION = "1.0"

def maat_write_sz_buf(fd, data):
        fd.send(struct.pack("!i",len(data)))
        fd.send(struct.pack("%ds" % (len(data),), data))
        return

def maat_read_sz_buf(fd, max_sz):
        ret = b''
        tsz = fd.recv(4)
        if len(tsz) < 4:
                return (0,"")
        size = struct.unpack("!i", tsz)[0]

        if max_sz < 0:
                max_sz = 1000000

        if size > max_sz:
                raise Exception("Size of contract is greater than maximum allowable size")

        while len(ret) < size:
                ret += fd.recv(size - len(ret))

        buf = struct.unpack("%ds" % (size,), ret)[0]
        return (size, buf)

def create_integrity_request(target_type, target_id, target_portnum, 
                             resource=None, nonce=None, tunnel=None, fingerprint=None, info=None):
        #if target_portnum != -1 and tunnel != None:
                #raise Exception("target_portnum != -1 and tunnel != NULL!")

        root = ET.Element("contract", version = MAAT_CONTRACT_VERSION, 
                                                type = "request")

        if target_type == 1:
                node = ET.SubElement(root, "target", type = "host-port")
                ET.SubElement(node, "host").text = target_id
                ET.SubElement(node, "port").text=str(target_portnum)
        else :
                node = ET.SubElement(root, "target", type = str(target_type))


        if resource:
                ET.SubElement(root, "resource").text=resource
       
        if nonce:
                ET.SubElement(root, "nonce").text=nonce


        if tunnel:
                ET.SubElement(root, "tunnel").text=tunnel

        if fingerprint:
                ET.SubElement(root, "cert_fingerprint").text=fingerprint

        if info:
                ET.SubElement(root, "info").text=info

        xml = ET.ElementTree(element=root)

        return ET.tostring(xml.getroot())

def parse_integrity_response(response):
        # Since Python 3.X receives data into a bytestring, we have to
        # convert this to a string for it to be consumable by the Element Tree
        # code. The last character is removed because it is a null byte that
        # is retained in the buffer and is not parsable by the Element Tree code
        response = response.decode('utf-8')
        if response[-1] == '\0':
                response = response[:-1]

        root = ET.fromstring(response)
        target_type = None  
        target_id = None
        result = False
        resource = None
        data = []
        
        if root.tag != 'contract':
                raise Exception("Not a contract file (%s) ?" % (root.tag,))

        for child in root:
                if child.tag.lower() == 'target':
                        #target_type = int(child.attrib['type'])
                        target_type = child.attrib['type']
                        target_id = child.text

                if child.tag.lower() == 'resource':
                        resource = child.text

                if child.tag.lower() == 'result':
                 	if (child.text.lower() == "pass"):
                                result = True

                if child.tag.lower() == 'data':
                        for entry in child:
                                key = None
                                value = None
                                for c2 in entry:
                                        if c2.tag.lower() == 'key':
                                                key = c2.text
                                        if c2.tag.lower() == 'value':
                                                value = base64.b64decode(c2.text)
                                data.append(dict(key=key, value=value))

        return {'target_type': target_type, 'target_id': target_id, 
                'resource': resource, 'result': result, 'data': data }


if __name__ == '__main__':
        xml = create_integrity_request(1, "localhost", 9910, 
                                        resource="debug resource")
        print(xml)

        print(parse_integrity_response(xml))
