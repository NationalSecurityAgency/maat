# Copyright 2022 United States Government
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

FROM ubuntu:18.04

RUN apt-get update -y

# Install Maat dependencies
RUN apt-get install -y autoconf automake libtool check libglib2.0-dev \
    libxml2-dev libssl-dev uuid-dev libcap-dev make libelf-dev libjson-c-dev \
    build-essential

ADD ./maat /app/maat

RUN cd /app/maat ; autoreconf -i ; ./configure --prefix=/opt/maat --disable-selinux ; make ; make check ; make install

RUN cd /app/maat/demo/credentials ; cp client.key client.pem server.key server.pem /opt/maat/etc/maat/credentials/

