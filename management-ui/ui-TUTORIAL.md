<!--
Copyright 2023 United States Government

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
-->

Maat UI Tutorial
================

This tutorial will guide you through the setup of Maat, and will enable you to
execute a few simple Maat demos. Some of the demos depend on configurations made
in preceding demos, so complete them in order for best results.


Setup
-----

Please follow the steps in `documentation/source/quick_start.txt` to build Maat,
with one modification: when compiling Maat, pass the `--enable-web-ui` flag to
ensure that the Maat web UI and its associated scripts are compiled. Then, run
through the demos in `documentation/source/basic_tutoral.txt` to ensure that
your certificates and ports are configured correctly.

The tutorials that follow assume Maat is installed in `/opt/maat`. If you
installed in a different directory, please modify accordingly.

Demo 1: Simple Attestation
--------------------------

Set the following variables:

.. code-block:: bash

    APP_ARGS="-i 127.0.0.1:2342 -m COPLAND -u /tmp/app.sock \
      -C /opt/maat/etc/maat/minimal-am-config.xml \
      -f /opt/maat/etc/maat/credentials/server.pem \
      -k /opt/maat/etc/maat/credentials/server.key \
      -s /opt/maat/share/maat/selector-configurations/selector.xml"

.. code-block:: bash

    ATT_ARGS="-i 127.0.0.1:2343 -m COPLAND -u /tmp/att.sock \
      -C /opt/maat/etc/maat/minimal-am-config.xml \
      -s /opt/maat/share/maat/selector-configurations/selector.xml"

    TC_ARGS="-l localhost -t localhost -a 2342 -p 2343"

Then run each of these commands in a separate terminal:

.. code-block:: bash

    sudo LIBMAAT_LOG_SYSLOG=0 /opt/maat/bin/attestmgr $APP_ARGS

    sudo LIBMAAT_LOG_SYSLOG=0 /opt/maat/bin/attestmgr $ATT_ARGS

    /opt/maat/bin/test_client $TC_ARGS

The output from the test_client should resemble:

.. code-block:: none

    measuring target: localhost : 127.0.0.1
    connecting to appraiser: 127.0.0.1 : 2342
    DEBUG!!!! Target type matches host-port
    sending request: <?xml version="1.0"?>
    <contract version="1.0" type="request"><target type="host-port">127.0.0.1<host>127.0.0.1</host><port>2343</port></target><resource>debug resource</resource></contract>

    Result from Appraiser: <?xml version="1.0"?>
    <contract version="1.0" type="response"><target type="host-port">127.0.0.1</target><resource>debug resource</resource><result>PASS</result>...</contract>

Where the <result>PASS</result> indicates successful measurement and
appraisal (whereas <result>FAIL</result> would indicate failure).

Demo 2: Attestation with Single AM
----------------------------------

This demonstration illustrates how a single AM can be used as both the Attester
and the Appraiser, even within a single measurement request.

Create a new test client variable to use only one port:

.. code-block:: bash

    SINGLE_TC_ARGS="-l localhost -t localhost -p 2342 -a 2342"

Run each of these commands in a separate terminal:

.. code-block:: bash

    sudo LIBMAAT_LOG_SYSLOG=0 /opt/maat/bin/attestmgr $APP_ARGS

    /opt/maat/bin/test_client $SINGLE_TC_ARGS

The output should be similar to the output from the previous demo.

Demo 3: Attestation with GOT/PLT Measure ASP
--------------------------------------------

This demo walks you through making changes to the selection policy to 
cause it to choose a different ASP.

Copy selector.xml to a new file called got_selector.xml:

.. code-block:: bash

    sudo cp /opt/maat/share/maat/selector-configurations/selector.xml \
            /opt/maat/share/maat/selector-configurations/got_selector.xml

In got_selector.xml, change every instance of:
    `"((USM procopenfiles) -> SIG)"`
To:
    `"((USM got) -> SIG)"`

For example:

.. code-block:: bash

    sudo sed -i -e 's/\"((USM procopenfiles) -> SIG)\"/\"((USM got) -> SIG)\"/g' /opt/maat/share/maat/selector-configurations/got_selector.xml

This is the Copland phrase for a GOT/PLT measurement defined in 
userspace_apb.xml

Set a variable to use the new policy:

.. code-block:: bash

    GOT_ARGS="-i 127.0.0.1:2342 -m COPLAND -u /tmp/app.sock \
      -C /opt/maat/etc/maat/minimal-am-config.xml \
      -f /opt/maat/etc/maat/credentials/server.pem \
      -k /opt/maat/etc/maat/credentials/server.key \
      -s /opt/maat/share/maat/selector-configurations/got_selector.xml"

Run each of these commands in a separate terminal:

.. code-block:: bash

    sudo LIBMAAT_LOG_SYSLOG=0 /opt/maat/bin/attestmgr $GOT_ARGS

    /opt/maat/bin/test_client $SINGLE_TC_ARGS

The output should be similar to the output from the previous two demos.

Demo 4: Scheduling Measurements via Message Queues
--------------------------------------------------

Install these dependencies:

Debian/Ubuntu:

.. code-block:: bash

    sudo apt-get install python3-pika mongodb python3-pymongo rabbitmq-server

Fedora/CentOS:

.. code-block:: bash

    sudo yum install python36-pika mongodb mongodb-server python36-pymongo \
    	       	     rabbitmq-server


On Fedora/CentOS you must manually start the rabbitmq and mongodb servers:

.. code-block:: bash

    sudo systemctl start rabbitmq-server
    sudo systemctl start mongod

Run the following commands, each in a separate terminal:

.. code-block:: bash

    /opt/maat/bin/attestmgr $APP_ARGS

    python3 ~/maat/src/am/mq_client.py

    python3 ~/maat/src/am/mq_test_driver.py

The output from mq_test_driver should be similar to:

.. code-block:: none

    {"appraiser_address": "localhost", "resource": "MQ test driver", "target_address": "localhost", "target_port": 2342, "request_id": "4fb1be8a-fe91-4262-8a4b-85d763ba167b", "appraiser_port": 2342}
    Received result of : {"time": 1415898475.778756, "result": true, "request_id": "4fb1be8a-fe91-4262-8a4b-85d763ba167b"}

Where the "result" key in the result message is true if the attestation
succeeded and false otherwise.


Demo 5: Scheduling Measurements From the UI
-------------------------------------------

Install the dependency:

+ lighttpd

edit `/etc/lighttpd/lighttpd.conf`:

+ set server.document-root = "/opt/maat/web"
+ add ".py" to the list of static-file.exclude-extensions

### On Debian/Ubuntu:

edit `/etc/lighttpd/conf-available/10-cgi.conf`:

+ uncomment all of the cgi.assign stanza
+ Change `".py"  => "/usr/bin/python"` to `".py"  => "/usr/bin/python3"`

To start web server, run:

.. code-block:: bash

    sudo lighty-enable-mod cgi
    sudo /etc/init.d/lighttpd restart


### On Fedora/CentOS:

edit `/etc/lighttpd/modules.conf`:

+ Uncomment the line: `include "conf.d/cgi.conf"`

edit `/etc/lighttpd/conf.d/cgi.conf`:

+ Change `".py"  => "/usr/bin/python"` to `".py"  => "/usr/bin/python3"`

To start the web server, run:

.. code-block:: bash

    sudo systemctl start lighttpd

The Web-UI's CGI scripts need to be able to connect to the mongodb
database and activemq message queues via TCP, this is not allowed
under the default SELinux policy but can be enabled with the following
command:

.. code-block:: bash

    sudo setsebool -P httpd_can_network_connect=on

### Running the Demo

Run the following commands in separate terminals:

.. code-block:: bash

    /opt/maat/bin/attestmgr $APP_ARGS

    python3 <maat>/src/am/mq_client.py

Next, add a resource and machine definitions to the database.

- This can be done from the command-line:

  Add a resource definition to the database

.. code-block:: bash

      python3 ~/maat/ui/addResourceToDatabase.py default

  Add a machine definition for localhost to the database

.. code-block:: bash

      python3 ~/maat/ui/addMachineToDatabase.py localhost \
        D6:79:C4:82:6A:DE:F4:D0:97:9B:CC:0C:15:9C:37:68:BF:7E:33:34 \
        127.0.0.1 2342

- Or through the user interface:

  Open browser, go to localhost. Click the `+ Machine` button and fill out the
  information as follows:

  - Machine Name : localhost
  - Fingerprint  : D6:79:C4:82:6A:DE:F4:D0:97:9B:CC:0C:15:9C:37:68:BF:7E:33:34
  - IP Address   : 127.0.0.1
  - Port of AM   : 2342

  Then click 'Add'. The page will reload with the new machine listed.

  Click to `+ Resource` button and fill out the information as follows:
  - Resource Name : default

  Click 'Add' and the page will refresh with the new resource listed.

If the machine and resource were added via the command line, open the 
browser and navigate to localhost.

Select machine(s) and resource(s) to schedule for measurement, and click 
'Schedule'.

The unique id of the machine(s) and resource(s) scheduled for measurement will
briefly appear listed above the Measurements header. As the measurement(s)
return, they will populate the Measurements table, listed in 
reverse-chronological order (most recent to least), topping off at ten 
measurements. You may need to reload the page to view the most recent
measurements.
