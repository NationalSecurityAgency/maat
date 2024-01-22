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

Maat Attestation Manager UI Tutorial
=====================================

This tutorial will guide you through the installation and usage of the
Attestation Manager UI feature of Maat.


Setup
-----

Please follow the steps in `documentation/source/quick_start.txt` to build
Maat.  Then, run through the demos in `documentation/source/basic_tutoral.txt`
to ensure that your certificates and ports are configured correctly.

The tutorials that follow assume Maat is installed in `/opt/maat`. If you
installed in a different directory, please modify accordingly.

Install these dependencies:

Ubuntu:

.. code-block:: bash

    sudo apt install python3-pip curl

CentOS:

.. code-block:: bash

    sudo yum install python3-pip curl

Run the following commands:

.. code-block:: bash

    pip3 install --user flask

Demo: Using Attestation Manager UI to View a Userspace Measurement
-------------------------------------------------------------------

This demonstration works by setting up the AM to write specific messages
associated with the Attestation Manager UI to the syslog file.  This is achieved
by setting the following environment variables: `LIBMAAT_LOG_SYSLOG=1` and
`LIBMAAT_DEBUG_LEVEL=5`.  The `syslog_daemon` reads these messages and forwards
them to the webserver, started by `app.py`.  The user can operate the webpage to
see these individual steps as they took place during a measurement.

The first step is to set up the userspace measurement components much like we
did in `documentation/source/basic_tutorial.txt`.  Open a terminal which wil act
as both the "Attester" and "Appraiser".

In the terminal, run

.. code-block:: bash

    sudo LIBMAAT_LOG_SYSLOG=1 LIBMAAT_DEBUG_LEVEL=5 /opt/maat/bin/attestmgr -i 127.0.0.1:2343 -u /tmp/app.sock \
         -C /opt/maat/etc/maat/minimal-am-config.xml

Now, we open another terminal and start the webserver for the user interface.
To do so, run the following commands:

.. code-block:: bash

    cd maat/am-ui
    python3 app.py

Open another terminal and start the daemon to listen for syslog messages:

.. code-block:: bash

    cd maat/am-ui
    ./syslog_daemon.sh

Open a web browser and navigate to the UI webpage by entering the following URL:

.. code-block:: none

    http://127.0.0.1:5000/steps

At this time, open another terminal as the "Test Client".  Run the following command:

.. code-block:: bash

    /opt/maat/bin/test_client -l localhost -a 2343 -t localhost -p 2343 \
         -r mtab

This will take the measurement of the `mtab` resource and perform the appraisal.
You should see activity in the terminals running the webserver and the syslog
daemon for each message that comes in.  Now, navigate back to the webpage and
click `Load latest measurement`.  Then, repeatedly click `Next step` to walk
through each step in the measurement that just occurred. Arrows and boxes will
appear, each containing a message with the step that occurred.  An outgoing
arrow shows the AM is sending something, and an incoming arrow represents the AM
receiving something.  Keep in mind that with one AM, things can be sent from
that AM to itself.

A screenshot of the AM UI after running this demo can be found at `./am-ui-screenshot.png`.

