
Libiota Demonstration
=====================

Demonstrates libiota's runtime verification on TrustZone-enabled platforms and
Maat's orchestration. 

We provide instructions to run the Libiota-Nuvoton-Maat. The demo runs `libiota`
instances on a Nuvoton board (i.e., Requester and Measurer) and Maat. It
demonstrates runtime state verification of trustzone-enabled resource-limited
devices using Maat for orchestration.

Copyright
---------

Copyright 2020 United States Government

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

Hardware Requirements:
-----------------------

* One Nuvoton NuMaker-PFM-M2351
  (https://direct.nuvoton.com/en/numaker-pfm-m2351) board. 
* USB to UART adapter (we used Gearmo FTDI TTL-232R-5V)

Software Requirements:
-----------------------
* Keil uVision 5.
* Keil MDK Nuvoton Edition (Instructions to install:
  https://www2.keil.com/nuvoton/M0-M23).
* PuTTY or Minicom (for Linux environments).
* NuMaker USB Driver.
* NuLink Debugger.

Instructions for setting up the demo (Nuvoton side):
----------------------------------------------------

* Please review general Trustzone and Keil configuration instructions
  (https://www.keil.com/appnotes/docs/apnt_291.asp). 
* Install Keil uVision development environment for Cortex and ARM devices
  (https://www.keil.com/download/product/). 
  * Keil requires licensing, but you can use the Nuvoton toolchain for free.
  * Download and install the Keil MDK Nuvoton edition.
* Install NuMaker USB driver and debugger following the instructions
  (https://os.mbed.com/platforms/NUMAKER-PFM-M2351/).
  * Connect the Nuvoton board to the USB peripheral and verify the COM port was
    added to the Device Manager. 
  * Use the COM information to connect to the board via PuTTY.
* The demo included here has one top-level directory `Measurer/`. 
  * Navigate to `Measurer/` and double-click on the `TrustZone.uvmpw` file to
    open the multi-project workspace in Keil.
    * Keil should expose two projects `Secure` and `Nonsecure`, both with the
      required configuration for the apps to run on the Nuvoton board.
    * On the `Project Navigation` window, right click the `Secure` project and
      select `Set as Active Project`. 
      * Go to `Project/Build 'Secure (Secure)'` and build the project.
      * Download the binary to the secure memory region of the board via
	`Flash/Download`.
    * On the `Project Navigation` window, right click the `Nonsecure` project
      and select `Set as Active Project`. 
      * Go to `Project/Build 'Nonsecure (Nonsecure)'` and build the project.
      * Download the binary to the non-secure memory region of board via
      	`Flash/Download`.
* Connect the Nuvoton board to the Maat instance via the Arduino UNO interface
  (https://www.nuvoton.com/export/resource-files/UM_NuMaker-PFM-M2351_EN_Rev1.00.pdf)
  * Measurer UART1_nRTS (PB.8) <==> USB-UART RTS (Pin 6)
  * Measurer UART1_TXD (PB.7)  <==>  USB-UART Rx (Pin 5)
  * Measurer UART1_RXD (PB.6)  <==>  USB-UART Tx (Pin 4)

Instructions for setting up the demo (Maat side):
-------------------------------------------------

* Follow the provided instructions to setup and install Maat. 
  * Use the following configuration flags to build:
  
    `./configure --prefix=/opt/maat --disable-selinux --enable-web-ui \
    		 --enable-asp-iot_uart --enable-asp-iot_appraiser \
		 --enable-apb-iot_uart --enable-apb-iot_appraiser`

Instructions for running the demo:
----------------------------------

* Measurer side: 
  * Re-initiate the measurer app by pressing the reset button on the board.
  * To the question: "Is this device compromised?" enter (Y) for simulating a
    compromised device and (N) for simulating a legitimate device.
* Requester/Maat side:
  * Open a command line window and execute the `attestmgr` with the following
    command: 

    ```
    sudo LIBMAAT_LOG_SYSLOG=0 LIBMAAT_DEBUG_LOG=9 /opt/maat/bin/attestmgr \
    -i 127.0.0.1:[PORT] -C /opt/maat/etc/maat/minimal-am-config.xml -m COPLAND \
    -s /opt/maat/share/maat/selector-configurations/iot_selector.xml
    ```

  * Open a second command window and execute the test by calling the `iota`
    resource:
    
    ```
    /opt/maat/bin/test_client -l 127.0.0.1 -a [PORT] -t 127.0.0.1 -p [PORT] \
    -r iota
    ```
 
The demo can also be executed via the Maat UI (only set to work on port 2342.
An `iota_test_driver.py` exists for this purpose. 

  * Open a command line window and execute the attestation manager via the
    following command:

    ```
    sudo LIBMAAT_LOG_SYSLOG=0 LIBMAAT_DEBUG_LOG=9 /opt/maat/bin/attestmgr \
    -i 127.0.0.1:2342 -C /opt/maat/etc/maat/minimal-am-config.xml -m COPLAND \
    -s /opt/maat/share/maat/selector-configurations/iot_selector.xml
    ```

  * Open a second command window and execute the test driver: 

    ```
    python3 src/am/mq_client.py
    ```

  * Follow intructions from Maat to setup and run a Maat server.
  * Open a browser and navigate to `127.0.0.1`
  * Add a new `iota` resource.
  * Select the `localhost` machine and the `iota` resource.
  * Click "Schedule." 
