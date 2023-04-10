COPYRIGHT
=========

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

ABOUT
==============

This repository contains the code for the prototype implementation of the Maat
Measurement and Attestation Framework, as described in "A Platform Service for 
Remote Integrity Measurement and Attestation" 
(DOI: 10.1109/MILCOM.2018.8599735). This includes the code for the Attestation 
Manager (the main program of the Maat Framework), as well as various Attestation
Protocol Blocks (APBs) and Attestation Service Providers (ASPs) to demonstrate 
measurement in different configurations. One of these demonstrations is an 
implementation of Userspace Measurement, as described in "Runtime Detection of 
Userspace Implants" (DOI: 10.1109/MILCOM47813.2019.9020783).

Maat uses the Copland language, and supports many of the usecases, described in
"Flexible Mechanisms for Remote Attestation" (DOI: 10.1145/3470535). Furthe
documents on Copland and the design of measurement and attestation protocols can
be found in "Orchestrating Layered Attestations" (DOI:
10.1007/978-3-030-17138-4_9) and "Automated Trust Analysis of Copland
Specifications for Layered Attestations" (DOI: 10.1145/3479394.3479418).

Maat currently supports RHEL 7 and 8, and Ubuntu 20.04 and 22.04.

Documentation
-------------

Maat has a user and administration guide which should be distributed separately,
but can also be built using `make docs` in the Maat repository.  Additionally, 
there are:

- README.md :  This file, which contains a high level overview of Maat

- am-ui/maat-attestation-manager-ui-TUTORIAL.md: Tutorial for setting up the Attestation Manager User 
						 Interface to step through a recent measurement.

- documentation/source/
  - quick_start.txt :	     	Contains building, installation, and configuration
    		    	     	instructions for installing Maat from source

  - basic_tutorial.txt :     	Contains a series of tutorials for getting Maat 
    		       	     	running in different basic scenarios to perform 
			     	userspace measurement (to be followed after 
			     	completion of quick_start.txt)

  - multirealm_tutorial.txt: 	A series of tutorials to demonstate execution of 
    		      	     	Maat in a multi-realm attestation scenario. 
		      	     	Introduces Copland and some more complex use cases.

  - layered_tutorial.txt:   A tutorial of attetstation of a platform with multiple
                            privilege levels, such as a hypervisor enabled machine.

- management-ui/ui-TUTORIAL.md: Basic tutorials for Maat that use a prototype Maat
  		    	     	web interface in lieu of the command line to 
			     	request attestations from Maat

BUILDING 
============

Please see the file `documentation/source/quick_start.txt` for a complete list 
of dependencies and build instructions.

SOURCE LAYOUT
==============

+ am-ui/		-- Code and tutorials for setting up a Python 
  			   Flask-based web server to act as a GUI for
			   stepping through a recent measurement

+ CHANGELOG.md		-- Markup file of major changes for each version

+ configure.ac          -- Autoconf script used to build everything

+ contrib/		-- Experimental tools and contributed items 

+ debian/		-- Debian packaging directory

+ demo/credentials      -- Sample credentials (CA, Certs, and Keys)
      			   These credentials are used by the test code and
			   tutorials

+ documentation/ 	-- Documentation that, when built, will render an 
  			   html version of the Maat docs

+ initscripts/		-- Upstart and SystemD init scripts for starting and
  			   stopping Maat processes

+ lib/			-- Maat library code for ASPs, APBs, graph
  			   implementations, measurement specifications, 
			   and other utility functions 

+ LICENSE		-- License and copyright information

+ m4/ 			-- Macros used by autoconf for building

+ MaatDox		-- Maat Doxygen configuration file

+ Makefile.am		-- Maat makefile to build everything

+ management-ui/	-- Code and tutorials for setting up a basic 
  			   lighttpd-based web server to act as a GUI for
			   Maat requests

+ measurement-specs/	-- Measurement specifications that, when paired
  			   with an appropriate APB, are used to complete
			   measurement requests

+ pam/			-- Code to set up a Maat PAM module

+ rpm/			-- RPM packaging directory

+ selector-configs/	-- Selector configurations used for negotiation
  			   between Maat Attestation Manager (AM) instances

+ selinux/		-- SELinux policy for Maat and its components; 
  			   work in progress

+ src/am/               -- Code for the Attestation Manager (AM)
  
+ src/apbs/             -- Code for the various Attestation Protocol 
  			   Blocks (APBs)

+ src/asps/             -- Code for the various Attestation Service
  			   Providers (ASPs)

+ src/include/          -- Header files shared across components

+ src/measurement_spec/ -- Shared functionality for using measurement
  			   specifications 

+ src/test/             -- The unit and system tests used to validate
      		           the implementation (based on the check
			   framework)

+ src/types/            -- Implementations of address_spaces,
    		           measurement types, and target types used by
			   the ASPs/APBs


RUNNING
=======

Run the AM with `--help` to get a listing of command line arguments.

    /opt/maat/bin/attestmgr --help

A typical usage may be:

    /opt/maat/bin/attestmgr -a ca.pem -f mycert.pem -k mykey.pem \
    -u /tmp/attestmgr.sock

This will cause the attestation manager to listen on a UNIX domain socket named 
`/tmp/attestmgr.sock`. It will use the default selector policy (in this case, 
installed in `$(prefix)/share/maat/selector-configurations/selector.xml`)
and look for APB and ASP metadata, and measurement specifications in the default
locations: `$(prefix)/share/maat/apbs`, `$(prefix)/share/maat/asps`, and
`$(prefix)/share/maat/measurement-specifications` respectively.

The test_client program can be used to trigger an attestation by sending a 
request to a running appraiser AM. Again, use the `--help` argument for a 
summary of its usage:



More detailed instructions on running and configuring Maat and several 
tutorials can be found in quick_start.txt and basic_tutorial.txt in the 
documentation directory. 


CONFIGURATION DETAILS
======================

One of the primary goals of the Maat Measurement and Attestation (M&A)
framework is to offer policy-driven negotiation and selection of 
attestation protocols and measurement evidence to satisfy a wide variety 
of attestation scenarios. 

The major elements to an M&A configuration are summarized in the table 
below.

| Configuration Type         | Default Location                  | Purpose |
|----------------------------|-----------------------------------|---------|
| Selector configurations    | /usr/local/share/maat/selector-configurations/\*.xml | Defines which Copland terms to offer/use in what scenario | 
| APB Metadata files         | /usr/local/share/maat/apb/\*.xml  | Associates an APB's UUID with its implementation (.so file), dependencies, and supported Copland terms |
| ASP Metadata files         | /usr/local/share/maat/asp/\*.xml  | Associates an ASP's UUID with its implementation (.so file) and measurement capabilities |
| Measurement Specifications | /usr/local/share/maat/measurement_specifications/\*.xml | Associates an UUID with a set of measurement directives |
-----------------------------------------------------------------------------------------

More information about each of these files can be found the `documentation`
directory.

