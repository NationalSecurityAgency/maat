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

Init Scripts
============

This directory contains the Upstart (RHEL6, Ubuntu 12.04-14.04), and SystemD
(RHEL7, Ubuntu 16.04+) init scripts for starting and stopping both the Maat
attestmgr process and the Maat MQ proxy. 

Install and Packaging
=====================

The init scripts in this directory are generated using the correct prefix 
path as defined by ./configure, and installed there by 'make install'.  So
if you install from source it should all work. 

This method also works for RPM packages, as the RPM spec file will happily
pick up the generated files from the installed path. 

Debian packaging, however, required the upstart/systemd scripts be located
in the debian/ package directory at package time, which happens before compile 
time.  Therefore, there is a copy of these scripts, without substitutions, 
in the debian/ directory.  If you make a change to any of the files here, you
*MUST ALSO CHANGE* the files in the debian directory.  This is not ideal, but 
necessary until another solution is reached for debian packaging. 



